//! Nachweise zur Sicherheitspruefung (Bericht vom 29.09.2026). Jeder Test
//! beschreibt das sichere Verhalten; bis 0.40.0 schlugen die ersten vier
//! fehl -- die Befunde K1 (Schnittstelle ohne Geheimnis), H0 (Konto loeschen
//! ohne Pruefung), H1 (BDF-Laengen als Panic) und H2 (Zuteilung aus dem
//! Content-Length) sind seit 0.41.0 zu.
//!
//! cargo baut Tests immer mit panic=unwind, auch mit --release. Im
//! ausgelieferten Dienst steht panic = "abort" (Cargo.toml), dort beendete
//! derselbe Panic den ganzen Prozess.

use briarkern::bdf;
use briarkern::store::Store;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// STRING_8 mit Laengenbyte 0xff: frueher als i8 (-1) gelesen und als usize
/// riesig. Briar verwirft negative Laengen (BdfReaderImpl.readString). Der
/// Inhalt ist vollstaendig da -- der Fehler kommt von der Laenge, nicht von
/// einem zu kurzen Strom.
#[test]
fn bdf_negative_stringlaenge_ist_ein_formfehler() {
    let mut roh = vec![0x41, 0xff];
    roh.extend(std::iter::repeat(b'a').take(255));
    let r = std::panic::catch_unwind(|| bdf::from_bytes(&roh).is_err());
    assert!(matches!(r, Ok(true)), "0x41,0xff sollte einen Fehler geben, kein Panic");
    // 127 ist die groesste 8-Bit-Laenge, die Briar annimmt.
    let mut gut = vec![0x41, 127];
    gut.extend(std::iter::repeat(b'a').take(127));
    assert!(bdf::from_bytes(&gut).is_ok());
}

/// RAW_16 mit 0x8000: als i16 negativ, als usize riesig -- auch mit
/// vollstaendigem Inhalt ein Formfehler.
#[test]
fn bdf_negative_rohlaenge_ist_ein_formfehler() {
    let mut roh = vec![0x52, 0x80, 0x00];
    roh.extend(std::iter::repeat(7u8).take(32768));
    let r = std::panic::catch_unwind(|| bdf::from_bytes(&roh).is_err());
    assert!(matches!(r, Ok(true)), "0x52,0x80,0x00 sollte einen Fehler geben, kein Panic");
}

/// Briar liest Laengen kanonisch: eine 16-Bit-Laenge unter 128 und eine
/// 32-Bit-Laenge unter 32768 sind dort Formfehler -- bei uns jetzt auch, sonst
/// zeigten wir Gruppenbeitraege, die Briar-Mitglieder verwerfen.
#[test]
fn nicht_kanonische_laengen_sind_formfehler() {
    let mut kurz16 = vec![0x52, 0x00, 0x05];
    kurz16.extend(std::iter::repeat(7u8).take(5));
    assert!(bdf::from_bytes(&kurz16).is_err(), "16 Bit fuer 5 Byte");
    let mut kurz32 = vec![0x54, 0x00, 0x00, 0x7f, 0xff];
    kurz32.extend(std::iter::repeat(7u8).take(32767));
    assert!(bdf::from_bytes(&kurz32).is_err(), "32 Bit fuer 32767 Byte");
    let mut gut16 = vec![0x52, 0x00, 0x80];
    gut16.extend(std::iter::repeat(7u8).take(128));
    assert!(bdf::from_bytes(&gut16).is_ok(), "128 ist die kleinste 16-Bit-Laenge");
    let mut gut32 = vec![0x54, 0x00, 0x00, 0x80, 0x00];
    gut32.extend(std::iter::repeat(7u8).take(32768));
    assert!(bdf::from_bytes(&gut32).is_ok(), "32768 ist die kleinste 32-Bit-Laenge");
}

/// RAW_32 mit 65537 Byte: ueber Briars maxBufferSize, also Formfehler -- und
/// zwar bevor etwas zugeteilt wird (der Strom ist absichtlich kurz).
#[test]
fn zu_lange_rohfolge_wird_verworfen() {
    assert!(bdf::from_bytes(&[0x54, 0x00, 0x01, 0x00, 0x01]).is_err());
    // 64 KiB genau gehen noch, mit vollstaendigem Inhalt.
    let mut ganz = vec![0x54, 0x00, 0x01, 0x00, 0x00];
    ganz.extend(std::iter::repeat(7u8).take(65536));
    assert!(bdf::from_bytes(&ganz).is_ok());
}

/// Listen in Listen, sechs tief: Briars nestedLimit ist 5.
#[test]
fn zu_tief_verschachteltes_wird_verworfen() {
    let mut fuenf = vec![0x60u8; 5];
    fuenf.extend(vec![0x80u8; 5]);
    assert!(bdf::from_bytes(&fuenf).is_ok(), "fuenf Ebenen sind erlaubt");
    let mut sechs = vec![0x60u8; 6];
    sechs.extend(vec![0x80u8; 6]);
    assert!(bdf::from_bytes(&sechs).is_err(), "sechs Ebenen nicht");
}

/// Ein praeparierter QR-Inhalt beim Treffen (Weg /bqp/scan -> bqp::parse ->
/// bdf::from_bytes): Kennbyte 0x04, dann eine Liste mit einem RAW_8 der
/// Laenge 0xff. Angreifer ist, wer einen Code zeigt.
#[test]
fn fremder_qr_code_bringt_den_parser_nicht_zum_absturz() {
    let r = std::panic::catch_unwind(|| {
        briarkern::bqp::parse(&[0x04, 0x60, 0x51, 0xff, 0x80]).is_none()
    });
    assert!(matches!(r, Ok(true)), "bqp::parse panict an einem praeparierten QR-Inhalt");
}

/// Ein Dienst mit Geheimnis auf einem freien Port, mit Kontakt Bob und einer
/// geheimen Nachricht. Liefert Port, Verzeichnis und das Geheimnis, wie die
/// Oberflaeche es liest: aus der Datei neben der state.json.
fn dienst(name: &str) -> (u16, std::path::PathBuf, String) {
    let mut d = std::env::temp_dir();
    d.push(format!("briar-sich-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let pfad = d.join("state.json");

    let mut store = Store::open(&pfad, 7399).unwrap();
    store.create_identity("Alice").unwrap();
    let kontakt = r#"{"id":1,"name":"Bob",
        "author_id":"1111111111111111111111111111111111111111111111111111111111111111",
        "signature_public":"2222222222222222222222222222222222222222222222222222222222222222",
        "master_key":"3333333333333333333333333333333333333333333333333333333333333333",
        "alice":true,"creation_period":0,"last_seen":0,
        "messages":[{"id":"aa","timestamp":1,"text":"GEHEIME NACHRICHT",
                     "outgoing":false,"acked":true}]}"#;
    store.state.contacts.push(serde_json::from_str(kontakt).unwrap());
    store.save().unwrap();
    briarkern::api::geheimnis_anlegen(&pfad).unwrap();
    let geheimnis = std::fs::read_to_string(d.join(briarkern::api::GEHEIMNIS_DATEI)).unwrap();
    assert_eq!(geheimnis.len(), 64, "32 Byte als Hexzahl");

    let port = {
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        l.local_addr().unwrap().port()
    };
    let geteilt = Arc::new(Mutex::new(store));
    std::thread::spawn(move || briarkern::api::run(geteilt, port));
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (port, d, geheimnis)
}

fn anfrage(port: u16, text: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(text.as_bytes()).unwrap();
    let mut antwort = String::new();
    let _ = s.read_to_string(&mut antwort);
    antwort
}

/// Eine fremde Webseite (fetch) oder eine App eines anderen Kontos liest die
/// Nachrichten ueber 127.0.0.1:8105. Ohne Geheimnis kommt nichts, und die
/// Antwort traegt kein Access-Control-Allow-Origin mehr.
#[test]
fn fremde_webseite_bekommt_keine_nachrichten() {
    let (port, d, _) = dienst("web");
    let antwort = anfrage(
        port,
        &format!(
            "GET /messages?contact=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\
             Origin: https://boese.example\r\n\r\n",
            port
        ),
    );
    let _ = std::fs::remove_dir_all(&d);
    assert!(
        !antwort.contains("GEHEIME NACHRICHT"),
        "die Schnittstelle gibt Nachrichten ohne jede Pruefung heraus:\n{}",
        antwort
    );
    assert!(antwort.starts_with("HTTP/1.1 401"), "{}", antwort);
    assert!(!antwort.contains("Access-Control-Allow-Origin"), "{}", antwort);
}

/// Mit dem Geheimnis -- in beiden Schreibweisen -- kommt alles.
#[test]
fn mit_geheimnis_kommen_die_nachrichten() {
    let (port, d, g) = dienst("geheimnis");
    let a = anfrage(
        port,
        &format!(
            "GET /messages?contact=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\n\r\n",
            port, g
        ),
    );
    assert!(a.starts_with("HTTP/1.1 200") && a.contains("GEHEIME NACHRICHT"), "{}", a);
    let b = anfrage(
        port,
        &format!(
            "GET /messages?contact=1 HTTP/1.1\r\nHost: localhost\r\nX-Briar-Geheimnis: {}\r\n\r\n",
            g
        ),
    );
    assert!(b.starts_with("HTTP/1.1 200") && b.contains("GEHEIME NACHRICHT"), "{}", b);
    // Ein falsches Geheimnis ist keines.
    let c = anfrage(
        port,
        &format!(
            "GET /messages?contact=1 HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
            "0".repeat(64)
        ),
    );
    let _ = std::fs::remove_dir_all(&d);
    assert!(c.starts_with("HTTP/1.1 401"), "{}", c);
}

/// Ohne Geheimnis sagt /status nur, dass der Dienst laeuft, ob er gesperrt
/// ist, und weist mit SHA-256 ueber das Geheimnis nach, dass er es kennt --
/// damit die Oberflaeche es nicht an einen Fremden auf dem Port gibt. KEINE
/// Fassung: eine aeltere Oberflaeche hielte den Dienst sonst fuer veraltet
/// und beendete ihn alle drei Sekunden. Link, Adressen, Kontakte: nichts.
#[test]
fn ohne_geheimnis_sagt_status_nur_dass_er_laeuft() {
    use sha2::{Digest, Sha256};
    let (port, d, g) = dienst("status");
    let a = anfrage(port, "GET /status HTTP/1.0\r\n\r\n");
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.starts_with("HTTP/1.1 401"), "{}", a);
    assert!(!a.contains("\"version\""), "{}", a);
    assert!(a.contains("\"running\":true"), "{}", a);
    let erwartet: String = Sha256::digest(g.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect();
    assert!(a.contains(&format!("\"nachweis\":\"{}\"", erwartet)), "{}", a);
    assert!(!a.contains("Bob") && !a.contains("\"link\""), "{}", a);
}

/// Die Fassung gibt es mit Geheimnis -- so fragt die App seit 0.41.0.
#[test]
fn mit_geheimnis_nennt_status_die_fassung() {
    let (port, d, g) = dienst("fassung");
    let a = anfrage(port, &format!("GET /status HTTP/1.0\r\nAuthorization: Bearer {}\r\n\r\n", g));
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.starts_with("HTTP/1.1 200") && a.contains("\"version\":\""), "{}", a);
}

/// Konto loeschen ohne Geheimnis: 401, und die state.json steht noch.
#[test]
fn konto_loeschen_braucht_das_geheimnis() {
    let (port, d, _) = dienst("loeschen");
    let a = anfrage(port, "POST /account/delete HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}");
    let steht = d.join("state.json").exists();
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.starts_with("HTTP/1.1 401"), "{}", a);
    assert!(steht, "die state.json darf nicht weg sein");
}

/// Eine Anfragezeile ueber 8 KiB und Kopfzeilen ueber 64 KiB werden nicht
/// erst gelesen und dann gemessen, sondern an der Grenze abgewiesen.
#[test]
fn ueberlange_anfragen_werden_abgewiesen() {
    let (port, d, _) = dienst("lang");
    let zeile = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(9000));
    let a = anfrage(port, &zeile);
    assert!(a.starts_with("HTTP/1.1 414"), "{}", a);
    let mut koepfe = String::from("GET /status HTTP/1.1\r\n");
    for i in 0..20 {
        koepfe.push_str(&format!("X-Fuell-{}: {}\r\n", i, "b".repeat(4000)));
    }
    koepfe.push_str("\r\n");
    let b = anfrage(port, &koepfe);
    let _ = std::fs::remove_dir_all(&d);
    // Zu viel Kopf: keine Antwort (die Verbindung wird abgebrochen), auf
    // keinen Fall aber ein Inhalt.
    assert!(!b.starts_with("HTTP/1.1 200"), "{}", b);
}

/// DNS-Rebinding: der Name einer fremden Seite zeigt auf 127.0.0.1. Der
/// Host-Kopf verraet es.
#[test]
fn fremder_host_wird_abgewiesen() {
    let (port, d, g) = dienst("host");
    let a = anfrage(
        port,
        &format!(
            "GET /status HTTP/1.1\r\nHost: boese.example\r\nAuthorization: Bearer {}\r\n\r\n",
            g
        ),
    );
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.starts_with("HTTP/1.1 400"), "{}", a);
}

/// Ein Content-Length von 4 GB war eine Zuteilung, die den Dienst beendete.
#[test]
fn zu_grosser_rumpf_wird_abgewiesen() {
    let (port, d, g) = dienst("rumpf");
    let a = anfrage(
        port,
        &format!(
            "POST /send HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Length: 4000000000\r\n\r\n",
            g
        ),
    );
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.starts_with("HTTP/1.1 413"), "{}", a);
}

/// Die Datei mit dem Geheimnis liest nur der Benutzer selbst.
#[test]
fn geheimnisdatei_ist_nur_fuer_den_benutzer() {
    use std::os::unix::fs::PermissionsExt;
    let (_, d, _) = dienst("rechte");
    let rechte = std::fs::metadata(d.join(briarkern::api::GEHEIMNIS_DATEI))
        .unwrap()
        .permissions()
        .mode();
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(rechte & 0o777, 0o600, "{:o}", rechte);
}
