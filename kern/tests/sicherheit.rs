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
use std::os::unix::net::UnixStream;
use std::path::Path;
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

/// Bytes hinter dem obersten Wert: Briar verwirft den Rumpf
/// (ClientHelperImpl.toList prueft `reader.eof()`).
#[test]
fn bdf_bytes_hinter_dem_wert_sind_ein_formfehler() {
    assert!(bdf::from_bytes(&[0x60, 0x80]).is_ok(), "die leere Liste allein");
    assert!(bdf::from_bytes(&[0x60, 0x80, 0x00]).is_err(), "ein NULL dahinter");
    assert!(bdf::from_bytes(&[0x60, 0x80, 0x60, 0x80]).is_err(), "zwei Listen");
}

/// Ein gueltiger QR-Inhalt (16 Byte Verpflichtung, keine Beschreiber) mit
/// einem Byte dahinter: PayloadParserImpl.parse wirft dann FormatException.
#[test]
fn qr_code_mit_bytes_dahinter_wird_verworfen() {
    let mut roh = vec![0x04, 0x60, 0x51, 16];
    roh.extend([9u8; 16]);
    roh.push(0x80);
    assert!(briarkern::bqp::parse(&roh).is_some(), "ohne Anhang gilt er");
    roh.push(0x00);
    assert!(briarkern::bqp::parse(&roh).is_none(), "mit Anhang nicht");
}

/// Ein Anhang traegt seine Daten hinter der Beschreibung -- der strenge
/// Leser darf ihn nicht unkenntlich machen.
#[test]
fn anhang_mit_daten_bleibt_ein_anhang() {
    use briarkern::sync;
    let rumpf = sync::attachment_body("image/jpeg", &[0xff, 0xd8, 0xff, 0xe0]);
    assert!(bdf::from_bytes(&rumpf).is_err(), "streng: Daten hinter der Liste");
    assert!(bdf::from_bytes_prefix(&rumpf).is_ok());
    assert!(sync::is_attachment(&rumpf));
    let (art, daten) = sync::parse_attachment(&rumpf).expect("ein Anhang");
    assert_eq!(art, "image/jpeg");
    assert_eq!(daten, vec![0xff, 0xd8, 0xff, 0xe0]);
}

/// Ein Woerterbuch als Bytes: die Schluessel in genau dieser Folge, als
/// Werte 0, 1, 2 ...
fn woerterbuch(schluessel: &[&str]) -> Vec<u8> {
    let mut roh = vec![0x70];
    for (i, k) in schluessel.iter().enumerate() {
        roh.push(0x41);
        roh.push(k.len() as u8);
        roh.extend(k.as_bytes());
        roh.extend([0x21, i as u8]);
    }
    roh.push(0x80);
    roh
}

/// Briars readDictionary verlangt die Schluessel streng aufsteigend.
#[test]
fn doppelter_woerterbuchschluessel_ist_ein_formfehler() {
    assert!(bdf::from_bytes(&woerterbuch(&["a", "b"])).is_ok());
    assert!(bdf::from_bytes(&woerterbuch(&["a", "a"])).is_err());
}

#[test]
fn absteigende_woerterbuchschluessel_sind_ein_formfehler() {
    assert!(bdf::from_bytes(&woerterbuch(&["b", "a"])).is_err());
    assert!(bdf::from_bytes(&woerterbuch(&["", "a", "ab", "b"])).is_ok());
}

/// Java vergleicht Strings nach UTF-16-Einheiten: U+10000 (Surrogate
/// D800 DC00) kommt vor U+E000, in Byte- und Codepunktordnung danach. Der
/// Leser folgt Java, und der Schreiber auch, sonst wiese Briar unsere
/// Woerterbuecher zurueck.
#[test]
fn woerterbuchschluessel_ordnen_wie_java() {
    let bmp = "\u{e000}";
    let astral = "\u{10000}";
    assert!(bdf::from_bytes(&woerterbuch(&[astral, bmp])).is_ok(), "Java-Ordnung");
    assert!(bdf::from_bytes(&woerterbuch(&[bmp, astral])).is_err(), "Byte-Ordnung");
    let wert = bdf::Bdf::dict(vec![(bmp, bdf::Bdf::Int(1)), (astral, bdf::Bdf::Int(0))]);
    let geschrieben = bdf::to_bytes(&wert);
    assert_eq!(geschrieben, woerterbuch(&[astral, bmp]), "der Schreiber ordnet wie Java");
    assert_eq!(bdf::from_bytes(&geschrieben).unwrap(), wert);
}

/// BdfReaderImpl.readInt16/32/64 mit canonical = true: passt der Wert in
/// die naechstkleinere Form, ist es ein Formfehler.
#[test]
fn nicht_kanonische_ganzzahlen_sind_formfehler() {
    let falsch: [&[u8]; 6] = [
        &[0x22, 0x00, 0x7f],                                     // 127 als INT_16
        &[0x22, 0xff, 0x80],                                     // -128 als INT_16
        &[0x24, 0x00, 0x00, 0x7f, 0xff],                         // 32767 als INT_32
        &[0x24, 0xff, 0xff, 0x80, 0x00],                         // -32768 als INT_32
        &[0x28, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff],             // 2^31-1 als INT_64
        &[0x28, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00], // -2^31 als INT_64
    ];
    for roh in falsch {
        assert!(bdf::from_bytes(roh).is_err(), "{:02x?} ist nicht kanonisch", roh);
    }
    let richtig: [(&[u8], i64); 6] = [
        (&[0x22, 0x00, 0x80], 128),
        (&[0x22, 0xff, 0x7f], -129),
        (&[0x24, 0x00, 0x00, 0x80, 0x00], 32768),
        (&[0x24, 0xff, 0xff, 0x7f, 0xff], -32769),
        (&[0x28, 0, 0, 0, 0, 0x80, 0, 0, 0], 1 << 31),
        (&[0x28, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff], -(1 << 31) - 1),
    ];
    for (roh, zahl) in richtig {
        assert_eq!(bdf::from_bytes(roh).unwrap(), bdf::Bdf::Int(zahl));
    }
}

/// Unser Schreiber waehlt immer die kleinste Form -- an allen Grenzen.
#[test]
fn schreiber_kodiert_ganzzahlen_kanonisch() {
    let grenzen: [(i64, u8); 14] = [
        (127, 0x21),
        (128, 0x22),
        (-128, 0x21),
        (-129, 0x22),
        (32767, 0x22),
        (32768, 0x24),
        (-32768, 0x22),
        (-32769, 0x24),
        ((1 << 31) - 1, 0x24),
        (1 << 31, 0x28),
        (-(1 << 31), 0x24),
        (-(1 << 31) - 1, 0x28),
        (i64::MAX, 0x28),
        (i64::MIN, 0x28),
    ];
    for (zahl, art) in grenzen {
        let roh = bdf::to_bytes(&bdf::Bdf::Int(zahl));
        assert_eq!(roh[0], art, "{} als {:02x}", zahl, art);
        assert_eq!(bdf::from_bytes(&roh).unwrap(), bdf::Bdf::Int(zahl), "{} liest sich zurueck", zahl);
    }
}

/// Ein Dienst mit Geheimnis, mit Kontakt Bob und einer geheimen Nachricht.
/// Er lauscht wie ausgeliefert auf dem Sockel neben der state.json (siehe
/// `sockel`) und zusaetzlich, wie mit --api-port, auf einem freien TCP-Port --
/// den brauchen die Pruefungen zu Host-Kopf und Webseiten. Liefert Port,
/// Verzeichnis und das Geheimnis, wie die Oberflaeche es liest: aus der Datei
/// neben der state.json.
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
    let lauscher =
        briarkern::api::lauscher_oeffnen(&pfad, &briarkern::api::sockel_pfad(&pfad), Some(port))
            .unwrap();
    let geteilt = Arc::new(Mutex::new(store));
    std::thread::spawn(move || briarkern::api::run(geteilt, lauscher));
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    (port, d, geheimnis)
}

/// Der Sockel des Dienstes aus `dienst`.
fn sockel(d: &Path) -> std::path::PathBuf {
    d.join(briarkern::api::SOCKEL_DATEI)
}

/// Eine Anfrage von Hand auf den Sockel -- so wie die Oberflaechen sie ueber
/// QLocalSocket schicken.
fn anfrage_sockel(pfad: &Path, text: &str) -> String {
    let mut s = UnixStream::connect(pfad).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(text.as_bytes()).unwrap();
    let mut antwort = String::new();
    let _ = s.read_to_string(&mut antwort);
    antwort
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

/// Der Sockel ist nur fuer den Benutzer selbst: Datei 0600, und der Ordner
/// der state.json 0700 -- auch wenn er vorher fuer alle lesbar war.
#[test]
fn sockel_und_ordner_sind_nur_fuer_den_benutzer() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let mut d = std::env::temp_dir();
    d.push(format!("briar-sich-ordner-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    let pfad = d.join("state.json");
    let sockel_pfad = briarkern::api::sockel_pfad(&pfad);
    // Ein liegengebliebener Sockel eines beendeten Dienstes stoert nicht.
    drop(std::os::unix::net::UnixListener::bind(&sockel_pfad).unwrap());
    let lauscher = briarkern::api::lauscher_oeffnen(&pfad, &sockel_pfad, None).unwrap();
    let datei = std::fs::symlink_metadata(&sockel_pfad).unwrap();
    let ordner = std::fs::metadata(&d).unwrap().permissions().mode();
    drop(lauscher);
    let _ = std::fs::remove_dir_all(&d);
    assert!(datei.file_type().is_socket());
    assert_eq!(datei.permissions().mode() & 0o777, 0o600, "{:o}", datei.permissions().mode());
    assert_eq!(ordner & 0o777, 0o700, "{:o}", ordner);
}

/// Ueber den Sockel mit Geheimnis: alles da.
#[test]
fn ueber_den_sockel_mit_geheimnis_kommen_die_nachrichten() {
    let (_, d, g) = dienst("sockel-mit");
    let a = anfrage_sockel(
        &sockel(&d),
        &format!("GET /messages?contact=1 HTTP/1.0\r\nAuthorization: Bearer {}\r\n\r\n", g),
    );
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.starts_with("HTTP/1.1 200") && a.contains("GEHEIME NACHRICHT"), "{}", a);
}

/// Der Sockel ersetzt nur den Transport, nicht das Geheimnis: ohne kommt 401,
/// auf /status mit dem Nachweis und ohne Fassung.
#[test]
fn ueber_den_sockel_ohne_geheimnis_nur_401_mit_nachweis() {
    let (_, d, _) = dienst("sockel-ohne");
    let a = anfrage_sockel(&sockel(&d), "GET /messages?contact=1 HTTP/1.0\r\n\r\n");
    let b = anfrage_sockel(&sockel(&d), "GET /status HTTP/1.0\r\n\r\n");
    let _ = std::fs::remove_dir_all(&d);
    assert!(a.starts_with("HTTP/1.1 401") && !a.contains("GEHEIME NACHRICHT"), "{}", a);
    assert!(b.starts_with("HTTP/1.1 401"), "{}", b);
    assert!(
        b.contains(&format!("\"nachweis\":\"{}\"", briarkern::api::nachweis())),
        "{}",
        b
    );
    assert!(!b.contains("\"version\""), "{}", b);
}

/// Kommt auf dem Sockel doch ein Host-Kopf, gelten dieselben Regeln wie auf
/// dem Port: localhost ja, ein fremder Name nein.
#[test]
fn ueber_den_sockel_gilt_die_host_pruefung() {
    let (_, d, g) = dienst("sockel-host");
    let gut = anfrage_sockel(
        &sockel(&d),
        &format!("GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n", g),
    );
    let fremd = anfrage_sockel(
        &sockel(&d),
        &format!("GET /status HTTP/1.1\r\nHost: briar\r\nAuthorization: Bearer {}\r\n\r\n", g),
    );
    let _ = std::fs::remove_dir_all(&d);
    assert!(gut.starts_with("HTTP/1.1 200"), "{}", gut);
    assert!(fremd.starts_with("HTTP/1.1 400"), "{}", fremd);
}

/// SO_PEERCRED nennt die UID des Gegenuebers -- hier die eigene, die der
/// Dienst zulaesst. Einen fremden Benutzer kann der Test ohne root nicht
/// stellen; die Abweisung haengt an genau diesem Wert.
#[test]
fn der_sockel_erkennt_den_eigenen_benutzer() {
    let (a, b) = UnixStream::pair().unwrap();
    let ich = unsafe { libc::getuid() };
    assert_eq!(briarkern::api::gegenueber_uid(&a), Some(ich));
    assert_eq!(briarkern::api::gegenueber_uid(&b), Some(ich));
}

/// Ohne --api-port lauscht nichts auf TCP: lauscher_oeffnen gibt genau den
/// Sockel zurueck.
#[test]
fn ohne_port_gibt_es_nur_den_sockel() {
    let mut d = std::env::temp_dir();
    d.push(format!("briar-sich-nurkel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    let pfad = d.join("state.json");
    let l = briarkern::api::lauscher_oeffnen(&pfad, &briarkern::api::sockel_pfad(&pfad), None).unwrap();
    let nur_sockel = l.len() == 1 && matches!(l[0], briarkern::api::Lauscher::Unix(_));
    drop(l);
    let _ = std::fs::remove_dir_all(&d);
    assert!(nur_sockel);
}

/// 7b, A1: `--api-port` allein oeffnet kein TCP mehr -- erst zusammen mit
/// BRIAR_API_TCP=1. So bleibt ein Dienst, den eine alte Oberflaeche mit
/// `--api-port 8105` startet, beim Sockel.
#[test]
fn api_port_ohne_schalter_oeffnet_kein_tcp() {
    use briarkern::api::tcp_erlaubt;
    use std::ffi::OsStr;
    assert_eq!(tcp_erlaubt(Some(8105), None), None);
    assert_eq!(tcp_erlaubt(Some(8105), Some(OsStr::new("0"))), None);
    assert_eq!(tcp_erlaubt(Some(8105), Some(OsStr::new(""))), None);
    assert_eq!(tcp_erlaubt(Some(8105), Some(OsStr::new("ja"))), None);
}

#[test]
fn api_port_mit_schalter_oeffnet_tcp() {
    use briarkern::api::tcp_erlaubt;
    use std::ffi::OsStr;
    assert_eq!(tcp_erlaubt(Some(8105), Some(OsStr::new("1"))), Some(8105));
    assert_eq!(tcp_erlaubt(None, Some(OsStr::new("1"))), None, "ohne Port kein TCP");
}

/// 7b, A2: antwortet am Sockel schon ein Dienst, nimmt ein zweiter ihn nicht
/// weg -- `Lauscher::unix` meldet AddrInUse (main.rs beendet sich dann), und
/// der Sockel des ersten bleibt, wie er ist.
#[test]
fn zweiter_dienst_nimmt_den_lebenden_sockel_nicht_weg() {
    use std::os::unix::fs::MetadataExt;
    let mut d = std::env::temp_dir();
    d.push(format!("briar-sich-zweiter-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let pfad = d.join("state.json");
    let sockel = briarkern::api::sockel_pfad(&pfad);
    let erster = briarkern::api::lauscher_oeffnen(&pfad, &sockel, None).unwrap();
    let vorher = std::fs::metadata(&sockel).unwrap().ino();
    let zweiter = briarkern::api::lauscher_oeffnen(&pfad, &sockel, None);
    let art = zweiter.as_ref().err().map(|e| e.kind());
    let nachher = std::fs::metadata(&sockel).unwrap().ino();
    // Der erste ist weiter erreichbar.
    let erreichbar = UnixStream::connect(&sockel).is_ok();
    drop(erster);
    let _ = std::fs::remove_dir_all(&d);
    assert_eq!(art, Some(std::io::ErrorKind::AddrInUse));
    assert_eq!(vorher, nachher, "derselbe Sockel");
    assert!(erreichbar);
}

/// Ein toter Sockel (Dienst beendet, Datei liegt noch) wird ersetzt.
#[test]
fn toter_sockel_wird_ersetzt() {
    let mut d = std::env::temp_dir();
    d.push(format!("briar-sich-tot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let pfad = d.join("state.json");
    let sockel = briarkern::api::sockel_pfad(&pfad);
    drop(briarkern::api::lauscher_oeffnen(&pfad, &sockel, None).unwrap());
    assert!(sockel.exists(), "die Datei bleibt nach dem Ende liegen");
    let neu = briarkern::api::lauscher_oeffnen(&pfad, &sockel, None);
    let ok = neu.is_ok();
    drop(neu);
    let _ = std::fs::remove_dir_all(&d);
    assert!(ok);
}

/// 7b, H: hoechstens eine Zeile je Minute.
#[test]
fn drossel_laesst_eine_zeile_je_minute_durch() {
    use briarkern::api::drossel_faellig;
    let zuletzt = std::sync::atomic::AtomicU64::new(0);
    assert!(drossel_faellig(&zuletzt, 1_000_000));
    assert!(!drossel_faellig(&zuletzt, 1_000_001));
    assert!(!drossel_faellig(&zuletzt, 1_059_999));
    assert!(drossel_faellig(&zuletzt, 1_060_000));
}
