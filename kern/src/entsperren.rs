//! Auf das Passwort warten, bevor der Dienst loslegt.
//!
//! Ist der Speicher verschluesselt, kann der Dienst beim Hochfahren nichts
//! tun: er kennt weder Kontakte noch Schluessel. Statt abzubrechen -- was
//! bedeutete, dass die App nach jedem Neustart von Hand gestartet werden
//! muesste -- lauscht er auf dem gewohnten Sockel (und, mit --api-port und
//! BRIAR_API_TCP=1, auf dem TCP-Port) und beantwortet genau zwei
//! Dinge: "ich bin gesperrt" und "hier ist das Passwort". Erst danach faehrt
//! der Rest hoch.
//!
//! Absichtlich ein eigener, winziger Server statt einer Sonderbehandlung im
//! grossen: der grosse braucht einen Store, den es hier noch nicht gibt.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use crate::api::{Lauscher, Strom};
use crate::store::Store;

/// Lauscht, bis jemand ein gueltiges Passwort schickt, und gibt den damit
/// geoeffneten Speicher zurueck. Kehrt nur mit Erfolg zurueck.
///
/// Die Lauscher gehoeren weiter dem Aufrufer: main.rs reicht sie danach an
/// api::run. Frueher fiel der Lauscher hier weg und der grosse Dienst band
/// den Port neu -- wer genau dazwischen fragte, stand vor verschlossener Tuer.
pub fn warten(pfad: &Path, lauscher: &[Lauscher], lan_port: u16) -> Store {
    crate::net::log("der Speicher ist verschluesselt -- warte auf das Passwort");

    // Je Verbindung ein eigener Faden. Frueher lief alles nacheinander im
    // Annehmen-Faden, und ein scrypt-Lauf haelt den knapp zwei Sekunden auf
    // (am N9 nachgemessen). Die Oberflaeche fragt daneben alle drei Sekunden
    // den Zustand ab -- diese Abfrage blieb dann in der Warteschlange
    // haengen, und wenn der Lauscher gleich darauf abgeloest wurde, bekam sie
    // nie eine Antwort. Im Protokoll stand danach "API request failed: Broken
    // pipe", und in der Oberflaeche stand fuer immer "wird geprueft".
    let (sender, empfaenger) = std::sync::mpsc::channel::<Store>();
    // Mehrere Lauscher in einem Faden: nicht blockierend, reihum.
    for l in lauscher {
        let _ = l.set_nonblocking(true);
    }
    loop {
        // Hat ein Faden das Passwort angenommen, sind wir fertig -- die
        // Lauscher wieder blockierend, fuer api::run.
        if let Ok(store) = empfaenger.try_recv() {
            for l in lauscher {
                let _ = l.set_nonblocking(false);
            }
            crate::net::log("entsperrt");
            return store;
        }
        let mut etwas = false;
        for l in lauscher {
            match l.annehmen() {
                Ok(Some(strom)) => {
                    etwas = true;
                    let sender = sender.clone();
                    let pfad = pfad.to_path_buf();
                    std::thread::spawn(move || {
                        if let Some(store) = bedienen(strom, &pfad, lan_port) {
                            let _ = sender.send(store);
                        }
                    });
                }
                // Ein Fremder am Sockel: schon abgewiesen und protokolliert.
                Ok(None) => etwas = true,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
        if !etwas {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

fn bedienen(mut strom: Strom, pfad: &Path, lan_port: u16) -> Option<Store> {
    // Wie api::serve: nicht ewig. Eine Gegenseite, die nie etwas schickt,
    // haelt sonst einen Faden fest, solange der Dienst lebt.
    strom.zeitgrenzen(std::time::Duration::from_secs(30));
    // Begrenzt wie die grosse Schnittstelle (Sicherheitsbefund H2).
    let mut leser = BufReader::new(strom.try_clone().ok()?).take(64 * 1024 + 4096);
    let mut zeile = String::new();
    leser.read_line(&mut zeile).ok()?;
    let mut teile = zeile.split_whitespace();
    let verb = teile.next().unwrap_or("");
    let weg = teile.next().unwrap_or("");

    // Kopfzeilen lesen: Laenge, Host, Geheimnis -- dieselbe Pruefung wie in
    // api::serve, denn dieser Weg bedient /unlock und /account/delete, bevor
    // der Speicher offen ist (Sicherheitsbefund H0).
    let koepfe = crate::api::koepfe_lesen(&mut leser).ok()?;
    let laenge = koepfe.laenge;

    let (code, rumpf, store) = if !crate::api::host_passt(koepfe.host.as_deref()) {
        (400, "{\"error\":\"wrong host\"}".to_string(), None)
    } else if !crate::api::berechtigt(&koepfe) {
        // Ohne Geheimnis nur das Noetigste, als 401 (siehe api::serve):
        // laeuft, gesperrt, und der Nachweis, dass wir das Geheimnis kennen
        // -- keine Fassung, damit eine aeltere Oberflaeche den Dienst nicht
        // fuer veraltet haelt. Aufsperren und Loeschen gibt es nur mit.
        (
            401,
            format!(
                "{{\"error\":\"unauthorised\",\"locked\":true,\"running\":true,\"nachweis\":\"{}\"}}",
                crate::api::nachweis()
            ),
            None,
        )
    } else if verb == "POST" && weg.starts_with("/unlock") {
        let mut rumpf = vec![0u8; laenge.min(4096)];
        if leser.read_exact(&mut rumpf).is_err() {
            rumpf.clear();
        }
        let passwort = passwort_aus(&String::from_utf8_lossy(&rumpf));
        match passwort {
            Some(pw) => match Store::open_mit_passwort(pfad, lan_port, &pw) {
                Ok(s) => (200, "{\"ok\":true}".to_string(), Some(s)),
                // Nach aussen absichtlich ohne Unterscheidung, ob das
                // Passwort falsch oder die Datei kaputt ist. Ins Protokoll
                // gehoert der Grund aber sehr wohl: stand er nirgends, sah
                // ein Lesefehler fuer den Benutzer aus wie ein vergessenes
                // Passwort -- und der naechste Schritt waere gewesen, das
                // Konto zu loeschen. Genau das ist einmal passiert.
                //
                // Der Grund darf keine Werte aus dem entschluesselten Zustand
                // zitieren -- Store::open kuerzt den Lesefehler dafuer auf
                // "state does not parse" samt Zeile und Spalte (7b, D4).
                Err(e) => {
                    crate::net::log(&format!("Entsperren gescheitert: {}", e));
                    (
                        403,
                        "{\"error\":\"falsches Passwort\"}".to_string(),
                        None,
                    )
                }
            },
            None => (
                400,
                "{\"error\":\"kein Passwort angegeben\"}".to_string(),
                None,
            ),
        }
    } else if verb == "POST" && weg.starts_with("/account/delete") {
        // Der Weg heraus, wenn das Passwort weg ist. Es gibt keinen anderen:
        // ohne Passwort ist die Datei nicht zu oeffnen, und ein Hintertuerchen
        // waere genau das, was hier niemand will.
        crate::net::log("Konto wird geloescht (Passwort vergessen)");
        crate::api::konto_loeschen(pfad);
        (200, "{\"ok\":true}".to_string(), None)
    } else if verb == "GET" && weg.starts_with("/status") {
        // Genau so viel, dass die Oberflaeche weiss, was sie fragen muss.
        // MIT Fassung. Ohne sie las die App "leer", hielt den Dienst fuer
        // veraltet und beendete ihn -- genau waehrend er auf das Passwort
        // wartete. Im Protokoll stand "der Speicher ist verschluesselt"
        // zweimal, 80 Sekunden auseinander, und die Oberflaeche blieb auf
        // "wird geprueft".
        (
            200,
            format!(
                "{{\"locked\":true,\"running\":true,\"version\":\"{}\"}}",
                env!("CARGO_PKG_VERSION")
            ),
            None,
        )
    } else {
        (
            503,
            "{\"error\":\"gesperrt\",\"locked\":true}".to_string(),
            None,
        )
    };

    let antwort = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        if code == 200 { "OK" } else { "Error" },
        rumpf.len(),
        rumpf
    );
    let _ = strom.write_all(antwort.as_bytes());
    let _ = strom.flush();
    store
}

/// Das Passwort aus dem JSON-Rumpf holen, ohne einen Parser dafuer zu
/// bemuehen: es ist ein Feld, und der Rumpf kommt von der eigenen
/// Oberflaeche.
fn passwort_aus(rumpf: &str) -> Option<String> {
    let wert: serde_json::Value = serde_json::from_str(rumpf).ok()?;
    let pw = wert.get("password")?.as_str()?;
    if pw.is_empty() {
        None
    } else {
        Some(pw.to_string())
    }
}

#[cfg(test)]
mod nebenlaeufig_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// Eine haengende Verbindung darf keine zweite aufhalten.
    ///
    /// Vorher lief alles nacheinander im Annehmen-Faden: ein scrypt-Lauf hielt
    /// ihn knapp zwei Sekunden auf (am N9 nachgemessen), und die Abfrage der
    /// Oberflaeche blieb so lange in der Warteschlange. Wurde der Lauscher
    /// gleich darauf abgeloest, bekam sie nie eine Antwort -- die Oberflaeche
    /// stand fuer immer auf "wird geprueft".
    ///
    /// Die Pruefung stellt das schaerfer nach als scrypt es koennte: die erste
    /// Verbindung nennt eine Rumpflaenge und schickt den Rumpf nie.
    #[test]
    fn eine_haengende_verbindung_haelt_die_naechste_nicht_auf() {
        // Ein eigener Ordner: lauscher_oeffnen schliesst den Ordner der
        // state.json ab, und das soll nicht das gemeinsame temp_dir sein.
        let mut ordner = std::env::temp_dir();
        ordner.push(format!("briar-entsperren-nebenlaeufig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ordner);
        std::fs::create_dir_all(&ordner).unwrap();
        let pfad = ordner.join("state.json");
        {
            let mut store = Store::open(&pfad, 7399).unwrap();
            store.create_identity("ich").unwrap();
            store.passwort_setzen(None, "Probewort123").unwrap();
        }

        // Einen freien Port nehmen und gleich wieder hergeben.
        let port = {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap().port()
        };
        crate::api::geheimnis_anlegen(&pfad).unwrap();
        let geheimnis = crate::api::geheimnis().to_string();
        let lauscher =
            crate::api::lauscher_oeffnen(&pfad, &crate::api::sockel_pfad(&pfad), Some(port))
                .unwrap();
        let pfad2 = pfad.clone();
        let dienst = std::thread::spawn(move || warten(&pfad2, &lauscher, 7399));

        // Warten, bis der Dienst lauscht.
        let mut haenger = None;
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                haenger = Some(s);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let mut haenger = haenger.expect("der Wartedienst lauscht nicht");
        // Eine Anfrage, deren Rumpf nie kommt: der bedienende Faden bleibt im
        // Lesen stehen.
        haenger
            .write_all(
                format!(
                    "POST /unlock HTTP/1.1\r\nX-Briar-Geheimnis: {}\r\nContent-Length: 40\r\n\r\n",
                    geheimnis
                )
                .as_bytes(),
            )
            .unwrap();
        haenger.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Und jetzt die zweite Verbindung -- sie muss trotzdem antworten.
        let mut zweite = TcpStream::connect(("127.0.0.1", port)).unwrap();
        zweite
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        zweite.write_all(b"GET /status HTTP/1.1\r\n\r\n").unwrap();
        zweite.flush().unwrap();
        let mut antwort = String::new();
        zweite.read_to_string(&mut antwort).unwrap();
        assert!(
            antwort.contains("\"locked\":true"),
            "die zweite Verbindung bekam keine Antwort: {:?}",
            antwort
        );
        // Ohne Geheimnis: 401 mit Nachweis, ohne Fassung.
        assert!(antwort.starts_with("HTTP/1.1 401"), "{:?}", antwort);
        assert!(antwort.contains(&format!("\"nachweis\":\"{}\"", crate::api::nachweis())), "{:?}", antwort);
        assert!(!antwort.contains("\"version\""), "{:?}", antwort);
        // Mit Geheimnis in der Zweitschreibweise: 200 mit Fassung.
        let mut mit = TcpStream::connect(("127.0.0.1", port)).unwrap();
        mit.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        mit.write_all(
            format!("GET /status HTTP/1.1\r\nX-Briar-Geheimnis: {}\r\n\r\n", geheimnis).as_bytes(),
        )
        .unwrap();
        let mut voll = String::new();
        let _ = mit.read_to_string(&mut voll);
        assert!(voll.starts_with("HTTP/1.1 200") && voll.contains("\"version\":\""), "{:?}", voll);
        // Fremder Host: 400.
        let mut fremd = TcpStream::connect(("127.0.0.1", port)).unwrap();
        fremd
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        fremd
            .write_all(b"GET /status HTTP/1.1\r\nHost: boese.example\r\n\r\n")
            .unwrap();
        let mut abgelehnt = String::new();
        let _ = fremd.read_to_string(&mut abgelehnt);
        assert!(abgelehnt.starts_with("HTTP/1.1 400"), "{:?}", abgelehnt);

        // Ohne Geheimnis kein Aufsperren, auch nicht mit dem richtigen
        // Passwort (Sicherheitsbefund H0/K1).
        let rumpf = "{\"password\":\"Probewort123\"}";
        let mut ohne = TcpStream::connect(("127.0.0.1", port)).unwrap();
        ohne.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        ohne.write_all(
            format!(
                "POST /unlock HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
                rumpf.len(),
                rumpf
            )
            .as_bytes(),
        )
        .unwrap();
        let mut abgewiesen = String::new();
        let _ = ohne.read_to_string(&mut abgewiesen);
        assert!(
            abgewiesen.starts_with("HTTP/1.1 401") && abgewiesen.contains("unauthorised"),
            "ohne Geheimnis muss 401 kommen: {:?}",
            abgewiesen
        );

        // Zum Schluss richtig entsperren, damit der Faden zurueckkommt.
        let mut dritte = TcpStream::connect(("127.0.0.1", port)).unwrap();
        dritte
            .write_all(
                format!(
                    "POST /unlock HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{}",
                    geheimnis,
                    rumpf.len(),
                    rumpf
                )
                .as_bytes(),
            )
            .unwrap();
        dritte.flush().unwrap();
        let mut ok = String::new();
        let _ = dritte.read_to_string(&mut ok);
        assert!(ok.contains("\"ok\":true"), "entsperren scheiterte: {:?}", ok);
        let store = dienst.join().expect("der Wartedienst kam nicht zurueck");
        assert!(store.identity().is_some());
        let _ = std::fs::remove_dir_all(&ordner);
    }

    /// Eine Anfrage von Hand auf den Sockel, Antwort bis zum Ende.
    fn ueber_sockel(sockel: &Path, text: &str) -> String {
        let mut s = std::os::unix::net::UnixStream::connect(sockel).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        s.write_all(text.as_bytes()).unwrap();
        let mut antwort = String::new();
        let _ = s.read_to_string(&mut antwort);
        antwort
    }

    /// Der Wartedienst vor dem Entsperren spricht auf dem Sockel dieselbe
    /// Sprache wie auf dem Port: ohne Geheimnis 401 mit Nachweis, mit
    /// Geheimnis die Fassung, und das Passwort sperrt auf. Danach steht der
    /// Sockel noch -- die Lauscher gehen an api::run weiter, statt neu
    /// gebunden zu werden.
    #[test]
    fn der_wartedienst_antwortet_ueber_den_sockel() {
        let mut ordner = std::env::temp_dir();
        ordner.push(format!("briar-entsperren-sockel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ordner);
        std::fs::create_dir_all(&ordner).unwrap();
        let pfad = ordner.join("state.json");
        {
            let mut store = Store::open(&pfad, 7399).unwrap();
            store.create_identity("ich").unwrap();
            store.passwort_setzen(None, "Probewort123").unwrap();
        }
        crate::api::geheimnis_anlegen(&pfad).unwrap();
        let geheimnis = crate::api::geheimnis().to_string();
        let sockel = crate::api::sockel_pfad(&pfad);
        let lauscher = crate::api::lauscher_oeffnen(&pfad, &sockel, None).unwrap();
        assert_eq!(lauscher.len(), 1, "ohne --api-port kein TCP");
        let pfad2 = pfad.clone();
        let dienst = std::thread::spawn(move || {
            let store = warten(&pfad2, &lauscher, 7399);
            (store, lauscher)
        });

        let ohne = ueber_sockel(&sockel, "GET /status HTTP/1.0\r\n\r\n");
        assert!(ohne.starts_with("HTTP/1.1 401"), "{:?}", ohne);
        assert!(
            ohne.contains(&format!("\"nachweis\":\"{}\"", crate::api::nachweis())),
            "{:?}",
            ohne
        );
        assert!(!ohne.contains("\"version\""), "{:?}", ohne);

        let mit = ueber_sockel(
            &sockel,
            &format!("GET /status HTTP/1.0\r\nAuthorization: Bearer {}\r\n\r\n", geheimnis),
        );
        assert!(mit.starts_with("HTTP/1.1 200") && mit.contains("\"version\":\""), "{:?}", mit);

        let rumpf = "{\"password\":\"Probewort123\"}";
        let ok = ueber_sockel(
            &sockel,
            &format!(
                "POST /unlock HTTP/1.0\r\nX-Briar-Geheimnis: {}\r\nContent-Length: {}\r\n\r\n{}",
                geheimnis,
                rumpf.len(),
                rumpf
            ),
        );
        assert!(ok.contains("\"ok\":true"), "entsperren scheiterte: {:?}", ok);
        let (store, lauscher) = dienst.join().expect("der Wartedienst kam nicht zurueck");
        assert!(store.identity().is_some());
        // Der Sockel ist noch gebunden: ein connect gelingt, auch wenn
        // gerade niemand annimmt.
        assert!(std::os::unix::net::UnixStream::connect(&sockel).is_ok());
        drop(lauscher);
        let _ = std::fs::remove_dir_all(&ordner);
    }
}
