//! Auf das Passwort warten, bevor der Dienst loslegt.
//!
//! Ist der Speicher verschluesselt, kann der Dienst beim Hochfahren nichts
//! tun: er kennt weder Kontakte noch Schluessel. Statt abzubrechen -- was
//! bedeutete, dass die App nach jedem Neustart von Hand gestartet werden
//! muesste -- lauscht er auf dem gewohnten Port und beantwortet genau zwei
//! Dinge: "ich bin gesperrt" und "hier ist das Passwort". Erst danach faehrt
//! der Rest hoch.
//!
//! Absichtlich ein eigener, winziger Server statt einer Sonderbehandlung im
//! grossen: der grosse braucht einen Store, den es hier noch nicht gibt.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use crate::store::Store;

/// Lauscht, bis jemand ein gueltiges Passwort schickt, und gibt den damit
/// geoeffneten Speicher zurueck. Kehrt nur mit Erfolg zurueck.
pub fn warten(pfad: &Path, api_port: u16, default_port: u16) -> Store {
    let lauscher = match TcpListener::bind(("127.0.0.1", api_port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Entsperren: Port {} nicht zu haben: {}", api_port, e);
            std::process::exit(1);
        }
    };
    crate::net::log("der Speicher ist verschluesselt -- warte auf das Passwort");

    // Je Verbindung ein eigener Faden. Frueher lief alles nacheinander im
    // Annehmen-Faden, und ein scrypt-Lauf haelt den knapp zwei Sekunden auf
    // (am N9 nachgemessen). Die Oberflaeche fragt daneben alle drei Sekunden
    // den Zustand ab -- diese Abfrage blieb dann in der Warteschlange
    // haengen, und wenn der Lauscher gleich darauf abgeloest wurde, bekam sie
    // nie eine Antwort. Im Protokoll stand danach "API request failed: Broken
    // pipe", und in der Oberflaeche stand fuer immer "wird geprueft".
    let (sender, empfaenger) = std::sync::mpsc::channel::<Store>();
    let _ = lauscher.set_nonblocking(true);
    loop {
        // Hat ein Faden das Passwort angenommen, sind wir fertig -- und der
        // Lauscher faellt mit dieser Funktion weg, damit der grosse Dienst
        // den Port bekommt.
        if let Ok(store) = empfaenger.try_recv() {
            crate::net::log("entsperrt");
            return store;
        }
        match lauscher.accept() {
            Ok((strom, _)) => {
                let _ = strom.set_nonblocking(false);
                let sender = sender.clone();
                let pfad = pfad.to_path_buf();
                std::thread::spawn(move || {
                    if let Some(store) = bedienen(strom, &pfad, default_port) {
                        let _ = sender.send(store);
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => continue,
        }
    }
}

fn bedienen(mut strom: TcpStream, pfad: &Path, default_port: u16) -> Option<Store> {
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
            Some(pw) => match Store::open_mit_passwort(pfad, default_port, &pw) {
                Ok(s) => (200, "{\"ok\":true}".to_string(), Some(s)),
                // Nach aussen absichtlich ohne Unterscheidung, ob das
                // Passwort falsch oder die Datei kaputt ist. Ins Protokoll
                // gehoert der Grund aber sehr wohl: stand er nirgends, sah
                // ein Lesefehler fuer den Benutzer aus wie ein vergessenes
                // Passwort -- und der naechste Schritt waere gewesen, das
                // Konto zu loeschen. Genau das ist einmal passiert.
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
        let mut pfad = std::env::temp_dir();
        pfad.push("briar-entsperren-nebenlaeufig.json");
        let _ = std::fs::remove_file(&pfad);
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
        let pfad2 = pfad.clone();
        let dienst = std::thread::spawn(move || warten(&pfad2, port, 7399));

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
        let _ = std::fs::remove_file(&pfad);
    }
}
