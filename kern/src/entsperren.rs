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
    loop {
        let (strom, _) = match lauscher.accept() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(store) = bedienen(strom, pfad, default_port) {
            crate::net::log("entsperrt");
            return store;
        }
    }
}

fn bedienen(mut strom: TcpStream, pfad: &Path, default_port: u16) -> Option<Store> {
    let mut leser = BufReader::new(strom.try_clone().ok()?);
    let mut zeile = String::new();
    leser.read_line(&mut zeile).ok()?;
    let mut teile = zeile.split_whitespace();
    let verb = teile.next().unwrap_or("");
    let weg = teile.next().unwrap_or("");

    // Kopfzeilen ueberlesen, dabei die Laenge merken.
    let mut laenge = 0usize;
    loop {
        let mut kopf = String::new();
        if leser.read_line(&mut kopf).ok()? == 0 || kopf.trim().is_empty() {
            break;
        }
        let kopf = kopf.to_ascii_lowercase();
        if let Some(wert) = kopf.strip_prefix("content-length:") {
            laenge = wert.trim().parse().unwrap_or(0);
        }
    }

    let (code, rumpf, store) = if verb == "POST" && weg.starts_with("/unlock") {
        let mut rumpf = vec![0u8; laenge.min(4096)];
        if leser.read_exact(&mut rumpf).is_err() {
            rumpf.clear();
        }
        let passwort = passwort_aus(&String::from_utf8_lossy(&rumpf));
        match passwort {
            Some(pw) => match Store::open_mit_passwort(pfad, default_port, &pw) {
                Ok(s) => (200, "{\"ok\":true}".to_string(), Some(s)),
                // Absichtlich ohne Unterscheidung nach aussen, ob das
                // Passwort falsch oder die Datei kaputt ist -- der Grund
                // steht im Protokoll, nicht in der Antwort.
                Err(_) => (
                    403,
                    "{\"error\":\"falsches Passwort\"}".to_string(),
                    None,
                ),
            },
            None => (
                400,
                "{\"error\":\"kein Passwort angegeben\"}".to_string(),
                None,
            ),
        }
    } else if verb == "GET" && weg.starts_with("/status") {
        // Genau so viel, dass die Oberflaeche weiss, was sie fragen muss.
        (200, "{\"locked\":true,\"running\":true}".to_string(), None)
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
