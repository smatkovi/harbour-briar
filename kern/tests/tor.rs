//! Der Umgang mit Tors Steuerport, geprueft gegen eine Attrappe.
//!
//! Was hier haengt, ist die eine Regel, die im Betrieb nicht auffiele, bis
//! Tor mitten im Gespraech verschwindet: TAKEOWNERSHIP bindet Tor an JEDE
//! Steuerverbindung, die es verlangt, und Tor stirbt, sobald eine davon
//! schliesst. `connect` (fuer jeden ausgehenden Aufbau gerufen und gleich
//! wieder fallen gelassen) darf es darum nie senden; und ein Tor, das schon
//! auf unserem Port laeuft, wird erst eingeordnet: nur eine Waise wird
//! angefasst -- und die wird beendet, nicht weiterbetrieben.

use briarkern::tor::{self, Vorgefunden};
use briarkern::util::{from_hex, to_hex};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SERVER_SCHLUESSEL: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const CLIENT_SCHLUESSEL: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// Ein Tor-Steuerport aus Pappe: merkt sich jeden Befehl und antwortet
/// 250 OK -- ausser auf GETINFO config-file und process/pid, da nennt er,
/// was ihm gesagt wurde, oder 552, wenn nichts. Mit `cookie` spricht er
/// SAFECOOKIE wie ein Tor mit CookieAuthentication 1 (weist sich mit dem
/// Server-HMAC aus, prueft den Client-HMAC) und schliesst nach einem
/// Fehlversuch die Verbindung, wie Tor es tut; ohne nimmt er das leere
/// Passwort (wie ein Tor bis 0.38.0). Ein `faelscher` sagt zu allem 250 --
/// auch auf AUTHCHALLENGE, mit einem erfundenen Hash. Schliesst die
/// Gegenseite, steht "<zu>" in der Liste.
struct Attrappe {
    port: u16,
    befehle: Arc<Mutex<Vec<String>>>,
}

fn attrappe(config_file: Option<&str>, pid: Option<u32>) -> Attrappe {
    attrappe_mit(config_file, pid, None, false)
}

fn attrappe_mit(
    config_file: Option<&str>,
    pid: Option<u32>,
    cookie: Option<Vec<u8>>,
    faelscher: bool,
) -> Attrappe {
    let lauscher = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = lauscher.local_addr().unwrap().port();
    let befehle = Arc::new(Mutex::new(Vec::new()));
    let merker = Arc::clone(&befehle);
    let config = config_file.map(|s| s.to_string());
    std::thread::spawn(move || {
        for socket in lauscher.incoming() {
            let socket = match socket {
                Ok(s) => s,
                Err(_) => break,
            };
            let merker = Arc::clone(&merker);
            let config = config.clone();
            let cookie = cookie.clone();
            std::thread::spawn(move || {
                let mut leser = BufReader::new(socket.try_clone().unwrap());
                let mut schreiber = socket;
                let mut zeile = String::new();
                // Was ein echter Client nach der Herausforderung schicken muss.
                let mut erwartete_antwort: Option<String> = None;
                while leser.read_line(&mut zeile).map(|n| n > 0).unwrap_or(false) {
                    let befehl = zeile.trim_end().to_string();
                    merker.lock().unwrap().push(befehl.clone());
                    if let Some(rest) = befehl.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
                        if faelscher {
                            // Ein Hash in voller Laenge, damit der Vergleich
                            // Byte fuer Byte laeuft und nicht schon an der
                            // Laenge scheitert.
                            let _ = schreiber.write_all(
                                format!(
                                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                                    "AB".repeat(32),
                                    "CD".repeat(32)
                                )
                                .as_bytes(),
                            );
                            zeile.clear();
                            continue;
                        }
                        let cookie = match &cookie {
                            Some(c) => c.clone(),
                            None => {
                                let _ = schreiber.write_all(
                                    b"513 SAFECOOKIE authentication is not enabled\r\n",
                                );
                                zeile.clear();
                                continue;
                            }
                        };
                        let client_nonce = from_hex(rest).unwrap_or_default();
                        let server_nonce: Vec<u8> = (0u8..32).map(|i| 200u8.wrapping_add(i)).collect();
                        let mut m = cookie.clone();
                        m.extend_from_slice(&client_nonce);
                        m.extend_from_slice(&server_nonce);
                        let server_hash = tor::hmac_sha256(SERVER_SCHLUESSEL, &m);
                        erwartete_antwort = Some(format!(
                            "AUTHENTICATE {}",
                            to_hex(&tor::hmac_sha256(CLIENT_SCHLUESSEL, &m))
                        ));
                        // Tor schreibt Hex in Grossbuchstaben (binascii.c);
                        // die Attrappe auch, damit unser Leser das kann.
                        let _ = schreiber.write_all(
                            format!(
                                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                                to_hex(&server_hash).to_uppercase(),
                                to_hex(&server_nonce).to_uppercase()
                            )
                            .as_bytes(),
                        );
                        zeile.clear();
                        continue;
                    }
                    if befehl.starts_with("AUTHENTICATE") {
                        let richtig = faelscher
                            || match (&cookie, &erwartete_antwort) {
                                (Some(_), Some(e)) => &befehl == e,
                                (Some(_), None) => false,
                                (None, _) => befehl == "AUTHENTICATE \"\"",
                            };
                        if richtig {
                            let _ = schreiber.write_all(b"250 OK\r\n");
                            zeile.clear();
                            continue;
                        }
                        let _ = schreiber.write_all(b"515 Authentication failed\r\n");
                        break;
                    }
                    let antwort = match befehl.as_str() {
                        "GETINFO config-file" => match &config {
                            Some(p) => format!("250-config-file={}\r\n250 OK\r\n", p),
                            None => "552 Unrecognized key \"config-file\"\r\n".to_string(),
                        },
                        "GETINFO process/pid" => match pid {
                            Some(p) => format!("250-process/pid={}\r\n250 OK\r\n", p),
                            None => "552 Unrecognized key \"process/pid\"\r\n".to_string(),
                        },
                        _ => "250 OK\r\n".to_string(),
                    };
                    if schreiber.write_all(antwort.as_bytes()).is_err() {
                        break;
                    }
                    zeile.clear();
                }
                merker.lock().unwrap().push("<zu>".to_string());
            });
        }
    });
    Attrappe { port, befehle }
}

impl Attrappe {
    /// Jeder Befehl wird vermerkt, bevor die Antwort geht; wer die Antwort
    /// hat, sieht den Befehl also schon. Nur das "<zu>" nach dem Schliessen
    /// kommt aus dem Faden der Attrappe -- darauf wird kurz gewartet.
    fn gesehen(&self) -> Vec<String> {
        self.befehle.lock().unwrap().clone()
    }
    fn gesehen_bis_zu(&self) -> Vec<String> {
        for _ in 0..100 {
            let g = self.gesehen();
            if g.last().map(|s| s == "<zu>").unwrap_or(false) {
                return g;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        self.gesehen()
    }
}

/// Ein Tor-Verzeichnis mit torrc, damit `einordnen` etwas zum Vergleichen hat.
fn tor_verzeichnis(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("briar-tor-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("torrc"), "ControlPort 1\n").unwrap();
    d
}

/// Dasselbe mit einem Cookie, wie Tor es beim Oeffnen des Steuerports ablegt.
fn tor_verzeichnis_mit_cookie(name: &str) -> (PathBuf, Vec<u8>) {
    let d = tor_verzeichnis(name);
    let cookie: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect();
    std::fs::write(tor::cookie_pfad(&d), &cookie).unwrap();
    (d, cookie)
}

#[test]
fn torrc_traegt_die_notbremse_und_sonst_nichts_neues() {
    let text = tor::torrc_text(59050, 59051, Path::new("/daten/tor"));
    assert!(text.contains("SocksPort 127.0.0.1:59050\n"));
    assert!(text.contains("ControlPort 127.0.0.1:59051\n"));
    assert!(text.contains("DataDirectory /daten/tor\n"));
    assert!(text.contains("MaxMemInQueues 64 MB\n"), "{}", text);
    assert!(text.contains("AvoidDiskWrites 1\n"));
    // Wie Briar: Cookie am Steuerport, keine nackten Adressen an SOCKS,
    // keine Laenderdatenbank, keine Fuellzellen.
    assert!(text.contains("CookieAuthentication 1\n"), "{}", text);
    assert!(!text.contains("CookieAuthentication 0"));
    assert!(text.contains("SafeSocks 1\n"));
    assert!(text.contains("GeoIPFile\nGeoIPv6File\n"));
    assert!(text.contains("ConnectionPadding 0\n"));
    // Kein Riegel, der Tor am Laden hinderte.
    assert!(!text.contains("DisableNetwork"));
}

#[test]
fn freier_platz_ist_messbar_und_fehlt_bei_fremden_pfaden() {
    let tmp = std::env::temp_dir();
    assert!(tor::freier_platz_mb(&tmp).is_some(), "statvfs auf {:?} antwortet nicht", tmp);
    assert!(tor::freier_platz_mb(Path::new("/gibt/es/nicht/tor")).is_none());
}

#[test]
fn verbinden_uebernimmt_nicht() {
    let a = attrappe(None, None);
    let tor = tor::connect_to(a.port, 0, None).expect("Attrappe nimmt das leere Passwort");
    assert_eq!(tor.control_port, a.port);
    // Ohne Cookie angemeldet: nicht vertraut. Einordnen darf man so ein Tor,
    // einen Dienst darauf anmelden nie.
    assert!(!tor.vertraut);
    let gesehen = a.gesehen();
    assert!(gesehen.iter().any(|b| b.starts_with("AUTHENTICATE")), "keine Anmeldung: {:?}", gesehen);
    assert!(
        !gesehen.iter().any(|b| b == "TAKEOWNERSHIP"),
        "connect darf Tor nicht uebernehmen -- jeder Waehler toetete es sonst: {:?}",
        gesehen
    );
    drop(tor);
}

#[test]
fn uebernehmen_bindet_tor_an_die_verbindung_und_stellt_die_pid_wache_ab() {
    let a = attrappe(None, None);
    let mut tor = tor::connect_to(a.port, 0, None).unwrap();
    tor.uebernehmen().expect("Attrappe sagt 250");
    let gesehen = a.gesehen();
    let pos = |s: &str| gesehen.iter().position(|b| b == s);
    let besitz = pos("TAKEOWNERSHIP").expect("TAKEOWNERSHIP fehlt");
    let reset = pos("RESETCONF __OwningControllerProcess").expect("RESETCONF fehlt");
    assert!(besitz < reset, "erst uebernehmen, dann die Wache abstellen: {:?}", gesehen);
}

#[test]
fn getinfo_liest_datei_und_prozessnummer() {
    let a = attrappe(Some("/daten/tor/torrc"), Some(4711));
    let mut tor = tor::connect_to(a.port, 0, None).unwrap();
    assert_eq!(tor.konfigurationsdatei().as_deref(), Some("/daten/tor/torrc"));
    assert_eq!(tor.prozessnummer(), Some(4711));
    let b = attrappe(None, None);
    let mut tor = tor::connect_to(b.port, 0, None).unwrap();
    assert_eq!(tor.konfigurationsdatei(), None);
    assert_eq!(tor.prozessnummer(), None);
}

#[test]
fn elternprozess_kommt_aus_proc_und_dienstnamen_sind_erkannt() {
    let eltern = tor::elternprozess(std::process::id()).expect("/proc/self/stat");
    assert_eq!(eltern, unsafe { libc::getppid() } as u32);
    assert!(!tor::prozessname(std::process::id()).is_empty());
    assert!(tor::ist_dienst("briard"));
    assert!(tor::ist_dienst("harbour-briar-b"));
    assert!(!tor::ist_dienst("tor"));
    assert!(!tor::ist_dienst("systemd"));
    assert!(!tor::ist_dienst("init"));
}

#[test]
fn fremdes_tor_wird_nur_mitbenutzt() {
    let d = tor_verzeichnis("fremd");
    // Liest eine andere torrc.
    let a = attrappe(Some("/etc/tor/torrc"), Some(std::process::id()));
    let mut tor = tor::connect_to(a.port, 0, None).unwrap();
    assert_eq!(tor::einordnen(&mut tor, &d), Vorgefunden::Fremd);
    assert!(!a.gesehen().iter().any(|b| b == "TAKEOWNERSHIP"));
    // Nennt keine Prozessnummer: nicht zu beurteilen, also auch fremd.
    let torrc = d.join("torrc").to_string_lossy().to_string();
    let b = attrappe(Some(&torrc), None);
    let mut tor = tor::connect_to(b.port, 0, None).unwrap();
    assert_eq!(tor::einordnen(&mut tor, &d), Vorgefunden::Fremd);
    // Unsere torrc gibt es nicht: ebenso.
    let c = attrappe(Some(&torrc), Some(std::process::id()));
    let mut tor = tor::connect_to(c.port, 0, None).unwrap();
    assert_eq!(tor::einordnen(&mut tor, Path::new("/gibt/es/nicht")), Vorgefunden::Fremd);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn waise_wird_erkannt_und_beendet_nicht_uebernommen() {
    // Unsere torrc, und als Prozessnummer die des Pruefstands selbst: sein
    // Elternprozess ist cargo, kein Dienst -- also eine Waise.
    let d = tor_verzeichnis("waise");
    let torrc = d.join("torrc").to_string_lossy().to_string();
    let a = attrappe(Some(&torrc), Some(std::process::id()));
    let mut tor = tor::connect_to(a.port, 0, None).unwrap();
    assert_eq!(tor::einordnen(&mut tor, &d), Vorgefunden::Waise);
    // Einordnen allein sendet noch kein TAKEOWNERSHIP.
    assert!(!a.gesehen().iter().any(|b| b == "TAKEOWNERSHIP"));
    // Beenden: TAKEOWNERSHIP, dann schliesst die Verbindung -- Tor stirbt
    // damit, ohne RESETCONF und ohne dass etwas weiterbetrieben wuerde.
    assert!(tor.beenden());
    let gesehen = a.gesehen_bis_zu();
    let n = gesehen.len();
    assert_eq!(&gesehen[n - 2..], ["TAKEOWNERSHIP", "<zu>"], "{:?}", gesehen);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn symlink_im_pfad_hindert_die_erkennung_nicht() {
    // Tor nennt den Pfad, wie er hinter -f stand; wir vergleichen aufgeloest.
    let d = tor_verzeichnis("symlink");
    let link = std::env::temp_dir().join(format!("briar-tor-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&d, &link).unwrap();
    let ueber_link = link.join("torrc").to_string_lossy().to_string();
    let a = attrappe(Some(&ueber_link), Some(std::process::id()));
    let mut tor = tor::connect_to(a.port, 0, None).unwrap();
    assert_eq!(tor::einordnen(&mut tor, &d), Vorgefunden::Waise);
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_dir_all(&d);
}


#[test]
fn mit_cookie_angemeldet_ist_vertraut_und_das_cookie_bleibt_zu_hause() {
    let (d, cookie) = tor_verzeichnis_mit_cookie("cookie");
    let a = attrappe_mit(None, None, Some(cookie.clone()), false);
    let tor = tor::connect_to(a.port, 0, Some(&d)).expect("Cookie passt");
    assert!(tor.vertraut);
    let gesehen = a.gesehen();
    assert!(
        gesehen.first().map(|s| s.starts_with("AUTHCHALLENGE SAFECOOKIE ")).unwrap_or(false),
        "{:?}",
        gesehen
    );
    assert!(gesehen.iter().any(|b| b.starts_with("AUTHENTICATE ") && b.len() > 20));
    // Das Cookie selbst geht nie ueber die Leitung, nur ein HMAC darueber.
    let hex = to_hex(&cookie);
    assert!(!gesehen.iter().any(|b| b.contains(&hex)), "{:?}", gesehen);
    // Das leere Passwort wurde gar nicht erst probiert.
    assert!(!gesehen.iter().any(|b| b == "AUTHENTICATE \"\""), "{:?}", gesehen);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ohne_passendes_cookie_kommt_keine_verbindung_zustande() {
    // Tor verlangt ein Cookie, wir haben ein anderes: sein Server-HMAC passt
    // nicht zu unserem, wir brechen ab; das leere Passwort scheitert auch --
    // Ergebnis ist ein Fehler, kein untergeschobenes Tor.
    let (d, _) = tor_verzeichnis_mit_cookie("falsch");
    let fremd: Vec<u8> = vec![0xaa; 32];
    let a = attrappe_mit(None, None, Some(fremd), false);
    assert!(tor::connect_to(a.port, 0, Some(&d)).is_err());
    let gesehen = a.gesehen_bis_zu();
    assert!(gesehen.iter().any(|b| b.starts_with("AUTHCHALLENGE")), "{:?}", gesehen);
    // Nach der falschen Herausforderung haben wir keinen Client-HMAC gesandt.
    assert!(
        !gesehen.iter().any(|b| b.starts_with("AUTHENTICATE ") && b.len() > 20),
        "{:?}",
        gesehen
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ein_faelscher_der_zu_allem_ja_sagt_ist_nicht_vertraut() {
    // Gegenpruefung 0.39.0, B1: wer unseren Port belegt und auf alles 250
    // antwortet, galt mit COOKIE als unser Tor und bekam Cookie und
    // Onion-Schluessel. Mit SAFECOOKIE muss er das Cookie kennen -- kann er
    // nicht, bleibt er ein Fremder, und ueber die Leitung ging nichts, was
    // ihm nuetzt.
    let (d, cookie) = tor_verzeichnis_mit_cookie("faelscher");
    let a = attrappe_mit(None, None, None, true);
    let tor = tor::connect_to(a.port, 0, Some(&d)).expect("der Faelscher nimmt auch das leere Passwort");
    assert!(!tor.vertraut, "ein Faelscher darf nie vertraut sein");
    let gesehen = a.gesehen();
    let hex = to_hex(&cookie);
    assert!(!gesehen.iter().any(|b| b.contains(&hex)), "Cookie verraten: {:?}", gesehen);
    assert!(
        !gesehen.iter().any(|b| b.starts_with("AUTHENTICATE ") && b != "AUTHENTICATE \"\""),
        "HMAC an einen Faelscher gesandt: {:?}",
        gesehen
    );
    // Und ein unvertrautes Tor bekommt keinen Dienst: connect() liefert es
    // nicht -- das prueft der Aufrufer ueber `vertraut`; hier genuegt, dass
    // die Kennung stimmt.
    assert!(!tor.vertraut);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ein_halb_geschriebenes_cookie_zaehlt_nicht() {
    // Tor schreibt das Cookie beim Oeffnen des Steuerports; wer es zu frueh
    // liest, sieht eine kurze Datei. Die darf nicht als Cookie gelten.
    let d = tor_verzeichnis("kurz");
    std::fs::write(tor::cookie_pfad(&d), [1u8; 10]).unwrap();
    // Eine kurze Datei kann nur etwas Fremdes sein (Tor schreibt atomar 32
    // Byte); sie zaehlt nicht als Cookie.
    let a = attrappe(None, None);
    let tor = tor::connect_to(a.port, 0, Some(&d)).unwrap();
    assert!(!tor.vertraut);
    let gesehen = a.gesehen();
    assert_eq!(gesehen.first().map(|s| s.as_str()), Some("AUTHENTICATE \"\""), "{:?}", gesehen);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn socks_port_lebt_genau_so_lange_wie_die_wache() {
    assert_eq!(tor::socks_port(), None);
    {
        let _wache = tor::SocksWache::merken(59050);
        assert_eq!(tor::socks_port(), Some(59050));
    }
    assert_eq!(tor::socks_port(), None);
}
