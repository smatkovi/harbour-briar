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
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Ein Tor-Steuerport aus Pappe: merkt sich jeden Befehl und antwortet
/// 250 OK -- ausser auf GETINFO config-file und process/pid, da nennt er,
/// was ihm gesagt wurde, oder 552, wenn nichts. Schliesst die Gegenseite,
/// steht "<zu>" in der Liste.
struct Attrappe {
    port: u16,
    befehle: Arc<Mutex<Vec<String>>>,
}

fn attrappe(config_file: Option<&str>, pid: Option<u32>) -> Attrappe {
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
            std::thread::spawn(move || {
                let mut leser = BufReader::new(socket.try_clone().unwrap());
                let mut schreiber = socket;
                let mut zeile = String::new();
                while leser.read_line(&mut zeile).map(|n| n > 0).unwrap_or(false) {
                    let befehl = zeile.trim_end().to_string();
                    merker.lock().unwrap().push(befehl.clone());
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

#[test]
fn torrc_traegt_die_notbremse_und_sonst_nichts_neues() {
    let text = tor::torrc_text(59050, 59051, Path::new("/daten/tor"));
    assert!(text.contains("SocksPort 127.0.0.1:59050\n"));
    assert!(text.contains("ControlPort 127.0.0.1:59051\n"));
    assert!(text.contains("DataDirectory /daten/tor\n"));
    assert!(text.contains("MaxMemInQueues 64 MB\n"), "{}", text);
    assert!(text.contains("AvoidDiskWrites 1\n"));
    // Kein Riegel, der Tor am Laden hinderte, und kein Padding-Schalter:
    // beides spart nachgemessen keinen Speicher.
    assert!(!text.contains("DisableNetwork"));
    assert!(!text.contains("ConnectionPadding"));
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
    let tor = tor::connect_to(a.port, 0).expect("Attrappe nimmt jede Anmeldung");
    assert_eq!(tor.control_port, a.port);
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
    let mut tor = tor::connect_to(a.port, 0).unwrap();
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
    let mut tor = tor::connect_to(a.port, 0).unwrap();
    assert_eq!(tor.konfigurationsdatei().as_deref(), Some("/daten/tor/torrc"));
    assert_eq!(tor.prozessnummer(), Some(4711));
    let b = attrappe(None, None);
    let mut tor = tor::connect_to(b.port, 0).unwrap();
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
    let mut tor = tor::connect_to(a.port, 0).unwrap();
    assert_eq!(tor::einordnen(&mut tor, &d), Vorgefunden::Fremd);
    assert!(!a.gesehen().iter().any(|b| b == "TAKEOWNERSHIP"));
    // Nennt keine Prozessnummer: nicht zu beurteilen, also auch fremd.
    let torrc = d.join("torrc").to_string_lossy().to_string();
    let b = attrappe(Some(&torrc), None);
    let mut tor = tor::connect_to(b.port, 0).unwrap();
    assert_eq!(tor::einordnen(&mut tor, &d), Vorgefunden::Fremd);
    // Unsere torrc gibt es nicht: ebenso.
    let c = attrappe(Some(&torrc), Some(std::process::id()));
    let mut tor = tor::connect_to(c.port, 0).unwrap();
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
    let mut tor = tor::connect_to(a.port, 0).unwrap();
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
    let mut tor = tor::connect_to(a.port, 0).unwrap();
    assert_eq!(tor::einordnen(&mut tor, &d), Vorgefunden::Waise);
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_dir_all(&d);
}
