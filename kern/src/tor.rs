//! The Tor transport: Briar's third way to reach a contact, and the only one
//! that works when the two are not in the same room or the same network.
//!
//! No Tor is built into this daemon. It speaks to one that is already
//! running, through the two interfaces every Tor has: the control port, to
//! publish a hidden service, and the SOCKS port, to dial someone else's.
//! That is also what Briar does -- it just ships its own Tor with it.
//!
//! Briar's hidden service maps virtual port 80 to a local port, and a
//! contact's address is the bare v3 onion, published as the transport
//! property "onion3".

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

pub const VIRTUAL_PORT: u16 = 80;
const TIMEOUT: Duration = Duration::from_secs(20);
/// Kein System-Tor mehr: bis 0.38.0 wurde ein Tor auf 9051 zuerst probiert.
/// Auf keinem der Geraete gibt es eines, und wer den Port (frei fuer jeden
/// Benutzer) belegt und "250" sagt, bekaeme sonst unsere Anmeldung und den
/// Onion-Schluessel gereicht (Gegenpruefung 0.39.0, B1). Briar startet
/// ebenfalls immer sein eigenes Tor und spricht nie einen fremden Port an.
/// Der Steuerport unseres eigenen Tor; SOCKS liegt eins darunter. Nur fuer
/// zwei Dienste auf einer Maschine (tools/tor-e2e.sh) umzustellen -- mit
/// Cookie-Anmeldung kann der zweite das Tor des ersten nicht mitbenutzen,
/// also braucht jeder seines.
static EIGENER_CONTROL: AtomicU16 = AtomicU16::new(59051);
pub fn eigenen_port_setzen(control_port: u16) {
    EIGENER_CONTROL.store(control_port, Ordering::Relaxed);
}
fn eigener() -> (u16, u16) {
    let c = EIGENER_CONTROL.load(Ordering::Relaxed);
    (c, c.saturating_sub(1))
}
/// Der SOCKS-Port des Tor, das der Lauscher gerade haelt -- 0 heisst keins.
/// Der Waehler liest ihn hier, statt fuer jeden ausgehenden Aufbau eine
/// eigene Steuerverbindung zu oeffnen (und sich dafuer anmelden zu muessen).
static SOCKS: AtomicU16 = AtomicU16::new(0);
pub fn socks_port() -> Option<u16> {
    match SOCKS.load(Ordering::Relaxed) {
        0 => None,
        p => Some(p),
    }
}
/// Merkt den SOCKS-Port, solange sie lebt; faellt sie, ist er wieder weg.
/// So bleibt kein Port stehen, wenn der Lauscher auf irgendeinem Weg
/// zurueckkehrt.
pub struct SocksWache;
impl SocksWache {
    pub fn merken(port: u16) -> SocksWache {
        SOCKS.store(port, Ordering::Relaxed);
        SocksWache
    }
}
impl Drop for SocksWache {
    fn drop(&mut self) {
        SOCKS.store(0, Ordering::Relaxed);
    }
}
/// Unterhalb dieser Grenze warnt der Dienst vor dem Start: der
/// Verzeichniscache misst rund 40 MB, und beim Neuschreiben liegt er kurz
/// doppelt da. Nur eine Warnung, kein Riegel -- ein Riegel bei 100 MB haette
/// Tor am N9 nach der ersten vollen Sitzung ausgesperrt (nachgerechnet am
/// 29.09.2026: 145 MB frei, 40 MB Cache, der Rest schwindet von selbst).
const PLATZ_WARNUNG_MB: u64 = 100;
/// Bekommt Tor beim Start mit auf den Weg: stirbt der Dienst, bevor er
/// TAKEOWNERSHIP senden konnte, merkt Tor es an der fehlenden Prozessnummer
/// und beendet sich selbst (es sieht alle 15 s nach). Danach wird die Angabe
/// wieder abgestellt, wie Briars AbstractTorWrapper es haelt.
const EIGENTUEMER: &str = "__OwningControllerProcess";

pub struct Tor {
    pub control_port: u16,
    pub socks_port: u16,
    /// Held open on purpose: an ephemeral hidden service lives exactly as
    /// long as the control connection that created it.
    control: TcpStream,
    /// Our own Tor, if we started it -- it is stopped again with us, so
    /// switching the transport off gives the memory back.
    child: Option<std::process::Child>,
    /// Beidseitig ausgewiesen (SAFECOOKIE: Tor hat bewiesen, dass es unser
    /// Cookie kennt, und wir ihm). Ohne das (altes Tor bis 0.38.0 mit
    /// CookieAuthentication 0, oder etwas Fremdes auf unserem Port) darf
    /// diese Verbindung nur eines: das Tor einordnen und, wenn es eine Waise
    /// ist, beenden. Nie einen Dienst darauf anmelden -- wer auf unserem
    /// Port antwortet, ohne das Cookie zu kennen, bekaeme sonst unseren
    /// Onion-Schluessel.
    pub vertraut: bool,
}

impl Drop for Tor {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            // Erst die Steuerverbindung schliessen: Tor gehoert ihr
            // (TAKEOWNERSHIP), endet von selbst und raeumt dabei sein Cookie
            // weg. Nach SIGKILL bliebe das Cookie liegen, und beim naechsten
            // Einschalten laege es fuer jeden bereit, der unseren Port
            // belegt. SIGKILL nur, wenn Tor nicht binnen fuenf Sekunden geht.
            let _ = self.control.shutdown(std::net::Shutdown::Both);
            for _ in 0..50 {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Finds a running Tor and authenticates to its control port.
///
/// Uebernimmt es NICHT: `connect` ruft auch der Waehler fuer jeden
/// ausgehenden Aufbau (net::dial) und laesst die Verbindung gleich wieder
/// fallen. Tor stirbt nach TAKEOWNERSHIP mit genau der Verbindung, die es
/// gesandt hat -- saesse die Uebernahme hier, toetete jeder Aufbau Tor.
///
/// Liefert nur ein Tor, dem zu trauen ist (Cookie-Anmeldung); `tor_dir` ist
/// das Verzeichnis unseres eigenen Tor, wo sein Cookie liegt.
pub fn connect(tor_dir: Option<&Path>) -> Option<Tor> {
    let (control_port, socks_port) = eigener();
    match connect_to(control_port, socks_port, tor_dir) {
        Ok(tor) if tor.vertraut => Some(tor),
        _ => None,
    }
}

/// Verbindet sich mit dem Tor auf dem genannten Steuerport. Getrennt von
/// `connect`, damit ein Pruefstand eine Attrappe auf einem eigenen Port
/// unterschieben kann. Ob die Anmeldung mit Cookie gelang, steht in
/// `vertraut`.
pub fn connect_to(
    control_port: u16,
    socks_port: u16,
    tor_dir: Option<&Path>,
) -> std::io::Result<Tor> {
    let (control, vertraut) = open_control(control_port, tor_dir)?;
    Ok(Tor {
        control_port,
        socks_port,
        control,
        child: None,
        vertraut,
    })
}

/// Die torrc, die der Dienst fuer sein eigenes Tor schreibt -- Zeile fuer
/// Zeile das, was Briars AbstractTorWrapper auch schreibt, soweit es uns
/// betrifft.
///
/// Speicherseitig ist daran nichts zu holen: alle Schalter zusammen bringen
/// 0 MB (gemessen 28./29.09.2026, Jolla und arch/i486). Der Heap besteht aus
/// Konsens und Mikrodeskriptoren, und den verkleinert nur der Bau-Patch in
/// tools/build-tor.sh. Was die Zeilen sonst tun:
/// - CookieAuthentication 1: der Steuerport verlangt das Cookie aus dem
///   Datenverzeichnis (0700). Ohne das konnte jeder lokale Prozess GETINFO,
///   SIGNAL SHUTDOWN oder ADD_ONION sprechen (Sicherheitsbericht H3).
/// - SafeSocks 1: SOCKS-Anfragen mit nackter IP-Adresse werden abgewiesen;
///   wir schicken ohnehin nur Hostnamen (connect_through_socks, ATYP 3).
/// - GeoIPFile/GeoIPv6File leer: keine Laenderdatenbank laden. Heute fehlt
///   die Datei im statischen Bau ohnehin; die Zeilen halten das so, auch
///   wenn einmal ein System-Tor mit geoip herhalten sollte.
/// - ConnectionPadding 0: keine Fuellzellen. Spart keinen Speicher, aber
///   Funk und Akku, auf 2G Datenvolumen. Briar schreibt dieselbe Zeile,
///   schaltet das Padding aber im WLAN am Ladegeraet wieder ein; wir nie.
/// - MaxMemInQueues 64 MB: Notbremse gegen Lastspitzen, im Leerlauf ohne
///   Wirkung. 64 MB ist der kleinste Wert, den Tor ohne Warnung nimmt
///   (MIN_UNWARNED_CLIENT_MB), statt der Vorgabe von 768 MB am N9.
pub fn torrc_text(socks_port: u16, control_port: u16, tor_dir: &Path) -> String {
    format!(
        "SocksPort 127.0.0.1:{}\nControlPort 127.0.0.1:{}\nCookieAuthentication 1\n\
         SafeSocks 1\nDataDirectory {}\nAvoidDiskWrites 1\nClientOnly 1\n\
         GeoIPFile\nGeoIPv6File\nConnectionPadding 0\nMaxMemInQueues 64 MB\n",
        socks_port,
        control_port,
        tor_dir.display()
    )
}

/// Wo unser eigenes Tor sein Cookie ablegt (CookieAuthFile-Vorgabe: im
/// Datenverzeichnis).
pub fn cookie_pfad(tor_dir: &Path) -> std::path::PathBuf {
    tor_dir.join("control_auth_cookie")
}

/// Freier Platz unter `pfad` in MB; None, wenn das Dateisystem nicht
/// antwortet oder der Pfad fehlt.
pub fn freier_platz_mb(pfad: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(pfad.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // Sicher: `c` ist eine gueltige C-Zeichenkette, `s` ein beschreibbarer
    // Puffer der richtigen Groesse.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    // Die Feldbreiten unterscheiden sich zwischen den drei musl-Zielen:
    // erst auf u64 heben, dann rechnen.
    Some((s.f_bavail as u64).saturating_mul(s.f_frsize as u64) / (1024 * 1024))
}

/// Was auf unserem eigenen Steuerport vorgefunden wurde, als der Dienst kam.
#[derive(Debug, PartialEq, Eq)]
pub enum Vorgefunden {
    /// Liest unsere torrc, und kein lebender Dienst ist sein Elternprozess:
    /// ein Tor, das ein frueherer Dienst zurueckliess.
    Waise,
    /// Liest unsere torrc, und ein anderer laufender Dienst haelt es --
    /// eine aeltere Fassung ohne Instanzsperre. Nur mitbenutzen.
    Lebendig,
    /// Liest eine andere torrc oder nennt weder Datei noch Prozessnummer:
    /// nicht unseres. Nur mitbenutzen.
    Fremd,
}

/// Ordnet ein Tor ein, das schon auf unserem Steuerport laeuft.
///
/// Warum das noetig ist und nicht einfach TAKEOWNERSHIP: Tor nimmt jede
/// Steuerverbindung als Eigentuemer an, die es verlangt, und stirbt, sobald
/// EINE davon schliesst. Haengt noch ein anderer Dienst daran (die App hat
/// einen gestartet, dann schaltete der Benutzer den Hintergrunddienst ein --
/// systemctl --now startete den zweiten), naehme ein blindes TAKEOWNERSHIP
/// dem ersten sein Tor weg, und beim ersten fehlgeschlagenen ADD_ONION
/// (550, der Schluessel ist ja schon angemeldet) fiele die Verbindung und
/// Tor mit ihr -- minuetlich, mit Onion-Dienst dauerhaft weg. Gefunden in
/// der Gegenpruefung von 0.38.0, bevor es auf ein Geraet kam.
///
/// Eine Waise entsteht nur in dem Fenster zwischen dem Start von Tor und
/// dem TAKEOWNERSHIP -- etwa wenn die App den Dienst bei einer
/// Aktualisierung genau dann beendet. Seit 0.38.0 schliesst
/// `__OwningControllerProcess` dieses Fenster; was heute noch steht, stammt
/// aus frueheren Fassungen (Jolla, 28.09.2026: 58 MB, die niemand freigab).
pub fn einordnen(tor: &mut Tor, tor_dir: &Path) -> Vorgefunden {
    let unsere = match std::fs::canonicalize(tor_dir.join("torrc")) {
        Ok(p) => p,
        // Ohne eigene torrc gibt es nichts, was unseres sein koennte.
        Err(_) => return Vorgefunden::Fremd,
    };
    let seine = match tor.konfigurationsdatei() {
        Some(pfad) => std::fs::canonicalize(&pfad).unwrap_or_else(|_| pfad.into()),
        None => return Vorgefunden::Fremd,
    };
    if seine != unsere {
        return Vorgefunden::Fremd;
    }
    let pid = match tor.prozessnummer() {
        Some(pid) => pid,
        None => return Vorgefunden::Fremd,
    };
    match elternprozess(pid).map(|eltern| ist_dienst(&prozessname(eltern))) {
        // Elternprozess ist ein laufender Dienst: ihm gehoert es.
        Some(true) => Vorgefunden::Lebendig,
        // Elternprozess ist init, ein Subreaper (systemd --user) oder sonst
        // etwas: der Dienst, der es startete, ist weg.
        Some(false) => Vorgefunden::Waise,
        // /proc gibt nichts her: dann lieber nicht toeten, was wir nicht
        // beurteilen koennen.
        None => Vorgefunden::Fremd,
    }
}

/// Ob ein Prozessname (aus /proc/<pid>/comm, auf 15 Zeichen gekuerzt)
/// einer unserer Dienste ist: /usr/bin/harbour-briar-briard auf Sailfish,
/// /opt/briar/bin/briard auf Harmattan.
pub fn ist_dienst(name: &str) -> bool {
    name == "briard" || name.starts_with("harbour-briar-b")
}

/// Der Elternprozess laut /proc/<pid>/stat -- das vierte Feld, hinter dem
/// eingeklammerten Namen, der selbst Leerzeichen enthalten darf.
pub fn elternprozess(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Der Name aus /proc/<pid>/comm; leer, wenn es den Prozess nicht gibt.
pub fn prozessname(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Wartet, bis auf dem Port niemand mehr antwortet -- nach dem Beenden einer
/// Waise, bevor das eigene Tor denselben Port nimmt. Ohne das scheiterte der
/// neue Start am noch belegten Steuerport, und der Aufseher braeuchte einen
/// zweiten Anlauf.
fn warten_bis_frei(port: u16) -> bool {
    for _ in 0..40 {
        if TcpStream::connect(("127.0.0.1", port)).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Where a Tor shipped with this port would be. Neither device can install
/// one from a repository, so the package brings its own. BRIAR_TOR in der
/// Umgebung geht vor -- fuer den Pruefstand auf dem Baurechner, wo keines
/// dieser Verzeichnisse existiert (tools/tor-e2e.sh).
const BUNDLED: [&str; 3] = [
    "/usr/bin/harbour-briar-tor",
    "/opt/briar/bin/tor",
    "/usr/bin/tor",
];

fn tor_binary() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("BRIAR_TOR") {
        let p = std::path::PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    BUNDLED
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
}

/// Starts the bundled Tor if none is running, and waits for its control
/// port. Returns the connection, or None when there is no Tor at all.
pub fn connect_or_start(data_dir: &Path) -> Option<Tor> {
    let tor_dir = data_dir.join("tor");
    if std::fs::create_dir_all(&tor_dir).is_err() {
        return None;
    }
    // Tor insists on a private data directory.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tor_dir, std::fs::Permissions::from_mode(0o700));
    }
    // Die torrc VOR dem Umsehen schreiben: `einordnen` vergleicht dagegen,
    // und nach "Konto loeschen" (raeumt tor/ weg) stuende sonst eine Waise
    // ohne Datei da, die als fremd durchginge und bis zum Neustart des
    // Geraets weiterliefe. Der Inhalt haengt nur an Ports und Verzeichnis;
    // ein laufendes Tor liest die Datei nicht noch einmal.
    let (control_port, socks_port) = eigener();
    let torrc = tor_dir.join("torrc");
    let _ = std::fs::write(&torrc, torrc_text(socks_port, control_port, &tor_dir));
    if let Ok(mut tor) = connect_to(control_port, socks_port, Some(&tor_dir)) {
        match einordnen(&mut tor, &tor_dir) {
            Vorgefunden::Waise => {
                // Nicht weiterbetreiben: es ist das alte Programm mit der
                // alten torrc (der laufende Prozess behaelt seine Datei, auch
                // wenn das Paket sie ersetzt hat), also ohne den Bau-Patch,
                // ohne Cookie und ohne Notbremse. Beenden und frisch starten.
                crate::net::log("Tor: ein zurueckgelassenes Tor gefunden -- wird beendet und neu gestartet");
                if !tor.beenden() {
                    crate::net::log("Tor: die Waise nahm TAKEOWNERSHIP nicht an");
                }
                if !warten_bis_frei(control_port) {
                    crate::net::log("Tor: die Waise gibt den Steuerport nicht frei");
                    return None;
                }
            }
            Vorgefunden::Lebendig | Vorgefunden::Fremd if !tor.vertraut => {
                // Ohne Cookie angemeldet: ein altes Tor (bis 0.38.0) oder
                // eines, das jemand ohne Geheimnis auf unseren Port gelegt
                // hat. Kein Dienst wird darauf angemeldet -- lieber gar kein
                // Tor als unser Onion-Schluessel bei einem Fremden.
                crate::net::log(&format!(
                    "Tor auf Port {} verlangt kein Cookie und gehoert nicht uns -- nicht benutzt",
                    control_port
                ));
                return None;
            }
            Vorgefunden::Lebendig => {
                crate::net::log("Tor: ein anderer Dienst haelt das Tor auf unserem Port -- nur mitbenutzt");
                return Some(tor);
            }
            Vorgefunden::Fremd => {
                crate::net::log(&format!(
                    "Tor auf Port {} ist nicht unseres -- nur mitbenutzt",
                    control_port
                ));
                return Some(tor);
            }
        }
    }
    let binary = tor_binary()?;
    // Wird die Platte knapp, scheitert spaeter das Neuschreiben des
    // Verzeichniscaches, und Tor haelt die Mikrodeskriptoren im Heap statt in
    // der Datei -- am N9 der Unterschied zwischen 22 und 60 MB. Gestartet
    // wird trotzdem; wer hier riegelte, sperrte Tor am N9 dauerhaft aus.
    if let Some(mb) = freier_platz_mb(&tor_dir) {
        if mb < PLATZ_WARNUNG_MB {
            crate::net::log(&format!(
                "Tor: nur {} MB frei unter {} -- der Verzeichniscache braucht rund 40 MB \
                 und beim Neuschreiben kurz das Doppelte",
                mb,
                tor_dir.display()
            ));
        }
    }
    // Ein altes Cookie weg, bevor Tor das neue schreibt -- sonst laese die
    // Warteschleife unten womoeglich das veraltete (Briar tut dasselbe).
    let _ = std::fs::remove_file(cookie_pfad(&tor_dir));
    let log = std::fs::File::create(tor_dir.join("tor.log")).ok()?;
    let errors = log.try_clone().ok()?;
    let mut child = std::process::Command::new(&binary)
        .arg("-f")
        .arg(&torrc)
        .arg(EIGENTUEMER)
        .arg(std::process::id().to_string())
        .stdout(log)
        .stderr(errors)
        .spawn()
        .ok()?;
    // Bootstrapping takes a while on these radios; the control port itself
    // comes up long before that.
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(1));
        // Anmelden mit dem Cookie, das Tor beim Oeffnen des Steuerports
        // schreibt; solange es fehlt, scheitert der Versuch und die Schleife
        // kommt wieder.
        if let Ok(mut tor) = connect_to(control_port, socks_port, Some(&tor_dir)) {
            // Ist das auch unser Kind? Tor oeffnet seine Ports, bevor es das
            // Datenverzeichnis sperrt: war der Steuerport schon belegt, ist
            // unser Kind laengst wieder gestorben, und hier antwortet das Tor
            // eines anderen -- das darf nicht unseres werden.
            if !tor.vertraut || tor.prozessnummer() != Some(child.id()) {
                crate::net::log(&format!(
                    "Tor auf Port {} ist nicht das gestartete Kind -- {}",
                    control_port,
                    if tor.vertraut { "nur mitbenutzt" } else { "ohne Cookie, nicht benutzt" }
                ));
                let _ = child.kill();
                let _ = child.wait();
                return if tor.vertraut { Some(tor) } else { None };
            }
            tor.child = Some(child);
            // Our Tor, so it may die with us: after TAKEOWNERSHIP it shuts
            // itself down when this control connection closes. That covers
            // the case where the daemon is killed and Drop never runs.
            if let Err(e) = tor.uebernehmen() {
                crate::net::log(&format!("Tor: TAKEOWNERSHIP abgelehnt: {}", e));
            }
            return Some(tor);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// Oeffnet den Steuerport und meldet sich an -- erst per SAFECOOKIE mit
/// unserem Cookie, dann, auf einer neuen Verbindung (Tor schliesst nach
/// einem Fehlversuch), ohne. Das Ergebnis sagt, welcher Weg es war.
///
/// SAFECOOKIE statt COOKIE, weil COOKIE nur uns ausweist: wir schickten das
/// Cookie, und jeder, der "250" sagt, galt als Tor. Bei SAFECOOKIE beweist
/// Tor zuerst mit einem HMAC ueber Cookie und beide Zufallswerte, dass es
/// das Cookie kennt; erst dann beweisen wir dasselbe. Das Cookie selbst
/// geht nie ueber die Leitung. Wer unseren Port belegt, ohne die Datei
/// lesen zu koennen, bleibt damit ein Fremder (Gegenpruefung 0.39.0, B1).
///
/// Der Weg ohne Cookie bleibt nur, um ein altes Tor (CookieAuthentication 0,
/// Fassungen bis 0.38.0) einordnen und als Waise beenden zu koennen. Er
/// verraet kein Geheimnis, und eine so gewonnene Verbindung wird nie fuer
/// einen Dienst benutzt (`Tor::vertraut` ist dann false).
fn open_control(port: u16, tor_dir: Option<&Path>) -> std::io::Result<(TcpStream, bool)> {
    if let Some(cookie) = tor_dir.and_then(cookie_lesen) {
        let mut tor = verbinden(port)?;
        if safecookie(&mut tor, &cookie)? {
            return Ok((tor, true));
        }
    }
    let mut tor = verbinden(port)?;
    let (code, message) = command(&mut tor, "AUTHENTICATE \"\"\r\n")?;
    if code == 250 {
        Ok((tor, false))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Tor refused the control connection: {:?}", message),
        ))
    }
}

fn verbinden(port: u16) -> std::io::Result<TcpStream> {
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    Ok(socket)
}

/// Das Cookie unseres eigenen Tor: genau 32 Byte, atomar geschrieben. Eine
/// andere Laenge ist keine halbe Datei (das kann Tor nicht), sondern etwas
/// Fremdes -- und zaehlt nicht.
fn cookie_lesen(tor_dir: &Path) -> Option<Vec<u8>> {
    let bytes = std::fs::read(cookie_pfad(tor_dir)).ok()?;
    if bytes.len() == 32 {
        Some(bytes)
    } else {
        None
    }
}

const SAFECOOKIE_SERVER: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const SAFECOOKIE_CLIENT: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// Tors SAFECOOKIE-Verfahren (control-spec 3.24): AUTHCHALLENGE mit unserem
/// Zufall, Tor antwortet mit seinem Zufall und
/// HMAC-SHA256(Serverschluessel, Cookie | unser Zufall | sein Zufall); stimmt
/// der, schicken wir HMAC-SHA256(Clientschluessel, dasselbe). Gibt Ok(false)
/// zurueck, wenn Tor sich nicht ausweisen kann oder uns nicht nimmt -- die
/// Verbindung ist dann verbraucht.
fn safecookie(tor: &mut TcpStream, cookie: &[u8]) -> std::io::Result<bool> {
    let unser_zufall = crate::util::random(32);
    let (code, lines) = command(
        tor,
        &format!("AUTHCHALLENGE SAFECOOKIE {}\r\n", crate::util::to_hex(&unser_zufall)),
    )?;
    if code != 250 {
        return Ok(false);
    }
    let mut server_hash = None;
    let mut server_zufall = None;
    for zeile in &lines {
        for teil in zeile.split_whitespace() {
            if let Some(h) = teil.strip_prefix("SERVERHASH=") {
                server_hash = crate::util::from_hex(h);
            } else if let Some(n) = teil.strip_prefix("SERVERNONCE=") {
                server_zufall = crate::util::from_hex(n);
            }
        }
    }
    let (server_hash, server_zufall) = match (server_hash, server_zufall) {
        (Some(h), Some(n)) => (h, n),
        _ => return Ok(false),
    };
    let mut nachricht = Vec::with_capacity(cookie.len() + 64);
    nachricht.extend_from_slice(cookie);
    nachricht.extend_from_slice(&unser_zufall);
    nachricht.extend_from_slice(&server_zufall);
    let erwartet = hmac_sha256(SAFECOOKIE_SERVER, &nachricht);
    if !gleich_in_konstanter_zeit(&erwartet, &server_hash) {
        return Ok(false);
    }
    let antwort = hmac_sha256(SAFECOOKIE_CLIENT, &nachricht);
    let (code, _) = command(
        tor,
        &format!("AUTHENTICATE {}\r\n", crate::util::to_hex(&antwort)),
    )?;
    Ok(code == 250)
}

fn gleich_in_konstanter_zeit(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// HMAC-SHA256 nach RFC 2104, von Hand: die zwei Zeilen sind billiger als
/// eine weitere Kiste, und sha2 liegt ohnehin im Baum. Gegen RFC 4231
/// geprueft (Test unten).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
    let inner = Sha256::new().chain_update(&ipad).chain_update(message).finalize();
    let outer = Sha256::new().chain_update(&opad).chain_update(inner).finalize();
    outer.into()
}

/// Sends one command and reads the reply, following Tor's multi-line form.
fn command(control: &mut TcpStream, line: &str) -> std::io::Result<(u16, Vec<String>)> {
    control.write_all(line.as_bytes())?;
    control.flush()?;
    let mut reader = BufReader::new(control.try_clone()?);
    let mut code = 0u16;
    let mut lines = Vec::new();
    loop {
        let mut answer = String::new();
        if reader.read_line(&mut answer)? == 0 {
            break;
        }
        let answer = answer.trim_end().to_string();
        if answer.len() < 4 {
            break;
        }
        code = answer[..3].parse().unwrap_or(0);
        let separator = answer.as_bytes()[3] as char;
        lines.push(answer[4..].to_string());
        if separator == ' ' {
            break;
        }
    }
    Ok((code, lines))
}

impl Tor {
    /// Ist die Steuerverbindung noch da? Der versteckte Dienst lebt genau
    /// so lange wie sie -- reisst sie ab (Netzwechsel, Tor neu gestartet),
    /// ist unter der Onion-Adresse niemand mehr zu erreichen, ohne dass es
    /// sonst irgendwo auffiele.
    pub fn alive(&mut self) -> bool {
        match command(&mut self.control, "GETINFO version\r\n") {
            Ok((code, _)) => code == 250,
            Err(_) => false,
        }
    }

    /// Macht dieses Tor zu unserem: nach TAKEOWNERSHIP beendet es sich,
    /// sobald diese Steuerverbindung schliesst. Danach wird die
    /// Prozessueberwachung vom Start (`__OwningControllerProcess`) wieder
    /// abgestellt, wie Briar es tut -- die Verbindung reicht als Band, und
    /// Tor muss nicht mehr alle 15 s nachsehen. Auf einem Tor, das ohne die
    /// Angabe gestartet wurde, ist das RESETCONF ein Leerlauf (250 OK).
    pub fn uebernehmen(&mut self) -> std::io::Result<()> {
        let (code, lines) = command(&mut self.control, "TAKEOWNERSHIP\r\n")?;
        if code != 250 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Tor refused TAKEOWNERSHIP: {:?}", lines),
            ));
        }
        let _ = command(&mut self.control, &format!("RESETCONF {}\r\n", EIGENTUEMER));
        Ok(())
    }

    /// Welche torrc dieses Tor liest. So unterscheidet der Dienst sein
    /// eigenes, zurueckgelassenes Tor von einem fremden auf demselben Port.
    /// Tor nennt den Pfad, wie er hinter -f stand, mit dem damaligen
    /// Arbeitsverzeichnis davor -- nicht aufgeloest; das tut `einordnen`.
    pub fn konfigurationsdatei(&mut self) -> Option<String> {
        self.getinfo("config-file")
    }

    /// Die Prozessnummer dieses Tor -- so erkennt der Dienst sein eigenes
    /// Kind und den Elternprozess einer Waise.
    pub fn prozessnummer(&mut self) -> Option<u32> {
        self.getinfo("process/pid")?.parse().ok()
    }

    fn getinfo(&mut self, schluessel: &str) -> Option<String> {
        let (code, lines) =
            command(&mut self.control, &format!("GETINFO {}\r\n", schluessel)).ok()?;
        if code != 250 {
            return None;
        }
        let praefix = format!("{}=", schluessel);
        lines
            .iter()
            .find_map(|l| l.strip_prefix(praefix.as_str()).map(|s| s.to_string()))
    }

    /// Beendet ein Tor, das niemandem mehr gehoert: TAKEOWNERSHIP, dann die
    /// Verbindung schliessen -- Tor nimmt das als Verlust seines Eigentuemers
    /// und beendet sich sauber (SIGTERM an sich selbst). Gibt zurueck, ob Tor
    /// die Uebernahme angenommen hat; ohne sie bleibt es stehen.
    pub fn beenden(mut self) -> bool {
        let angenommen = command(&mut self.control, "TAKEOWNERSHIP\r\n")
            .map(|(code, _)| code == 250)
            .unwrap_or(false);
        drop(self);
        angenommen
    }

    /// Raeumt einen mit `publish` angemeldeten Dienst wieder ab.
    ///
    /// `&mut self` ist keine Foermlichkeit: einen nicht abgetrennten
    /// ADD_ONION-Dienst darf nur die Steuerverbindung loeschen, die ihn
    /// angelegt hat. Eine andere bekommt "Unknown Onion Service ID" zu
    /// hoeren, und der Dienst bliebe stehen.
    ///
    /// `Ok(false)` heisst: Tor kennt die Kennung nicht mehr -- fuer einen
    /// Abbau kein Fehler, sondern schon erledigt.
    pub fn unpublish(&mut self, service_id: &str) -> std::io::Result<bool> {
        // Tor will den nackten v3-Namen; mit ".onion" kennt es ihn nicht.
        let id = service_id.trim_end_matches(".onion");
        let (code, lines) = command(&mut self.control, &format!("DEL_ONION {}\r\n", id))?;
        match code {
            250 => Ok(true),
            // 552 "Unknown Onion Service ID"
            552 => Ok(false),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Tor kept the hidden service {}: {:?}", id, lines),
            )),
        }
    }
}

pub struct HiddenService {
    pub onion: String,
    /// The key, to be stored so the address survives a restart
    pub private_key: String,
}

impl Tor {
    /// Publishes a hidden service for our local port. With a stored key the
    /// address stays the same, which matters: contacts only have the old one.
    pub fn publish(
        &mut self,
        local_port: u16,
        private_key: Option<&str>,
    ) -> std::io::Result<HiddenService> {
        let key = match private_key {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => "NEW:ED25519-V3".to_string(),
        };
        let line = format!(
            "ADD_ONION {} Port={},127.0.0.1:{}\r\n",
            key, VIRTUAL_PORT, local_port
        );
        let (code, lines) = command(&mut self.control, &line)?;
        if code != 250 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Tor refused the hidden service: {:?}", lines),
            ));
        }
        let mut onion = String::new();
        let mut returned_key = private_key.unwrap_or("").to_string();
        for answer in lines {
            if let Some(rest) = answer.strip_prefix("ServiceID=") {
                onion = rest.to_string();
            } else if let Some(rest) = answer.strip_prefix("PrivateKey=") {
                returned_key = rest.to_string();
            }
        }
        if onion.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Tor named no hidden service",
            ));
        }
        Ok(HiddenService {
            onion,
            private_key: returned_key,
        })
    }
}

/// Dials an onion address through Tor's SOCKS port.
pub fn connect_through_socks(socks_port: u16, onion: &str) -> std::io::Result<TcpStream> {
    let host = if onion.ends_with(".onion") {
        onion.to_string()
    } else {
        format!("{}.onion", onion)
    };
    let mut socket = TcpStream::connect(("127.0.0.1", socks_port))?;
    // Reaching a hidden service takes a while: circuits, descriptor lookup,
    // rendezvous. Briar allows two minutes on top of its usual timeout.
    socket.set_read_timeout(Some(Duration::from_secs(120)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;

    // SOCKS5, no authentication
    socket.write_all(&[0x05, 0x01, 0x00])?;
    let mut answer = [0u8; 2];
    socket.read_exact(&mut answer)?;
    if answer != [0x05, 0x00] {
        return Err(bad("the SOCKS proxy wants an authentication we do not have"));
    }
    // CONNECT to a host name, so Tor resolves the onion itself
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.push((VIRTUAL_PORT >> 8) as u8);
    request.push((VIRTUAL_PORT & 0xff) as u8);
    socket.write_all(&request)?;

    let mut head = [0u8; 4];
    socket.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(bad(&format!("Tor could not connect (SOCKS error {})", head[1])));
    }
    // Skip the bound address the proxy reports back
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            socket.read_exact(&mut rest)?;
        }
        0x03 => {
            let mut length = [0u8; 1];
            socket.read_exact(&mut length)?;
            let mut rest = vec![0u8; length[0] as usize + 2];
            socket.read_exact(&mut rest)?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            socket.read_exact(&mut rest)?;
        }
        _ => return Err(bad("the SOCKS proxy answered with an unknown address type")),
    }
    Ok(socket)
}

fn bad(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, message.to_string())
}


#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231, Testfall 2.
    #[test]
    fn hmac_sha256_trifft_rfc_4231() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            crate::util::to_hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 4231, Testfall 6: Schluessel laenger als ein Block.
    #[test]
    fn hmac_sha256_mit_langem_schluessel() {
        let key = [0xaau8; 131];
        let mac = hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            crate::util::to_hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }
}
