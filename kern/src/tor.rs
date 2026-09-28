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
use std::time::Duration;

pub const VIRTUAL_PORT: u16 = 80;
const TIMEOUT: Duration = Duration::from_secs(20);
/// Briar's own Tor listens here; a system Tor uses the usual 9050/9051.
const CANDIDATES: [(u16, u16); 2] = [(9051, 9050), (59051, 59050)];
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
}

impl Drop for Tor {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
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
pub fn connect() -> Option<Tor> {
    for (control_port, socks_port) in CANDIDATES {
        if let Ok(tor) = connect_to(control_port, socks_port) {
            return Some(tor);
        }
    }
    None
}

/// Verbindet sich mit dem Tor auf dem genannten Steuerport. Getrennt von
/// `connect`, damit ein Pruefstand eine Attrappe auf einem eigenen Port
/// unterschieben kann.
pub fn connect_to(control_port: u16, socks_port: u16) -> std::io::Result<Tor> {
    let control = open_control(control_port)?;
    Ok(Tor {
        control_port,
        socks_port,
        control,
        child: None,
    })
}

/// Die torrc, die der Dienst fuer sein eigenes Tor schreibt.
///
/// Speicherseitig ist daran nichts mehr zu holen: alle Schalter zusammen
/// bringen 0 MB (gemessen 28./29.09.2026, Jolla und arch/i486). Der Heap
/// besteht aus Konsens und Mikrodeskriptoren, und den verkleinert nur der
/// Bau-Patch in tools/build-tor.sh. MaxMemInQueues ist eine Notbremse gegen
/// Lastspitzen, im Leerlauf ohne Wirkung: 64 MB ist der kleinste Wert, den
/// Tor ohne Warnung nimmt (MIN_UNWARNED_CLIENT_MB), statt der Vorgabe von
/// 768 MB, die es sich am N9 aus dem Arbeitsspeicher ableitet.
pub fn torrc_text(socks_port: u16, control_port: u16, tor_dir: &Path) -> String {
    format!(
        "SocksPort 127.0.0.1:{}\nControlPort 127.0.0.1:{}\nCookieAuthentication 0\n\
         DataDirectory {}\nAvoidDiskWrites 1\nClientOnly 1\nMaxMemInQueues 64 MB\n",
        socks_port,
        control_port,
        tor_dir.display()
    )
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
/// one from a repository, so the package brings its own.
const BUNDLED: [&str; 3] = [
    "/usr/bin/harbour-briar-tor",
    "/opt/briar/bin/tor",
    "/usr/bin/tor",
];

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
    let (control_port, socks_port) = CANDIDATES[1];
    let torrc = tor_dir.join("torrc");
    let _ = std::fs::write(&torrc, torrc_text(socks_port, control_port, &tor_dir));
    if let Some(mut tor) = connect() {
        // Der System-Tor auf 9051 bleibt, was er ist. Nur auf unserem
        // eigenen Port kann ein zurueckgelassenes Tor stehen.
        if tor.control_port != CANDIDATES[1].0 {
            return Some(tor);
        }
        match einordnen(&mut tor, &tor_dir) {
            Vorgefunden::Waise => {
                // Nicht weiterbetreiben: es ist das alte Programm mit der
                // alten torrc (der laufende Prozess behaelt seine Datei, auch
                // wenn das Paket sie ersetzt hat), also ohne den Bau-Patch
                // und ohne Notbremse. Beenden und frisch starten.
                let port = tor.control_port;
                crate::net::log("Tor: ein zurueckgelassenes Tor gefunden -- wird beendet und neu gestartet");
                if !tor.beenden() {
                    crate::net::log("Tor: die Waise nahm TAKEOWNERSHIP nicht an");
                }
                if !warten_bis_frei(port) {
                    crate::net::log("Tor: die Waise gibt den Steuerport nicht frei");
                    return None;
                }
            }
            Vorgefunden::Lebendig => {
                crate::net::log("Tor: ein anderer Dienst haelt das Tor auf unserem Port -- nur mitbenutzt");
                return Some(tor);
            }
            Vorgefunden::Fremd => {
                crate::net::log(&format!(
                    "Tor auf Port {} ist nicht unseres -- nur mitbenutzt",
                    tor.control_port
                ));
                return Some(tor);
            }
        }
    }
    let binary = BUNDLED.iter().find(|path| Path::new(path).exists())?;
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
    let log = std::fs::File::create(tor_dir.join("tor.log")).ok()?;
    let errors = log.try_clone().ok()?;
    let mut child = std::process::Command::new(binary)
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
        if let Ok(control) = open_control(control_port) {
            let mut tor = Tor {
                control_port,
                socks_port,
                control,
                child: None,
            };
            // Ist das auch unser Kind? Tor oeffnet seine Ports, bevor es das
            // Datenverzeichnis sperrt: war der Steuerport schon belegt, ist
            // unser Kind laengst wieder gestorben, und hier antwortet das Tor
            // eines anderen -- das darf nicht unseres werden.
            if tor.prozessnummer() != Some(child.id()) {
                crate::net::log(&format!(
                    "Tor auf Port {} ist nicht das gestartete Kind -- nur mitbenutzt",
                    control_port
                ));
                let _ = child.kill();
                let _ = child.wait();
                return Some(tor);
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

fn open_control(port: u16) -> std::io::Result<TcpStream> {
    let address = format!("127.0.0.1:{}", port);
    let socket = TcpStream::connect(&address)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    let mut tor = socket;
    // Cookie first, empty password second: a stock Tor uses one or the other.
    if let Some(cookie) = read_cookie() {
        let (code, _) = command(&mut tor, &format!("AUTHENTICATE {}\r\n", cookie))?;
        if code == 250 {
            return Ok(tor);
        }
    }
    let (code, message) = command(&mut tor, "AUTHENTICATE \"\"\r\n")?;
    if code == 250 {
        Ok(tor)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Tor refused the control connection: {:?}", message),
        ))
    }
}

fn read_cookie() -> Option<String> {
    for path in [
        "/var/lib/tor/control_auth_cookie",
        "/run/tor/control.authcookie",
        "/var/run/tor/control.authcookie",
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            return Some(crate::util::to_hex(&bytes));
        }
    }
    None
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
