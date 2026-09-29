//! The local HTTP interface the user interfaces talk to. Same shape as the
//! WhatsApp and Fluesterwind backends: a small JSON API, so the Silica and
//! Qt 4 front ends can both use it unchanged. Seit 0.42.0 liegt sie auf einem
//! Unix-Sockel neben der state.json (`api.sock`); TCP auf 127.0.0.1 gibt es
//! nur noch fuer Tests und den Netztest (`tcp_erlaubt`).

use crate::groups;
use crate::net::{self, Node, Shared};
use crate::store::{key_from_hex, GroupPost, OutMessage, PendingContact, PrivateGroup, Store};
use crate::transport::{BLUETOOTH_TRANSPORT_ID, LAN_TRANSPORT_ID, TOR_TRANSPORT_ID};
use crate::util::{from_hex, now_ms, to_hex};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "sfos")]
fn close_notification(key: &str) {
    crate::notify::close(key);
}

#[cfg(not(feature = "sfos"))]
fn close_notification(_key: &str) {}

/// Das Geheimnis dieser Sitzung -- die Schnittstelle gibt ohne es nichts
/// heraus und nimmt nichts an.
///
/// Sicherheitsbefund K1: 127.0.0.1:8105 war fuer jede App desselben
/// Benutzers und -- ueber fetch() -- fuer jede Webseite im Browser offen,
/// samt "Access-Control-Allow-Origin: *". Briar auf Android hat keine lokale
/// Schnittstelle; sein briar-headless verlangt je Anfrage einen Bearer-Token
/// (Router.kt). So auch hier: der Dienst wuerfelt beim Start 32 Byte, legt sie
/// als Hexzahl neben die state.json (api-token, 0600), und nur die
/// Oberflaeche liest sie dort. Was ein Prozess desselben Benutzers ohne
/// Sandkasten lesen kann, kann er weiterhin lesen -- dagegen hilft nur ein
/// Sandkasten, den es hier nicht gibt; Webseiten und andere Konten sind
/// draussen, und mit ihnen H0 (Konto loeschen ohne Pruefung) und M5 (das
/// Schluesselbund-Passwort an den, der zuerst lauscht). Seit dem Sockel
/// (0700-Ordner, 0600, SO_PEERCRED) kommt ein anderes Konto gar nicht mehr
/// heran; der Nachweis bleibt fuer den TCP-Weg der Tests.
static GEHEIMNIS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
/// Der Dateiname neben der state.json.
pub const GEHEIMNIS_DATEI: &str = "api-token";
/// Der Unix-Sockel der Schnittstelle, ebenfalls neben der state.json.
///
/// Seit 0.42.0 der Vorgabeweg statt 127.0.0.1:8105. Den TCP-Port erreichte
/// jede Webseite im Browser -- ohne Geheimnis bekam sie zwar nichts, konnte
/// aber sehen, dass dort etwas lauscht (und auf Sailfish laeuft der Browser
/// ausserhalb von firejail). Einen Sockel in einem 0700-Ordner erreicht keine
/// Webseite und kein anderes Konto; SO_PEERCRED prueft es beim Annehmen
/// noch einmal.
pub const SOCKEL_DATEI: &str = "api.sock";
/// Hoechstens so viel Rumpf nimmt eine Anfrage an (Sicherheitsbefund H2: ein
/// erfundener Content-Length von 4 GB war eine Zuteilung, die auf einem
/// 1-GB-Geraet den Dienst beendete).
const MAX_RUMPF: usize = 1024 * 1024;
/// ... und so viel Kopf, Anfragezeile eingeschlossen.
const MAX_KOPF: u64 = 64 * 1024;

/// Das Geheimnis erzeugen (einmal je Prozess) und neben die state.json legen.
/// Mehrmals aufrufbar: die Datei wird jedes Mal geschrieben, das Geheimnis
/// bleibt -- so findet jede Pruefung in ihrem Verzeichnis eines.
pub fn geheimnis_anlegen(state_path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let wert = GEHEIMNIS.get_or_init(|| to_hex(&crate::util::random(32)));
    let dir = state_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let pfad = dir.join(GEHEIMNIS_DATEI);
    // Erst weg damit, dann neu und ausschliesslich anlegen, mit 0600 und
    // ohne einem Link zu folgen. Entfernen darf der Benutzer im eigenen
    // Verzeichnis auch eine Datei, die root gehoert (etwa nach einem Start
    // per devel-su); create_new + O_NOFOLLOW verhindern, dass ein gelegter
    // Link auf eine fremde Datei zeigt und die ueberschrieben wird.
    let _ = std::fs::remove_file(&pfad);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&pfad)?;
    f.write_all(wert.as_bytes())?;
    f.flush()
}

/// Das Geheimnis dieser Sitzung -- leer, solange keines angelegt ist; dann
/// ist niemand berechtigt.
pub fn geheimnis() -> &'static str {
    GEHEIMNIS.get().map(|s| s.as_str()).unwrap_or("")
}

/// Der Nachweis, dass WIR das Geheimnis kennen: SHA-256 darueber, als
/// Hexzahl. Steht in jeder Antwort ohne Geheimnis auf /status.
///
/// Wozu: die Oberflaeche schickt Geheimnis und -- beim Aufsperren -- das
/// Passwort aus dem Schluesselbund an den, der auf dem Port antwortet. Ohne
/// Nachweis waere das jeder Prozess, der den Port zuerst bindet, auch einer
/// eines anderen Kontos (Gegenpruefung 6, A1; Sicherheitsbefund M5). Die
/// Oberflaeche liest das Geheimnis aus der Datei, rechnet denselben Hash
/// und gibt das Geheimnis nur an einen Dienst heraus, dessen Nachweis passt.
/// Wer die Datei nicht lesen kann, kann den Nachweis nicht faelschen; wer
/// sie lesen kann, braucht ihn nicht.
pub fn nachweis() -> String {
    use sha2::{Digest, Sha256};
    let g = geheimnis();
    if g.is_empty() {
        return String::new();
    }
    to_hex(&Sha256::digest(g.as_bytes()))
}

/// Die Kopfzeilen einer Anfrage, soweit sie hier zaehlen.
pub struct Koepfe {
    pub laenge: usize,
    pub geheimnis: Option<String>,
    pub host: Option<String>,
}

/// Kopfzeilen lesen -- begrenzt: eine Gegenseite, die nie einen Zeilenumbruch
/// schickt, darf den Speicher nicht fuellen.
pub fn koepfe_lesen(leser: &mut impl BufRead) -> std::io::Result<Koepfe> {
    let mut k = Koepfe {
        laenge: 0,
        geheimnis: None,
        host: None,
    };
    let mut gelesen = 0u64;
    loop {
        let mut zeile = String::new();
        // Je Zeile hoechstens 8 KiB, insgesamt hoechstens MAX_KOPF -- beides
        // beim Lesen, nicht hinterher.
        let n = (&mut *leser).take(8192 + 1).read_line(&mut zeile)?;
        gelesen += n as u64;
        if n == 0 || zeile.trim().is_empty() {
            break;
        }
        if n > 8192 || gelesen > MAX_KOPF {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too long",
            ));
        }
        let Some((name, wert)) = zeile.split_once(':') else {
            continue;
        };
        let wert = wert.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => k.laenge = wert.parse().unwrap_or(0),
            // Zwei Schreibweisen, weil Qt 4.7 nicht jeden Kopf durchlaesst.
            "authorization" => {
                if let Some(t) = wert.strip_prefix("Bearer ") {
                    k.geheimnis = Some(t.trim().to_string());
                }
            }
            "x-briar-geheimnis" => k.geheimnis = Some(wert.to_string()),
            "host" => k.host = Some(wert.to_string()),
            _ => {}
        }
    }
    Ok(k)
}

/// Traegt die Anfrage das Geheimnis? Vergleich in konstanter Zeit.
pub fn berechtigt(koepfe: &Koepfe) -> bool {
    let g = geheimnis();
    if g.is_empty() {
        return false;
    }
    match &koepfe.geheimnis {
        Some(t) => crate::tor::gleich_in_konstanter_zeit(t.as_bytes(), g.as_bytes()),
        None => false,
    }
}

/// Der Host-Kopf: fehlt er, ist das ein Werkzeug mit HTTP/1.0 (die App selbst
/// fragt so nach der Fassung); steht er da, muss er auf uns zeigen. Ein
/// fremder Name ist DNS-Rebinding -- eine Webseite, deren Name gerade auf
/// 127.0.0.1 aufgeloest wird.
pub fn host_passt(host: Option<&str>) -> bool {
    let Some(h) = host else {
        return true;
    };
    let ohne_port = match h.rsplit_once(':') {
        Some((a, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => a,
        _ => h,
    };
    matches!(ohne_port, "127.0.0.1" | "localhost" | "[::1]")
}

/// Wo der Sockel liegt, wenn niemand etwas anderes sagt: neben der
/// state.json, wie das Geheimnis.
pub fn sockel_pfad(state_path: &Path) -> PathBuf {
    state_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(SOCKEL_DATEI)
}

/// Eine angenommene Verbindung, gleich auf welchem Weg. `serve` und der
/// Wartedienst lesen und schreiben nur ueber Read/Write und kennen den
/// Unterschied nicht.
pub enum Strom {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Strom {
    pub fn try_clone(&self) -> std::io::Result<Strom> {
        Ok(match self {
            Strom::Tcp(s) => Strom::Tcp(s.try_clone()?),
            Strom::Unix(s) => Strom::Unix(s.try_clone()?),
        })
    }

    /// Lesen und Schreiben begrenzt -- auf beiden Wegen gleich.
    pub fn zeitgrenzen(&self, dauer: std::time::Duration) {
        match self {
            Strom::Tcp(s) => {
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(dauer));
                let _ = s.set_write_timeout(Some(dauer));
            }
            Strom::Unix(s) => {
                let _ = s.set_nonblocking(false);
                let _ = s.set_read_timeout(Some(dauer));
                let _ = s.set_write_timeout(Some(dauer));
            }
        }
    }
}

impl Read for Strom {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Strom::Tcp(s) => s.read(buf),
            Strom::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Strom {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Strom::Tcp(s) => s.write(buf),
            Strom::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Strom::Tcp(s) => s.flush(),
            Strom::Unix(s) => s.flush(),
        }
    }
}

/// Wer auf der anderen Seite des Sockels sitzt (SO_PEERCRED): die UID des
/// verbindenden Prozesses, wie der Kern sie beim connect festgehalten hat.
pub fn gegenueber_uid(strom: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut laenge = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // Sicher: cred und laenge leben ueber den Aufruf, die Laenge stimmt.
    let r = unsafe {
        libc::getsockopt(
            strom.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut laenge,
        )
    };
    if r != 0 || laenge as usize != std::mem::size_of::<libc::ucred>() {
        return None;
    }
    Some(cred.uid)
}

/// Ob der Dienst zusaetzlich auf TCP lauscht: nur mit `--api-port` UND der
/// Umgebungsvariable `BRIAR_API_TCP=1`.
///
/// Eine Oberflaeche bis 0.41.0 startet den Dienst noch mit
/// `--api-port 8105`. Laeuft gerade keiner (nach `%post`), kaeme so ein
/// neuer Dienst mit offenem Port 8105 hoch und behielte ihn bis zum naechsten
/// Neustart -- sichtbar fuer jede Webseite (Gegenpruefung 7b, A1). Ohne die
/// Variable bleibt es beim Sockel; Tests und Netztest setzen sie.
pub fn tcp_erlaubt(port: Option<u16>, schalter: Option<&std::ffi::OsStr>) -> Option<u16> {
    port.filter(|_| schalter.is_some_and(|v| v == "1"))
}

/// Hoechstens eine Zeile je Minute fuer abgewiesene Verbindungen: gelingt
/// das Abschliessen des Ordners nicht, koennte ein Zugriffsberechtigter sonst
/// das Protokoll damit fluten (7b, H).
static ABGEWIESEN_GEMELDET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Ist eine gedrosselte Zeile jetzt faellig? `zuletzt` haelt die Zeit der
/// letzten, in Millisekunden; `jetzt` kommt von aussen, damit es pruefbar ist.
pub fn drossel_faellig(zuletzt: &std::sync::atomic::AtomicU64, jetzt: u64) -> bool {
    use std::sync::atomic::Ordering;
    let alt = zuletzt.load(Ordering::Relaxed);
    if alt != 0 && jetzt.saturating_sub(alt) < 60_000 {
        return false;
    }
    // Nur einer von mehreren gleichzeitigen Faeden schreibt.
    zuletzt
        .compare_exchange(alt, jetzt.max(1), Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

/// Ein Lauscher der Schnittstelle: der Sockel immer, der TCP-Port nur mit
/// --api-port und BRIAR_API_TCP=1 (Tests, Netztest; `tcp_erlaubt`).
pub enum Lauscher {
    Unix(UnixListener),
    Tcp(TcpListener),
}

impl Lauscher {
    /// Den Sockel anlegen: ein alter von einem beendeten Dienst wird vorher
    /// entfernt, danach bekommt die Datei 0600. Der Ordner ist dann schon
    /// 0700, also kommt in der kurzen Zeit dazwischen ohnehin kein Fremder
    /// heran.
    ///
    /// Ob der alte Sockel wirklich tot ist, sagt die Instanzsperre nicht
    /// immer: laesst sich die Sperrdatei nicht oeffnen oder sperren, laeuft
    /// der Dienst "unlocked" weiter, und ein zweiter nahm dem ersten frueher
    /// still den Sockel weg (7b, A2). Darum vorher anklopfen: antwortet
    /// jemand, ist dort ein lebender Dienst, und die Antwort ist `AddrInUse`
    /// -- main.rs beendet sich dann. Ein toter Sockel lehnt ab
    /// (ECONNREFUSED) und wird ersetzt.
    pub fn unix(pfad: &Path) -> std::io::Result<Lauscher> {
        use std::os::unix::fs::PermissionsExt;
        if UnixStream::connect(pfad).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "another briard answers on the API socket",
            ));
        }
        let _ = std::fs::remove_file(pfad);
        let l = UnixListener::bind(pfad)?;
        std::fs::set_permissions(pfad, std::fs::Permissions::from_mode(0o600))?;
        Ok(Lauscher::Unix(l))
    }

    pub fn tcp(port: u16) -> std::io::Result<Lauscher> {
        Ok(Lauscher::Tcp(TcpListener::bind(("127.0.0.1", port))?))
    }

    pub fn set_nonblocking(&self, an: bool) -> std::io::Result<()> {
        match self {
            Lauscher::Unix(l) => l.set_nonblocking(an),
            Lauscher::Tcp(l) => l.set_nonblocking(an),
        }
    }

    /// Eine Verbindung annehmen. `Ok(None)`: sie kam von einem anderen
    /// Benutzer und ist schon wieder zu.
    pub fn annehmen(&self) -> std::io::Result<Option<Strom>> {
        match self {
            Lauscher::Tcp(l) => Ok(Some(Strom::Tcp(l.accept()?.0))),
            Lauscher::Unix(l) => {
                let (s, _) = l.accept()?;
                // Sicher: getuid kann nicht scheitern.
                let ich = unsafe { libc::getuid() };
                match gegenueber_uid(&s) {
                    Some(uid) if uid == ich => Ok(Some(Strom::Unix(s))),
                    uid => {
                        if drossel_faellig(&ABGEWIESEN_GEMELDET, now_ms()) {
                            net::log(&format!(
                                "API: refused a connection on the socket from uid {:?} (logged once a minute)",
                                uid
                            ));
                        }
                        Ok(None)
                    }
                }
            }
        }
    }

    fn beschreibung(&self) -> String {
        match self {
            Lauscher::Unix(_) => format!("the socket {}", SOCKEL_DATEI),
            Lauscher::Tcp(l) => match l.local_addr() {
                Ok(a) => a.to_string(),
                Err(_) => "TCP".to_string(),
            },
        }
    }
}

/// Den Ordner der state.json abschliessen (0700) und die Lauscher oeffnen:
/// den Sockel, und den TCP-Port nur, wenn einer genannt ist.
///
/// Einmal in main.rs, vor dem Wartedienst: der reicht sie danach an `run`
/// weiter, so dass zwischen Entsperren und grossem Dienst niemand vor einer
/// geschlossenen Tuer steht.
pub fn lauscher_oeffnen(
    state_path: &Path,
    sockel: &Path,
    port: Option<u16>,
) -> std::io::Result<Vec<Lauscher>> {
    use std::os::unix::fs::PermissionsExt;
    let ordner = state_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(ordner)?;
    // Nur wenn noetig, und nur einen eigenen Ordner ohne Sticky-Bit: liegt
    // die state.json mit --state direkt in /tmp, soll /tmp nicht 0700 werden
    // (als root ginge das). Scheitert chmod, ist das eine Protokollzeile
    // wert, aber kein Grund, nicht zu starten -- SO_PEERCRED haelt Fremde
    // trotzdem draussen.
    if let Ok(m) = std::fs::metadata(ordner) {
        use std::os::unix::fs::MetadataExt;
        // Sicher: getuid kann nicht scheitern.
        let eigener = m.uid() == unsafe { libc::getuid() };
        let modus = m.permissions().mode();
        if eigener && modus & 0o1000 == 0 && modus & 0o777 != 0o700 {
            if let Err(e) = std::fs::set_permissions(ordner, std::fs::Permissions::from_mode(0o700)) {
                net::log(&format!("cannot make the state directory private: {}", e));
            }
        }
    }
    let mut lauscher = vec![Lauscher::unix(sockel)?];
    if let Some(port) = port {
        lauscher.push(Lauscher::tcp(port)?);
    }
    Ok(lauscher)
}

fn antworten(mut socket: Strom, code: u16, wert: &Value) -> std::io::Result<()> {
    let text = serde_json::to_string(wert).unwrap_or_else(|_| "{}".to_string());
    let grund = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        _ => "Error",
    };
    // Kein Access-Control-Allow-Origin mehr: eine Webseite bekommt die
    // Antwort nicht zu lesen -- und ohne Geheimnis ohnehin keine.
    write!(
        socket,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        grund,
        text.as_bytes().len(),
        text
    )?;
    socket.flush()
}

/// Die Schnittstelle bedienen, auf allen Lauschern, je einer im eigenen
/// Faden. Kehrt nicht zurueck.
pub fn run(store: Shared, lauscher: Vec<Lauscher>) {
    let mut faeden = Vec::new();
    for l in lauscher {
        // Kam er vom Wartedienst, steht er noch auf nicht blockierend.
        let _ = l.set_nonblocking(false);
        net::log(&format!("API on {}", l.beschreibung()));
        let store = Arc::clone(&store);
        faeden.push(std::thread::spawn(move || loop {
            match l.annehmen() {
                Ok(Some(socket)) => {
                    let store = Arc::clone(&store);
                    std::thread::spawn(move || {
                        if let Err(e) = serve(store, socket) {
                            net::log(&format!("API request failed: {}", e));
                        }
                    });
                }
                Ok(None) => {}
                Err(e) => {
                    net::log(&format!("API accept failed: {}", e));
                    // Nicht im Kreis drehen, wenn etwas dauerhaft klemmt
                    // (keine Deskriptoren mehr frei).
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }));
    }
    for f in faeden {
        let _ = f.join();
    }
}

fn serve(store: Shared, socket: Strom) -> std::io::Result<()> {
    // Alles zusammen begrenzt, Kopf wie Rumpf: mehr liest der Dienst nicht.
    // Und nicht ewig: eine Gegenseite, die troepfelt, bindet sonst einen
    // Faden je Verbindung, beliebig viele.
    socket.zeitgrenzen(std::time::Duration::from_secs(30));
    let mut reader = BufReader::new(socket.try_clone()?).take(MAX_KOPF + MAX_RUMPF as u64);
    let mut request_line = String::new();
    // Die Anfragezeile hoechstens 8 KiB, gelesen mit genau dieser Grenze --
    // nicht erst hinterher gemessen.
    (&mut reader).take(8192 + 1).read_line(&mut request_line)?;
    if request_line.len() > 8192 {
        return antworten(socket, 414, &json!({"error": "request line too long"}));
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let koepfe = koepfe_lesen(&mut reader)?;
    if !host_passt(koepfe.host.as_deref()) {
        return antworten(socket, 400, &json!({"error": "wrong host"}));
    }
    if koepfe.laenge > MAX_RUMPF {
        return antworten(socket, 413, &json!({"error": "request too large"}));
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    if !berechtigt(&koepfe) {
        // Ohne Geheimnis nur, was die App zum Anlaufen braucht: laeuft der
        // Dienst, gesperrt oder nicht, und der Nachweis, dass wir das
        // Geheimnis kennen. Als 401, nicht als 200 -- die Oberflaeche liest
        // bei 401 ihr Geheimnis neu und fragt noch einmal. Der Rumpf wird
        // gar nicht erst gelesen.
        //
        // KEINE Fassung hier. Die Fassungsabfrage der App fragt seit 0.41.0
        // mit Geheimnis; eine aeltere Oberflaeche (bis 0.40.0) fragt ohne,
        // laese hier eine fremde Fassung, hielte den Dienst fuer veraltet
        // und beendete ihn -- alle drei Sekunden, bis sie geschlossen wird
        // (Gegenpruefung 6, A2). Ohne Fassung laesst sie ihn stehen.
        let mut antwort = json!({"error": "unauthorised"});
        if method == "GET" && path == "/status" {
            antwort["running"] = json!(true);
            antwort["locked"] = json!(ist_gesperrt());
            antwort["nachweis"] = json!(nachweis());
        }
        return antworten(socket, 401, &antwort);
    }
    let mut raw = vec![0u8; koepfe.laenge];
    if koepfe.laenge > 0 {
        reader.read_exact(&mut raw)?;
    }
    let body: Value = if raw.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&raw).unwrap_or_else(|_| json!({}))
    };
    let response = handle(store, &method, &path, &query, &body);
    antworten(socket, 200, &response)
}

/// Eine gewoehnliche Datei bis `capacity` Byte lesen; groessere liefern ihre
/// Laenge zurueck, damit die Meldung stimmt, ohne dass alles im Speicher
/// landet. Kein FIFO, kein Geraet: `is_file` sagt es vorher.
fn datei_lesen_begrenzt(path: &str, capacity: usize) -> std::io::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut data = Vec::new();
    std::fs::File::open(path)?
        .take(capacity as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > capacity {
        // Die echte Groesse fuer die Meldung, ohne sie zu lesen.
        data.resize(meta.len() as usize, 0);
    }
    Ok(data)
}

fn query_value(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn spawn_poll(store: &Shared) {
    let store = Arc::clone(store);
    std::thread::spawn(move || {
        let node = Node::new(store);
        node.poll();
    });
}

/// Die Oberflaeche ist zugesperrt. Das ist Briars Bildschirmsperre, nicht das
/// Siegel des Speichers: der Schluessel bleibt im Dienst, der Abgleich laeuft
/// weiter und Nachrichten kommen an -- nur herzeigen tut die App nichts mehr,
/// bis das Passwort wieder da ist. Genau so haelt es Briar (pref_key_lock).
///
/// Absichtlich nicht gespeichert: nach einem Neustart des Dienstes ist der
/// Speicher ohnehin versiegelt, und dann fragt entsperren.rs.
static GESPERRT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Die Marke, mit der die Oberflaeche wieder aufsperren darf, ohne das
/// Passwort zu kennen.
///
/// Gedacht fuer den Fingerabdruck: an der Jolla sperrt Briar auf Android mit
/// dem Bildschirmschloss des Telefons auf, nicht mit dem Briar-Passwort. Das
/// geht hier auch (org.nemomobile.devicelock), nur weiss der Dienst nichts
/// davon, ob jemand seinen Finger aufgelegt hat -- also bekommt die App beim
/// Zusperren eine einmalige Marke, die sie nach geglueckter Pruefung
/// zurueckgibt.
///
/// Sie liegt nur im Arbeitsspeicher, gilt nur fuer dieses eine Zusperren und
/// ist nach dem Aufsperren verbraucht. Mit ihr laesst sich die Datei nicht
/// entschluesseln: sie oeffnet nur die Oberflaeche, die der Dienst ohnehin
/// schon offen haelt.
static MARKE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
/// Wann zuletzt etwas ueber die Schnittstelle kam -- fuer die Sperre nach Zeit.
static LETZTE_REGUNG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn ist_gesperrt() -> bool {
    GESPERRT.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn sperren() {
    GESPERRT.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::net::log("die Oberflaeche ist zugesperrt");
}

/// Beim Zusperren von selbst gibt es keine Marke: niemand steht davor, der sie
/// entgegennehmen koennte. Dann hilft nur das Passwort -- so wie bei Briar,
/// wo nach der Frist ebenfalls das Bildschirmschloss verlangt wird.
fn marke_verwerfen() {
    *MARKE.lock().unwrap() = None;
}

fn regung_vermerken() {
    LETZTE_REGUNG.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
}

/// Der Waechter fuer die Sperre nach Zeit. Er schaut jede halbe Minute nach;
/// genauer muss es nicht sein, und haeufiger waere auf dem N9 Strom fuer
/// nichts.
pub fn sperrwaechter(store: Shared) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let frist = {
            let locked = match store.lock() {
                Ok(l) => l,
                Err(_) => continue,
            };
            locked.state.sperre_nach_minuten
        };
        if frist == 0 || ist_gesperrt() {
            continue;
        }
        let zuletzt = LETZTE_REGUNG.load(std::sync::atomic::Ordering::Relaxed);
        if zuletzt > 0 && now_ms().saturating_sub(zuletzt) > frist * 60_000 {
            marke_verwerfen();
            sperren_und_leeren(&store);
        }
    });
}

/// Zusperren und die entschluesselten Kopien wegraeumen, unter EINEM Halten
/// des Speicherschlosses. Eine /conversation, die schon an der Sperrschranke
/// vorbei ist und auf das Schloss wartet, kommt erst danach dran -- und dann
/// gibt `anhang_pfad` nichts mehr her, weil die Sperre steht. Vorher lagen
/// Sperren und Leeren in zwei Zuegen, und eine Kopie konnte dazwischen
/// entstehen und die Sperre ueberleben (7b, C3).
fn sperren_und_leeren(store: &Shared) {
    let locked = store.lock().unwrap_or_else(|e| e.into_inner());
    sperren();
    locked.anhang_kopien_leeren();
}

/// Alles loeschen, was zu diesem Konto gehoert, und den Dienst beenden.
///
/// Beim naechsten Start findet er keine Datei und faengt bei null an -- ohne
/// Passwort, ohne Kontakte. Das ist auch der Weg heraus, wenn jemand sein
/// Passwort vergessen hat: dort gibt es sonst keinen.
pub fn konto_loeschen(pfad: &std::path::Path) {
    // Die letzte Zeile vor dem Aufraeumen, und dann die Datei loslassen:
    // danach schreibt nur noch die Standardausgabe, sonst legte die naechste
    // Zeile eines anderen Fadens das gerade geloeschte Protokoll neu an.
    crate::net::log("das Konto wird geloescht -- der Dienst beendet sich");
    crate::net::log_datei_loesen();
    konto_aufraeumen(pfad);
    // Entsiegelte Kopien im Laufzeitordner gehoeren ebenfalls zum Konto.
    // Nicht in konto_aufraeumen: dessen Test liefe sonst gegen den echten
    // Laufzeitordner des Benutzers.
    crate::store::anhang_kopien_leeren(&crate::store::anhang_laufzeit_ordner());
    // Nicht bloss den Speicher leeren: die Schluessel liegen auch im
    // Arbeitsspeicher, und der Tor-Dienst laeuft noch. Ein Ende raeumt beides.
    std::process::exit(0);
}

/// Die Dateien des Kontos entfernen: Zustand, Geheimnis und Sockel der
/// Schnittstelle, Anhaenge, Tor-Verzeichnis und das Protokoll samt umgehaengter Fassung --
/// auch das Protokoll nennt Kontakte (Nummern, Zeiten), und nach dem
/// Loeschen soll nichts mehr verraten, dass es ein Konto gab.
pub fn konto_aufraeumen(pfad: &std::path::Path) {
    let _ = std::fs::remove_file(pfad);
    // Ein halb geschriebener Zustand (Store::save schreibt erst dorthin).
    let _ = std::fs::remove_file(pfad.with_extension("tmp"));
    let (log, log_alt) = crate::net::log_pfade(pfad);
    let _ = std::fs::remove_file(log);
    let _ = std::fs::remove_file(log_alt);
    if let Some(ordner) = pfad.parent() {
        let _ = std::fs::remove_file(ordner.join(GEHEIMNIS_DATEI));
        let _ = std::fs::remove_file(ordner.join(SOCKEL_DATEI));
        let _ = std::fs::remove_dir_all(ordner.join("attachments"));
        let _ = std::fs::remove_dir_all(ordner.join("tor"));
    }
}

fn handle(store: Shared, method: &str, path: &str, query: &str, body: &Value) -> Value {
    regung_vermerken();
    // Solange zugesperrt ist, geht nur das Noetigste: nachsehen, aufsperren,
    // und das Konto loeschen (fuer den Fall eines vergessenen Passworts).
    if ist_gesperrt()
        && !matches!(
            (method, path),
            ("GET", "/status") | ("POST", "/unlock") | ("POST", "/account/delete")
        )
    {
        return json!({"error": "gesperrt", "locked": true});
    }
    match (method, path) {
        ("GET", "/status") => status(&store),

        // Zusperren wie Briars Bildschirmsperre: der Abgleich laeuft weiter,
        // die Oberflaeche zeigt nichts mehr.
        ("POST", "/lock") => {
            let verschluesselt = store.lock().unwrap().verschluesselt();
            if !verschluesselt {
                // Ohne Passwort waere die Sperre eine Tuer ohne Schloss: jeder
                // Aufruf von /unlock ohne Passwort wuerde sie oeffnen.
                return json!({"error": "set a password first"});
            }
            // Die entschluesselten Kopien der Anhaenge gehen mit: hinter der
            // Sperre soll nichts lesbar herumliegen.
            sperren_und_leeren(&store);
            let marke = to_hex(&crate::util::random(16));
            *MARKE.lock().unwrap() = Some(marke.clone());
            json!({"ok": true, "locked": true, "token": marke})
        }

        // Aufsperren, wenn nur die Oberflaeche zu ist. Ist der Speicher selbst
        // versiegelt, laeuft dieser Dienst gar nicht -- dann antwortet
        // entsperren.rs auf denselben Weg.
        ("POST", "/unlock") => {
            // Zwei Wege herein: das Passwort, oder die Marke vom Zusperren --
            // die gibt die Oberflaeche erst zurueck, wenn das Telefon selbst
            // den Benutzer erkannt hat (Fingerabdruck oder Gerätecode).
            let marke = body["token"].as_str().unwrap_or("");
            let stimmt = if !marke.is_empty() {
                let mut gemerkt = MARKE.lock().unwrap();
                let passt = gemerkt.as_deref() == Some(marke) && !marke.is_empty();
                if passt {
                    // Einmalig: verbraucht ist verbraucht.
                    *gemerkt = None;
                }
                passt
            } else {
                let passwort = body["password"].as_str().unwrap_or("");
                let locked = store.lock().unwrap();
                locked.passwort_stimmt(passwort)
            };
            if !stimmt {
                return json!({"error": "falsches Passwort"});
            }
            GESPERRT.store(false, std::sync::atomic::Ordering::Relaxed);
            regung_vermerken();
            crate::net::log("aufgesperrt");
            json!({"ok": true, "locked": false})
        }

        // Wie lange ohne Regung, bis von selbst zugesperrt wird. 0 heisst nie.
        ("POST", "/lockafter") => {
            let minuten = body["minutes"].as_u64().unwrap_or(0);
            let mut locked = store.lock().unwrap();
            locked.state.sperre_nach_minuten = minuten;
            let _ = locked.save();
            json!({"ok": true, "minutes": minuten})
        }

        // Nachrichten loeschen -- eine einzelne oder das ganze Gespraech.
        // Rein oertlich: die Gegenseite behaelt ihre Kopie, wie bei Briar
        // ("delete messages" loescht nur hier). Der Anhang geht mit, sonst
        // bliebe das Bild auf der Platte, das man gerade weghaben wollte.
        ("POST", "/message/delete") => {
            let contact_id = body["contact"].as_u64().unwrap_or(0) as u32;
            let alle = body["all"].as_bool().unwrap_or(false);
            let kennung = body["id"].as_str().unwrap_or("").to_string();
            // Mehrere auf einmal, wie Briars Auswahlmodus: eine Liste von
            // Kennungen. Einzeln geht weiter ueber "id".
            let liste: std::collections::BTreeSet<String> = body["ids"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let mut locked = store.lock().unwrap();
            // Je Nachricht ihre Kennung und ALLE ihre Anhaenge -- bis 0.29.2
            // blieb alles ausser dem ersten als verwaiste Datei liegen.
            let betroffen: Vec<(String, Vec<String>)> = match locked.contact(contact_id) {
                Some(c) => c
                    .messages
                    .iter()
                    .filter(|m| alle || m.id == kennung || liste.contains(&m.id))
                    .map(|m| {
                        let mut anhaenge: Vec<String> =
                            m.anhaenge.iter().map(|k| k.id.clone()).collect();
                        if anhaenge.is_empty() {
                            if let Some(a) = &m.attachment {
                                anhaenge.push(a.clone());
                            }
                        }
                        (m.id.clone(), anhaenge)
                    })
                    .collect(),
                None => return json!({"error": "no such contact"}),
            };
            if betroffen.is_empty() {
                return json!({"error": "no such message"});
            }
            let ids: std::collections::BTreeSet<String> =
                betroffen.iter().map(|(id, _)| id.clone()).collect();
            // Im Korb liegen die Anhaenge als eigene Nachrichten -- unter ihrer
            // eigenen Kennung, nicht unter der des Textes.
            let im_korb: std::collections::BTreeSet<String> = betroffen
                .iter()
                .flat_map(|(id, anhaenge)| {
                    std::iter::once(id.clone()).chain(anhaenge.iter().cloned())
                })
                .collect();
            // Erst die Anhaenge, dann die Eintraege: nach dem Streichen wuesste
            // niemand mehr, welche Datei gemeint war.
            for (_, anhaenge) in &betroffen {
                for anhang in anhaenge {
                    locked.anhang_loeschen(anhang);
                }
            }
            if let Some(c) = locked.contact_mut(contact_id) {
                c.messages.retain(|m| !ids.contains(&m.id));
                // Was noch nicht hinaus ist, geht auch nicht mehr hinaus --
                // die Datei ebensowenig wie der Text. Vorher blieb der
                // Anhang im Korb und ging beim naechsten Treffen doch hinaus,
                // als Nachricht ohne Text.
                c.outbox.retain(|m| !im_korb.contains(&m.id));
            }
            let _ = locked.save();
            json!({"ok": true, "removed": ids.len()})
        }

        // Nebeneinander hinzufuegen, wie Briar es tut (BQP).
        //
        // Zwei Schritte: erst den eigenen Code zeigen -- dabei entsteht ein
        // fluechtiges Schluesselpaar und ein Lauscher --, dann den Code der
        // Gegenseite lesen. Beide Geraete tun beides; wer zuerst durchkommt,
        // gewinnt, der andere Versuch laeuft ins Leere.
        ("POST", "/bqp/start") => {
            let node = net::Node::new(Arc::clone(&store));
            match node.bqp_start() {
                Ok(rumpf) => json!({"ok": true, "payload": to_hex(&rumpf)}),
                Err(e) => json!({"error": e.to_string()}),
            }
        }

        ("POST", "/bqp/scan") => {
            let rumpf = match from_hex(body["payload"].as_str().unwrap_or("")) {
                Some(r) => r,
                None => return json!({"error": "der Code ist nicht lesbar"}),
            };
            let node = net::Node::new(Arc::clone(&store));
            // Nebenher: das Anwaehlen kann bis zu einer Minute dauern, und die
            // Oberflaeche soll derweil weiterlaufen. Ob es geglueckt ist, sagt
            // die naechste Statusabfrage -- der Kontakt steht dann in der Liste.
            std::thread::spawn(move || match node.bqp_gelesen(rumpf) {
                Ok(id) => crate::net::log(&format!("BQP: Kontakt {} steht", id)),
                Err(e) => crate::net::log(&format!("BQP: gescheitert: {}", e)),
            });
            json!({"ok": true})
        }

        // Verschwindende Nachrichten fuer einen Kontakt einstellen. Die
        // Dauer steht in Millisekunden; 0 oder -1 schaltet sie ab. Sie geht
        // nicht als eigene Nachricht hinaus, sondern faehrt in der naechsten
        // Privatnachricht mit -- so macht es Briar auch.
        ("POST", "/autodelete") => {
            let Some(id) = body["contact"].as_u64() else {
                return json!({"error": "no contact given"});
            };
            let dauer = body["timer"].as_i64().unwrap_or(-1);
            let dauer = if dauer <= 0 {
                crate::store::kein_timer()
            } else if !(crate::store::MIN_LOESCHDAUER_MS..=crate::store::MAX_LOESCHDAUER_MS)
                .contains(&dauer)
            {
                return json!({"error": "the timer must be between a minute and a year"});
            } else {
                dauer
            };
            let mut locked = store.lock().unwrap();
            match locked.contact_mut(id as u32) {
                Some(contact) => {
                    if contact.loesch_timer != dauer {
                        // Die vorige Dauer merken, solange die Aenderung noch
                        // in keiner Nachricht draussen war -- daran entscheidet
                        // sich, wessen Aenderung gilt, wenn beide gleichzeitig
                        // umstellen.
                        contact.loesch_vorher = contact.loesch_timer;
                        contact.loesch_timer = dauer;
                    }
                    let _ = locked.save();
                    json!({"ok": true, "timer": dauer})
                }
                None => json!({"error": "no such contact"}),
            }
        }

        ("POST", "/bqp/stop") => {
            net::Node::bqp_stop();
            json!({"ok": true})
        }

        ("POST", "/account/delete") => {
            let pfad = store.lock().unwrap().path.clone();
            konto_loeschen(&pfad);
            json!({"ok": true})
        }

        // Die vier Wege der Nachrichtenbrücke (siehe unten).
        ("GET", "/chats") => {
            let locked = store.lock().unwrap();
            let mut chats: Vec<Value> = locked
                .state
                .contacts
                .iter()
                .map(|c| {
                    let last = c.messages.last();
                    json!({
                        "jid": format!("c{}", c.id),
                        "name": c.name,
                        "isGroup": false,
                        "lastMessage": last.map(|m| m.text.clone()).unwrap_or_default(),
                        "lastTime": last.map(|m| m.timestamp).unwrap_or(0),
                        "fromMe": last.map(|m| m.outgoing).unwrap_or(false),
                    })
                })
                .collect();
            for group in locked.state.groups.iter().filter(|g| g.joined) {
                let last = group.messages.iter().filter(|m| !m.join).last();
                chats.push(json!({
                    "jid": format!("g{}", group.id),
                    "name": group.name,
                    "isGroup": true,
                    "lastMessage": last.map(|m| m.text.clone()).unwrap_or_default(),
                    "lastTime": last.map(|m| m.timestamp).unwrap_or(0),
                    "fromMe": false,
                }));
            }
            Value::Array(chats)
        }

        // Dieselben Pfade wie bei den anderen Diensten: die Brücke fragt
        // /messages?jid=... und /send?to=...&text=... ab (GET), die eigene
        // Oberfläche /messages?contact=... und POST /send.
        ("GET", "/send") => {
            let to = query_value(query, "to").unwrap_or_default();
            let text = query_value(query, "text").unwrap_or_default();
            bridge_send(&store, &to, &text)
        }

        ("GET", "/events") => {
            // Lange Abfrage: kehrt zurück, sobald sich am Zustand etwas
            // getan hat -- die Brücke hängt daran statt zu pollen.
            let since = query_value(query, "since")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let mut revision = store.lock().unwrap().state.revision;
            for _ in 0..70 {
                if revision != since {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
                revision = store.lock().unwrap().state.revision;
            }
            json!({"seq": revision})
        }

        ("POST", "/identity") => {
            let name = body["name"].as_str().unwrap_or("").trim().to_string();
            // In UTF-8-Bytes, nicht in Zeichen -- Briar misst so, und ein
            // Name mit Umlauten ist sonst laenger als er aussieht.
            if name.len() > crate::sync::MAX_AUTHOR_NAME_LEN {
                return json!({"error": format!(
                    "the name is {} bytes long, at most {} are allowed -- it is part of your identifier and cannot be changed later",
                    name.len(), crate::sync::MAX_AUTHOR_NAME_LEN)});
            }
            if name.is_empty() {
                return json!({"error": "name is empty"});
            }
            let mut locked = store.lock().unwrap();
            if locked.identity().is_some() {
                return json!({"error": "identity already exists"});
            }
            match locked.create_identity(&name) {
                Ok(_) => {
                    drop(locked);
                    status(&store)
                }
                Err(e) => json!({"error": e.to_string()}),
            }
        }

        ("POST", "/pending") => {
            let link = body["link"].as_str().unwrap_or("").to_string();
            let alias = body["alias"].as_str().unwrap_or("").to_string();
            let address = body["address"]
                .as_str()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let bluetooth = body["bluetooth"]
                .as_str()
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty());
            let onion = body["onion"]
                .as_str()
                .map(|s| s.trim().trim_end_matches(".onion").to_lowercase())
                .filter(|s| !s.is_empty());
            let public_key = match crate::ids::parse_handshake_link(&link) {
                Some(k) => k,
                None => return json!({"error": "not a briar:// link"}),
            };
            {
                let mut locked = store.lock().unwrap();
                if locked.identity().is_none() {
                    return json!({"error": "create an identity first"});
                }
                let own = locked
                    .identity()
                    .map(|i| key_from_hex(&i.handshake_public))
                    .unwrap_or([0u8; 32]);
                if own == public_key {
                    return json!({"error": "that is your own link"});
                }
                let hex = to_hex(&public_key);
                if locked.state.pending.iter().any(|p| p.public_key == hex)
                    || locked
                        .state
                        .contacts
                        .iter()
                        .any(|c| c.handshake_public.as_deref() == Some(hex.as_str()))
                {
                    return json!({"error": "that contact is already known"});
                }
                locked.state.pending.push(PendingContact {
                    public_key: hex,
                    alias,
                    address,
                    bluetooth,
                    onion,
                    added: now_ms(),
                    last_error: None,
                    transports: BTreeMap::new(),
                });
                if let Err(e) = locked.save() {
                    return json!({"error": e.to_string()});
                }
            }
            spawn_poll(&store);
            status(&store)
        }

        ("POST", "/send") => {
            let contact_id = body["contact"].as_u64().unwrap_or(0) as u32;
            let text = body["text"].as_str().unwrap_or("").to_string();
            if text.len() > crate::sync::MAX_PRIVATE_MESSAGE_TEXT_LEN {
                return json!({"error": format!(
                    "the message is {} bytes long, at most {} are allowed",
                    text.len(), crate::sync::MAX_PRIVATE_MESSAGE_TEXT_LEN)});
            }
            let file = body["file"].as_str().map(|s| s.to_string());
            if text.trim().is_empty() && file.is_none() {
                return json!({"error": "message is empty"});
            }
            {
                let mut locked = store.lock().unwrap();
                let group = match net::messaging_group_for(&locked, contact_id) {
                    Some(g) => g,
                    None => return json!({"error": "no such contact"}),
                };
                let mut attachments: Vec<(crate::crypto::SecretKey, String)> = Vec::new();
                if let Some(path) = file {
                    let content_type = body["contentType"]
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| guess_content_type(&path));
                    let capacity = crate::sync::attachment_capacity(&content_type);
                    // Nicht blind die ganze Datei lesen -- unter dem
                    // Speicherschloss: ein 2-GB-Video waere OOM, ein FIFO
                    // stuende fuer immer, und mit ihm der ganze Dienst.
                    // Erst nachsehen, was das ist, dann hoechstens so viel
                    // lesen, wie in eine Nachricht passt.
                    let data = match datei_lesen_begrenzt(&path, capacity) {
                        Ok(d) => d,
                        Err(e) => return json!({"error": format!("{}: {}", path, e)}),
                    };
                    if data.len() > capacity {
                        // Briar puts an attachment in a single message, and a
                        // message body cannot grow past 32 KiB. That is why
                        // Briar compresses images before sending them.
                        return json!({
                            "error": format!(
                                "the file is {} bytes, at most {} fit in one message",
                                data.len(), capacity),
                            "maxSize": capacity,
                        });
                    }
                    let attachment_body = crate::sync::attachment_body(&content_type, &data);
                    let timestamp = now_ms();
                    let attachment_id =
                        crate::ids::message_id(&group, timestamp, &attachment_body);
                    let hex = to_hex(&attachment_id);
                    if let Err(e) = locked.store_attachment(&hex, &content_type, &data) {
                        return json!({"error": e.to_string()});
                    }
                    locked.queue(
                        contact_id,
                        OutMessage {
                            id: hex,
                            group: to_hex(&group),
                            timestamp,
                            body: to_hex(&attachment_body),
                            acked: false,
                            intern: false,
                            loesch_dauer: None,
                        },
                    );
                    attachments.push((attachment_id, content_type));
                }
                // Der Zeitstempel muss ueber dem liegen, den die Gegenseite
                // zuletzt von uns gesehen hat -- sonst zaehlt unsere
                // Zuenddauer drueben nicht.
                //
                // Briar verwirft eine gemeldete Dauer, deren Zeitstempel nicht
                // groesser ist als der zuletzt gespeicherte
                // (AutoDeleteManagerImpl.receiveAutoDeleteTimer: "if (timestamp
                // <= oldTimestamp) return"). Geht unsere Uhr nach -- auf N9 und
                // N950 laeuft sie ohne Zeitdienst --, traegt jede Nachricht
                // einen kleineren Stempel als die vorige der Gegenseite, und
                // unsere Einstellung kaeme drueben nie an. Die Uhr wird dafuer
                // nicht verstellt, nur dieser eine Wert vorgerueckt.
                let timestamp = {
                    let zuletzt = locked
                        .contact(contact_id)
                        .map(|c| c.loesch_stempel)
                        .unwrap_or(0);
                    now_ms().max(zuletzt.saturating_add(1))
                };
                // Die Zuenddauer faehrt mit -- ausser die Gegenseite hat
                // ausdruecklich eine aeltere Nebenfassung angesagt. Wir sagen
                // 3 an, also erwartet Briar sie von uns; eine dreigliedrige
                // Nachricht liest es als "keine Dauer" und spiegelt sie
                // zurueck.
                let dauer = {
                    let kann = locked
                        .contact(contact_id)
                        .map(|c| c.darf_zuenddauer_bekommen())
                        .unwrap_or(false);
                    let t = locked.contact(contact_id).map(|c| c.loesch_timer).unwrap_or(-1);
                    if kann && t > 0 {
                        Some(t as u64)
                    } else {
                        None
                    }
                };
                if let Some(c) = locked.contact_mut(contact_id) {
                    // Die Aenderung ist jetzt draussen.
                    c.loesch_stempel = timestamp;
                    c.loesch_vorher = crate::store::keine_vorige();
                }
                let message_body = crate::sync::private_message_body_with(
                    if text.trim().is_empty() { None } else { Some(text.trim()) },
                    &attachments,
                    dauer,
                );
                let message_id = crate::ids::message_id(&group, timestamp, &message_body);
                let hex = to_hex(&message_id);
                locked.add_message(
                    contact_id,
                    crate::store::Message {
                        id: hex.clone(),
                        timestamp,
                        text: text.trim().to_string(),
                        outgoing: true,
                        acked: false,
                        attachment: attachments.first().map(|(id, _)| to_hex(id)),
                        attachment_type: attachments.first().map(|(_, t)| t.clone()),
                        anhaenge: attachments
                            .iter()
                            .map(|(id, t)| crate::store::Anhangskopf {
                                id: to_hex(id),
                                content_type: Some(t.clone()),
                            })
                            .collect(),
                        loesch_dauer: dauer,
                        loesch_frist: None,
                    },
                );
                locked.queue(
                    contact_id,
                    OutMessage {
                        id: hex,
                        group: to_hex(&group),
                        timestamp,
                        body: to_hex(&message_body),
                        acked: false,
                        intern: false,
                        loesch_dauer: dauer,
                    },
                );
                if let Err(e) = locked.save() {
                    return json!({"error": e.to_string()});
                }
            }
            let node_store = Arc::clone(&store);
            std::thread::spawn(move || {
                let node = Node::new(node_store);
                if let Err(e) = node.reach_contact(contact_id) {
                    net::log(&format!("sending to contact {} failed: {}", contact_id, e));
                }
            });
            json!({"ok": true})
        }

        ("GET", "/messages") if query_value(query, "jid").is_some() => {
            bridge_messages(&store, query)
        }

        ("GET", "/messages") => {
            let contact_id = query_value(query, "contact")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            let locked = store.lock().unwrap();
            match locked.contact(contact_id) {
                Some(contact) => json!({
                    "contact": contact.id,
                    "name": contact.name,
                    "messages": contact.messages.iter().map(|m| {
                        let attachment = m.attachment.as_ref()
                            .and_then(|id| locked.attachment(id));
                        // Alle Anhaenge -- die vier Felder darueber nennen
                        // weiterhin den ersten, damit eine aeltere Oberflaeche
                        // unveraendert weiterlaeuft.
                        let anhaenge: Vec<Value> = m.anhaenge.iter().map(|kopf| {
                            let datei = locked.attachment(&kopf.id);
                            // Ist der Anhang da, gilt sein gespeicherter Typ:
                            // der im Kopf der Nachricht ist der gemeldete,
                            // ungepruefte (Befund M7). Der Pfad ist bei
                            // versiegelter Ablage die Kopie im Laufzeitordner.
                            json!({
                                "id": kopf.id,
                                "type": datei.map(|a| Some(a.content_type.clone()))
                                    .unwrap_or_else(|| kopf.content_type.clone()),
                                "path": datei.and(locked.anhang_pfad(&kopf.id)),
                                "size": datei.map(|a| a.size),
                            })
                        }).collect();
                        json!({
                            "id": m.id,
                            "timestamp": m.timestamp,
                            "text": m.text,
                            "outgoing": m.outgoing,
                            "acked": m.acked,
                            "attachment": m.attachment,
                            "attachmentType": attachment
                                .map(|a| Some(a.content_type.clone()))
                                .unwrap_or_else(|| m.attachment_type.clone()),
                            "attachmentPath": m.attachment.as_ref()
                                .and_then(|id| locked.anhang_pfad(id)),
                            "attachmentSize": attachment.map(|a| a.size),
                            "attachments": anhaenge,
                            // Verschwindende Nachricht: die Dauer und, wenn
                            // die Uhr schon laeuft, der Zeitpunkt.
                            "autoDelete": m.loesch_dauer,
                            "deleteAt": m.loesch_frist,
                        })
                    }).collect::<Vec<Value>>(),
                    "autoDelete": contact.loesch_timer,
                    "autoDeleteReady": contact.zuenddauer_bestaetigt(),
                }),
                None => json!({"error": "no such contact"}),
            }
        }

        ("POST", "/connect") => {
            let contact_id = body["contact"].as_u64().map(|v| v as u32);
            let address = body["address"].as_str().map(|s| s.trim().to_string());
            let bluetooth = body["bluetooth"].as_str().map(|s| s.trim().to_uppercase());
            if let Some(id) = contact_id {
                let mut locked = store.lock().unwrap();
                if let Some(contact) = locked.contact_mut(id) {
                    if let Some(address) = address.filter(|a| !a.is_empty()) {
                        contact.transport_mut(LAN_TRANSPORT_ID).address = Some(address);
                    }
                    if let Some(address) = bluetooth.filter(|a| !a.is_empty()) {
                        contact.transport_mut(BLUETOOTH_TRANSPORT_ID).address = Some(address);
                    }
                    if let Some(address) = body["onion"].as_str().map(|s| s.trim().to_string())
                        .filter(|a| !a.is_empty())
                    {
                        contact.transport_mut(TOR_TRANSPORT_ID).address = Some(address);
                    }
                }
                let _ = locked.save();
            }
            let node_store = Arc::clone(&store);
            std::thread::spawn(move || {
                let node = Node::new(node_store);
                match contact_id {
                    Some(id) => {
                        if let Err(e) = node.reach_contact(id) {
                            net::log(&format!("connecting to contact {} failed: {}", id, e));
                        }
                    }
                    None => {
                        node.poll();
                    }
                }
            });
            json!({"ok": true})
        }

        ("POST", "/poll") => {
            spawn_poll(&store);
            json!({"ok": true})
        }

        // Einen wartenden Kontakt streichen -- eigener Weg, nicht /remove: dort
        // steht eine Kontaktnummer, hier der oeffentliche Schluessel, denn
        // eine Nummer bekommt ein Wartender erst mit dem Handschlag.
        ("POST", "/pending/remove") => {
            let public_key = body["publicKey"]
                .as_str()
                .unwrap_or("")
                .trim()
                .to_lowercase();
            if public_key.is_empty() {
                return json!({"error": "no publicKey given"});
            }
            let mut locked = store.lock().unwrap();
            let vorher = locked.state.pending.len();
            locked.state.pending.retain(|p| p.public_key != public_key);
            let entfernt = locked.state.pending.len() < vorher;
            if entfernt {
                let _ = locked.save();
            }
            drop(locked);
            // Den Treffpunkt raeumt run_rendezvous von selbst ab: es leitet
            // sein Soll in jeder Runde neu aus den Wartenden ab und nimmt
            // herunter, was daraus verschwunden ist.
            //
            // Kein Fehler, wenn nichts da war: dann ist der Handschlag
            // wahrscheinlich gerade geglueckt, und der Eintrag steht schon
            // als Kontakt in derselben Antwort.
            let mut antwort = status(&store);
            antwort["removed"] = json!(entfernt);
            antwort
        }

        ("POST", "/remove") => {
            let contact_id = match body["contact"].as_u64() {
                Some(id) => id as u32,
                None => return json!({"error": "no contact given"}),
            };
            let mut locked = store.lock().unwrap();
            locked.state.contacts.retain(|c| c.id != contact_id);
            for group in locked.state.groups.iter_mut() {
                group.contacts.retain(|c| *c != contact_id);
            }
            let _ = locked.save();
            drop(locked);
            status(&store)
        }

        ("POST", "/tor") => {
            let on = body["enabled"].as_bool().unwrap_or(true);
            let mut locked = store.lock().unwrap();
            locked.state.tor = on;
            if !on {
                // The address stops being reachable the moment Tor goes.
                locked.state.tor_onion = None;
            }
            let _ = locked.save();
            drop(locked);
            // No restart needed: the supervisor picks the switch up within
            // a few seconds, and stops Tor again when it is switched off.
            status(&store)
        }

        ("POST", "/read") => {
            let mut locked = store.lock().unwrap();
            let now = now_ms();
            if let Some(id) = body["contact"].as_u64() {
                let id = id as u32;
                if let Some(contact) = locked.contact_mut(id) {
                    contact.last_read = now;
                    // Gelesen heisst: die Uhr einer verschwindenden Nachricht
                    // laeuft. Briar macht es an derselben Stelle
                    // (ConversationManagerImpl.setReadFlag).
                    for m in contact.messages.iter_mut() {
                        if !m.outgoing {
                            net::loeschuhr_starten(m, now);
                        }
                    }
                }
                let _ = locked.save();
                drop(locked);
                close_notification(&id.to_string());
            } else if let Some(group) = body["group"].as_str() {
                let group = group.to_string();
                if let Some(entry) = locked.group_mut(&group) {
                    entry.last_read = now;
                    // Die Antwort der Gegenseite ist gesehen, sobald die Gruppe
                    // offen war. Sonst stuende "hat abgelehnt" fuer immer in der
                    // Liste und verdeckte den letzten Beitrag.
                    entry.letztes_ereignis = None;
                }
                let _ = locked.save();
                drop(locked);
                close_notification(&group);
            } else {
                drop(locked);
            }
            status(&store)
        }

        // Passwort setzen, aendern oder entfernen. Ein leeres Passwort hebt
        // die Verschluesselung auf -- das soll gehen, sonst waere ein
        // vergessenes Passwort bei noch laufendem Dienst eine Sackgasse.
        ("POST", "/password") => {
            let alt = body["old"].as_str();
            let passwort = body["password"].as_str().unwrap_or("");
            let mut locked = store.lock().unwrap();
            match locked.passwort_setzen(alt, passwort) {
                Ok(()) => json!({"ok": true, "encrypted": locked.verschluesselt()}),
                Err(e) => json!({"error": e.to_string()}),
            }
        }

        ("POST", "/language") => {
            let language = body["language"].as_str().unwrap_or("en");
            let mut locked = store.lock().unwrap();
            locked.state.language = Some(if language.starts_with("de") {
                "de".to_string()
            } else {
                "en".to_string()
            });
            let _ = locked.save();
            drop(locked);
            status(&store)
        }

        // Einstellungen ohne eigenen Weg. Bisher nur die Vorschau in den
        // Benachrichtigungen; was fehlt, bleibt, wie es ist.
        ("POST", "/settings") => {
            let mut locked = store.lock().unwrap();
            if let Some(vorschau) = body.get("notificationPreview") {
                match vorschau.as_bool() {
                    Some(v) => locked.state.notification_preview = v,
                    None => return json!({"error": "notificationPreview must be true or false"}),
                }
            }
            let _ = locked.save();
            json!({"ok": true})
        }

        ("POST", "/bluetooth") => {
            let on = body["enabled"].as_bool().unwrap_or(true);
            let mut locked = store.lock().unwrap();
            locked.state.bluetooth = on;
            let _ = locked.save();
            json!({"ok": true, "restart": true})
        }

        // --- private groups ------------------------------------------------
        ("GET", "/groups") => {
            let locked = store.lock().unwrap();
            json!({"groups": locked
                .state
                .groups
                .iter()
                .map(|g| group_json(&locked, g))
                .collect::<Vec<Value>>()})
        }

        ("POST", "/group") => {
            let name = body["name"].as_str().unwrap_or("").trim().to_string();
            if name.len() > crate::sync::MAX_GROUP_NAME_LEN {
                return json!({"error": format!(
                    "the group name is {} bytes long, at most {} are allowed",
                    name.len(), crate::sync::MAX_GROUP_NAME_LEN)});
            }
            if name.is_empty() {
                return json!({"error": "the group needs a name"});
            }
            let mut locked = store.lock().unwrap();
            let (author, seed) = match net::local_author(&locked) {
                Some(v) => v,
                None => return json!({"error": "create an identity first"}),
            };
            let salt = crate::util::random(groups::SALT_LEN);
            let group_id = groups::group_id(&author, &name, &salt);
            let group_hex = to_hex(&group_id);
            let author_id = to_hex(&author.id());
            let mut member_names = BTreeMap::new();
            member_names.insert(author_id.clone(), author.name.clone());
            let mut group = PrivateGroup {
                id: group_hex.clone(),
                name: name.clone(),
                salt: to_hex(&salt),
                creator_name: author.name.clone(),
                creator_public: to_hex(&author.public_key),
                creator_author_id: author_id.clone(),
                joined: true,
                invited_by: None,
                invite_timestamp: None,
                invite_signature: None,
                member_names,
                last_read: 0,
                messages: Vec::new(),
                our_previous: None,
                einladungen: BTreeMap::new(),
                einladung_previous: None,
                aufgeloest: false,
                letztes_ereignis: None,
                contacts: Vec::new(),
                wartend: Vec::new(),
                verworfen: Vec::new(),
            };
            // The creator's own join message starts its chain.
            let timestamp = now_ms();
            let join = groups::join_body(&group_id, timestamp, &author, &seed, None);
            let join_id = to_hex(&crate::ids::message_id(&group_id, timestamp, &join));
            group.messages.push(GroupPost {
                id: join_id.clone(),
                author_id,
                author_name: author.name.clone(),
                timestamp,
                text: String::new(),
                body: to_hex(&join),
                join: true,
            });
            group.our_previous = Some(join_id);
            locked.state.groups.push(group);
            let _ = locked.save();
            drop(locked);
            json!({"ok": true, "group": group_hex})
        }

        ("POST", "/group/invite") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let contact_id = body["contact"].as_u64().unwrap_or(0) as u32;
            let mut locked = store.lock().unwrap();
            let (author, seed) = match net::local_author(&locked) {
                Some(v) => v,
                None => return json!({"error": "create an identity first"}),
            };
            let our_author_id = author.id();
            let (group_id, name, salt, creator_author_id, is_creator) =
                match locked.group(&group_hex) {
                    Some(g) => (
                        key_from_hex(&g.id),
                        g.name.clone(),
                        from_hex(&g.salt).unwrap_or_default(),
                        key_from_hex(&g.creator_author_id),
                        g.creator_author_id == to_hex(&our_author_id),
                    ),
                    None => return json!({"error": "no such group"}),
                };
            if !is_creator {
                // Briar lets only the creator invite, and a member's join
                // message has to carry the creator's signature.
                return json!({"error": "only the group's creator can invite"});
            }
            let their_author_id = match locked.contact(contact_id) {
                Some(c) => c.author_id_bytes(),
                None => return json!({"error": "no such contact"}),
            };
            // Zweimal einladen ist in Briar ein Zustandsfehler (onInviteAction
            // wirft in INVITED, JOINED und LEFT). Hier kostet es mehr als dort:
            // die zweite Einladung traegt eine andere Kennung, die Gegenseite
            // hat die Gruppe schon und wirft sie weg -- der Benutzer sieht
            // nichts und tippt weiter. Das ist auch der Grund, warum wir eine
            // doppelte Einladung beim Empfaenger NICHT abbrechen: hier ist der
            // Ort, wo sie gar nicht entsteht.
            let (schon_drin, sitzungszustand) = match locked.group(&group_hex) {
                Some(g) => (
                    g.messages
                        .iter()
                        .any(|m| m.join && m.author_id == to_hex(&their_author_id)),
                    g.einladungen.get(&contact_id).map(|s| s.zustand),
                ),
                None => (false, None),
            };
            if schon_drin || sitzungszustand == Some(crate::store::Sitzungszustand::Beigetreten) {
                return json!({"error": "the contact is already in this group"});
            }
            if sitzungszustand == Some(crate::store::Sitzungszustand::Eingeladen) {
                return json!({"error": "an invitation is already on its way"});
            }
            if sitzungszustand == Some(crate::store::Sitzungszustand::Fehler) {
                // In ERROR nimmt Briar nichts mehr an; eine Einladung ginge in
                // eine Sitzung, die auf beiden Seiten abgebrochen ist.
                return json!({"error": "the invitation session with this contact has failed"});
            }
            if sitzungszustand == Some(crate::store::Sitzungszustand::Gegangen) {
                // Seine Beitrittsnachricht steht noch in der Gruppe. Ein
                // zweiter Beitritt wuerde seine Kette gabeln, und die Gruppe
                // prueft genau die.
                return json!({"error": "the contact has left this group"});
            }
            // Echt spaeter als alles, was in dieser Sitzung schon lief.
            let timestamp = locked
                .sitzung(&group_hex, contact_id)
                .map(|s| s.naechster_zeitstempel())
                .unwrap_or_else(now_ms);
            let signature = groups::invite_signature(
                &seed,
                &creator_author_id,
                &their_author_id,
                &group_id,
                timestamp,
            );
            let invite = groups::invite_body(&author, &name, &salt, None, &signature);
            let invite_group = groups::invite_group_id(&our_author_id, &their_author_id);
            let invite_id = crate::ids::message_id(&invite_group, timestamp, &invite);
            locked.queue(
                contact_id,
                OutMessage {
                    id: to_hex(&invite_id),
                    group: to_hex(&invite_group),
                    timestamp,
                    body: to_hex(&invite),
                    acked: false,
                    intern: false,
                    loesch_dauer: None,
                },
            );
            // Die Kennung DIESER INVITE ist der erste Anker der Kette zu
            // DIESEM Kontakt: unser spaeteres JOIN nennt sie als vorige
            // Nachricht (CreatorProtocolEngine.onRemoteAccept ->
            // sendJoinMessage mit s.getLastLocalMessageId()). Bisher wurde sie
            // berechnet und weggeworfen, und damit war die Kette kopflos.
            if let Some(s) = locked.sitzung_mut(&group_hex, contact_id) {
                s.letzte_eigene = Some(to_hex(&invite_id));
                s.eigener_zeitstempel = timestamp;
                s.einladungs_zeitstempel = timestamp;
                s.zustand = crate::store::Sitzungszustand::Eingeladen;
            }
            // Den Verlauf der Gruppe bekommt die Eingeladene NICHT schon jetzt,
            // sondern erst mit ihrer Zusage (net.rs, receive_einladung_join).
            //
            // Vorher ging er sofort hinaus. Bei einem echten Briar existiert die
            // Gruppe vor der Zusage aber gar nicht, sie gilt als unsichtbar --
            // und in einer unsichtbaren Gruppe wird jede Nachricht verworfen UND
            // nicht quittiert. Der Korb haette also den ganzen Verlauf in jeder
            // Runde erneut geschickt, bis sie zusagt, und fuer immer, wenn sie
            // nie antwortet.
            if let Some(group) = locked.group_mut(&group_hex) {
                if !group.contacts.contains(&contact_id) {
                    group.contacts.push(contact_id);
                }
            }
            let _ = locked.save();
            drop(locked);
            let node_store = Arc::clone(&store);
            std::thread::spawn(move || {
                let node = Node::new(node_store);
                let _ = node.reach_contact(contact_id);
            });
            json!({"ok": true})
        }

        ("POST", "/group/join") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let mut locked = store.lock().unwrap();
            let (author, seed) = match net::local_author(&locked) {
                Some(v) => v,
                None => return json!({"error": "create an identity first"}),
            };
            let (group_id, invite, contacts, already) = match locked.group(&group_hex) {
                Some(g) => {
                    let invite = match (g.invite_timestamp, g.invite_signature.clone()) {
                        (Some(t), Some(s)) => Some((t, from_hex(&s).unwrap_or_default())),
                        _ => None,
                    };
                    (key_from_hex(&g.id), invite, g.contacts.clone(), g.joined)
                }
                None => return json!({"error": "no such group"}),
            };
            if already {
                return json!({"error": "already joined"});
            }
            // Eine Einladung, die nicht mehr gilt: der Ersteller ist gegangen
            // (Briars onRemoteLeaveWhenNotSubscribed macht sie unbeantwortbar)
            // oder die Sitzung ist zerrissen. Beitreten wuerde eine Gruppe
            // anlegen, die niemand mehr haelt, und ein JOIN an jemanden
            // schicken, der uns nicht mehr zuhoert.
            let hinfaellig = match locked.group(&group_hex) {
                Some(g) => {
                    g.aufgeloest
                        || g.invited_by
                            .and_then(|c| g.einladungen.get(&c))
                            .map(|s| s.zustand == crate::store::Sitzungszustand::Fehler)
                            .unwrap_or(false)
                }
                None => false,
            };
            if hinfaellig {
                return json!({"error": "this invitation is no longer valid"});
            }
            // Das JOIN muss echt hinter der Einladung liegen. Sonst erklaert
            // Briars GroupMessageValidator es fuer ungueltig, und die Sitzung
            // des Einladenden bricht bei unserer Antwort in der
            // Einladungsgruppe ab, statt die Gruppe zu teilen -- wir waeren
            // formal beigetreten und bekaemen doch nie einen Beitrag. Die Uhr
            // des N9 geht gern nach, dann liegt eine Einladung von der Jolla
            // in unserer Zukunft.
            let einladung_zeit = invite.as_ref().map(|(t, _)| *t).unwrap_or(0);
            let timestamp = groups::vorgerueckt(now_ms(), einladung_zeit);
            let join = groups::join_body(&group_id, timestamp, &author, &seed, invite);
            let join_id = to_hex(&crate::ids::message_id(&group_id, timestamp, &join));
            let author_id = to_hex(&author.id());
            if let Some(group) = locked.group_mut(&group_hex) {
                group.joined = true;
                group.our_previous = Some(join_id.clone());
                group
                    .member_names
                    .insert(author_id.clone(), author.name.clone());
                group.messages.push(GroupPost {
                    id: join_id.clone(),
                    author_id,
                    author_name: author.name.clone(),
                    timestamp,
                    text: String::new(),
                    body: to_hex(&join),
                    join: true,
                });
            }
            for contact in &contacts {
                locked.queue(
                    *contact,
                    OutMessage {
                        id: join_id.clone(),
                        group: group_hex.clone(),
                        timestamp,
                        body: to_hex(&join),
                        acked: false,
                        intern: false,
                        loesch_dauer: None,
                    },
                );
            }
            // Und die Antwort an den Einladenden, in SEINE Einladungsgruppe.
            // Ohne sie teilt er die Gruppe nie: seine Sitzung wartet auf
            // genau diese Nachricht und bliebe sonst ewig im Zustand
            // INVITED -- wir bekaemen die Beitraege der anderen Mitglieder
            // nicht, obwohl wir formal beigetreten sind.
            if let Some(einladender) = locked.group(&group_hex).and_then(|g| g.invited_by) {
                let ihre_kennung = locked
                    .contact(einladender)
                    .map(|c| c.author_id_bytes());
                let vorige = locked
                    .sitzung(&group_hex, einladender)
                    .and_then(|s| s.letzte_eigene.clone());
                if let Some(ihre) = ihre_kennung {
                    let einladungsgruppe = groups::invite_group_id(&author.id(), &ihre);
                    let rumpf = groups::einladung_join_body(
                        &group_id,
                        vorige.as_deref().and_then(|v| from_hex(v)).as_deref(),
                    );
                    let kennung = to_hex(&crate::ids::message_id(
                        &einladungsgruppe,
                        timestamp,
                        &rumpf,
                    ));
                    locked.queue(
                        einladender,
                        OutMessage {
                            id: kennung.clone(),
                            group: to_hex(&einladungsgruppe),
                            timestamp,
                            body: to_hex(&rumpf),
                            acked: false,
                            intern: false,
                            loesch_dauer: None,
                        },
                    );
                    // Fortschreiben in DER Sitzung, aus der die Kette kommt --
                    // nicht an der Gruppe, wo sie sich mit anderen Kontakten
                    // vermischt.
                    if let Some(s) = locked.sitzung_mut(&group_hex, einladender) {
                        s.letzte_eigene = Some(kennung);
                        s.eigener_zeitstempel = timestamp;
                        // Gleich Beigetreten, nicht ein Wartezustand: unser
                        // Beitritt in der Gruppe geht im selben Aufruf hinaus,
                        // wir teilen also sofort. Briars Eingeladener geht nach
                        // ACCEPTED und wartet auf das JOIN des Erstellers, aber
                        // nur, weil dort die Sichtbarkeit daran haengt.
                        s.zustand = crate::store::Sitzungszustand::Beigetreten;
                    }
                }
            }
            let _ = locked.save();
            drop(locked);
            spawn_poll(&store);
            json!({"ok": true})
        }

        ("POST", "/group/send") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let text = body["text"].as_str().unwrap_or("").trim().to_string();
            if text.is_empty() {
                return json!({"error": "message is empty"});
            }
            // Dieselbe Falle wie bei /send, nur mit einer anderen Zahl: ein zu
            // langer Beitrag reisst bei der Gegenseite nicht die Nachricht ab,
            // sondern die Verbindung -- und weil der Ausgangskorb Unquittiertes
            // behaelt, stolpert danach jede weitere Runde daran.
            if text.len() > crate::sync::MAX_GROUP_POST_TEXT_LEN {
                return json!({"error": format!(
                    "the post is {} bytes long, at most {} are allowed",
                    text.len(), crate::sync::MAX_GROUP_POST_TEXT_LEN)});
            }
            let mut locked = store.lock().unwrap();
            let (author, seed) = match net::local_author(&locked) {
                Some(v) => v,
                None => return json!({"error": "create an identity first"}),
            };
            let (group_id, previous, vorher, contacts, joined, aufgeloest) =
                match locked.group(&group_hex) {
                    Some(g) => (
                        key_from_hex(&g.id),
                        g.our_previous.clone(),
                        g.vorgaenger_zeit(),
                        // Nicht an offene Einladungen -- siehe empfaenger().
                        g.empfaenger(),
                        g.joined,
                        g.aufgeloest,
                    ),
                    None => return json!({"error": "no such group"}),
                };
            if !joined {
                return json!({"error": "join the group first"});
            }
            // In eine aufgeloeste Gruppe laesst Briar nichts mehr schreiben
            // (isDissolved). Der Verlauf bleibt lesbar und Entfernen bleibt
            // moeglich -- nur hinaus geht nichts mehr, denn der Ersteller, an
            // dem die Gruppe haengt, ist weg.
            if aufgeloest {
                return json!({"error": "this group has been dissolved"});
            }
            let previous = match previous {
                Some(p) => key_from_hex(&p),
                None => return json!({"error": "no join message yet"}),
            };
            // Zwei Beitraege in derselben Millisekunde, oder eine
            // zurueckgestellte Uhr, und Briar wirft den zweiten beim Zustellen
            // weg: er muss echt hinter unserer vorigen eigenen Nachricht
            // liegen (PrivateGroupManagerImpl.handleGroupMessage, Zeile 588).
            // Nach einem vorgeruecktem JOIN ist das sogar der Normalfall --
            // dessen Zeitstempel kann vor der Uhr liegen.
            let timestamp = groups::vorgerueckt(now_ms(), vorher);
            let post = groups::post_body(
                &group_id,
                timestamp,
                &author,
                &seed,
                None,
                &previous,
                &text,
            );
            let post_id = to_hex(&crate::ids::message_id(&group_id, timestamp, &post));
            let author_id = to_hex(&author.id());
            if let Some(group) = locked.group_mut(&group_hex) {
                group.messages.push(GroupPost {
                    id: post_id.clone(),
                    author_id,
                    author_name: author.name.clone(),
                    timestamp,
                    text: text.clone(),
                    body: to_hex(&post),
                    join: false,
                });
                group.our_previous = Some(post_id.clone());
            }
            for contact in &contacts {
                locked.queue(
                    *contact,
                    OutMessage {
                        id: post_id.clone(),
                        group: group_hex.clone(),
                        timestamp,
                        body: to_hex(&post),
                        acked: false,
                        intern: false,
                        loesch_dauer: None,
                    },
                );
            }
            let _ = locked.save();
            drop(locked);
            for contact in contacts {
                let node_store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let node = Node::new(node_store);
                    let _ = node.reach_contact(contact);
                });
            }
            json!({"ok": true})
        }

        ("GET", "/group/messages") => {
            let group_hex = query_value(query, "group").unwrap_or_default();
            let locked = store.lock().unwrap();
            // Wem gegenueber sich die Beziehung in dieser Gruppe noch zeigen
            // laesst -- Briars "Kontakte zeigen". Die Regeln stehen in
            // net::zeigbarkeit; hier wird nur gefragt.
            let kontaktnummern: Vec<u32> = locked.state.contacts.iter().map(|c| c.id).collect();
            let zeigbar: Vec<Value> = kontaktnummern
                .iter()
                .filter(|id| net::zeigbarkeit(&locked, &group_hex, **id).is_ok())
                .filter_map(|id| {
                    locked
                        .contact(*id)
                        .map(|c| json!({"id": c.id, "name": c.name}))
                })
                .collect();
            // Und wem gegenueber es schon geschehen ist: eine eigene
            // Nachricht in einer Sitzung, in der wir weder eingeladen haben
            // noch eingeladen wurden.
            let gezeigt: Vec<Value> = kontaktnummern
                .iter()
                .filter(|id| {
                    matches!(
                        net::zeigbarkeit(&locked, &group_hex, **id),
                        Err("schon gezeigt")
                    )
                })
                .filter_map(|id| {
                    locked
                        .contact(*id)
                        .map(|c| json!({"id": c.id, "name": c.name}))
                })
                .collect();
            match locked.group(&group_hex) {
                Some(group) => json!({
                    "revealable": zeigbar,
                    "revealed": gezeigt,
                    "group": group.id,
                    "name": group.name,
                    "joined": group.joined,
                    "dissolved": group.aufgeloest,
                    "messages": group.messages.iter().filter(|m| !m.join).map(|m| json!({
                        "id": m.id,
                        "timestamp": m.timestamp,
                        "text": m.text,
                        "author": m.author_name,
                        "authorId": m.author_id,
                    })).collect::<Vec<Value>>(),
                    "members": group.member_names.values().collect::<Vec<&String>>(),
                }),
                None => json!({"error": "no such group"}),
            }
        }

        // Die Beziehung in einer Gruppe zeigen -- Briars "Kontakte zeigen".
        // Es ist ein JOIN in der Einladungsgruppe dieses Kontakts, mehr nicht;
        // was es bewirkt, steht bei Node::beziehung_zeigen.
        ("POST", "/group/reveal") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let kontakt = body["contact"].as_u64().unwrap_or(0) as u32;
            let mut locked = store.lock().unwrap();
            let node = Node::new(Arc::clone(&store));
            match node.beziehung_zeigen(&mut locked, kontakt, &group_hex) {
                Ok(()) => {
                    let _ = locked.save();
                    drop(locked);
                    // Gleich hinausschicken, nicht erst beim naechsten
                    // Abgleich -- sonst sieht es aus, als sei nichts geschehen.
                    let node_store = Arc::clone(&store);
                    std::thread::spawn(move || {
                        let node = Node::new(node_store);
                        let _ = node.reach_contact(kontakt);
                    });
                    json!({"ok": true})
                }
                Err(grund) => json!({"error": grund}),
            }
        }

        ("POST", "/group/remove") => {
            let group_hex = body["group"].as_str().unwrap_or("").to_string();
            let mut locked = store.lock().unwrap();
            // Erst den Mitgliedern sagen, dass wir gehen, dann gehen. Ohne
            // LEAVE haelt die Gegenseite uns fuer immer fuer ein Mitglied und
            // schickt weiter Beitraege an jemanden, der nicht mehr zuhoert.
            let (gruppen_id, kontakte, eigene) = match locked.group(&group_hex) {
                Some(g) => (
                    key_from_hex(&g.id),
                    g.contacts.clone(),
                    locked.identity().map(|i| key_from_hex(&i.author_id)),
                ),
                None => (key_from_hex(&group_hex), Vec::new(), None),
            };
            if let Some(unsere) = eigene {
                // Das LEAVE muss hinter der Einladung liegen, sonst bricht die
                // Sitzung der Gegenseite ab statt unser Gehen zu verbuchen
                // (CreatorProtocolEngine.onRemoteDecline) -- und wir gelten
                // dort weiter als Mitglied, genau das, was der Kommentar oben
                // verhindern will. Eine selbst angelegte Gruppe hat keine
                // Einladung, dann bleibt es bei der Uhr.
                let einladung_zeit = locked
                    .group(&group_hex)
                    .and_then(|g| g.invite_timestamp)
                    .unwrap_or(0);
                for kontakt in &kontakte {
                    let ihre = match locked.contact(*kontakt) {
                        Some(c) => c.author_id_bytes(),
                        None => continue,
                    };
                    let einladungsgruppe = groups::invite_group_id(&unsere, &ihre);
                    // Jede Sitzung hat ihre eigene Kette und ihren eigenen
                    // Zeitstempel. Vorher nahmen alle LEAVE dieselbe vorige
                    // Nachricht -- sie stammte aus der Sitzung mit dem
                    // Einladenden und kommt in der Kontaktgruppe der anderen
                    // nicht vor. Briars Pruefer macht die vorige Nachricht zur
                    // Vorbedingung (GroupInvitationValidator.validateLeave),
                    // und die trifft dort nie ein: das LEAVE bliebe fuer immer
                    // liegen.
                    let (vorige, timestamp) = match locked.sitzung(&group_hex, *kontakt) {
                        Some(s) => (s.letzte_eigene.clone(), s.naechster_zeitstempel()),
                        None => (
                            None,
                            groups::vorgerueckt(crate::util::now_ms(), einladung_zeit),
                        ),
                    };
                    let rumpf = groups::einladung_leave_body(
                        &gruppen_id,
                        vorige.as_deref().and_then(|v| from_hex(v)).as_deref(),
                    );
                    let kennung = to_hex(&crate::ids::message_id(
                        &einladungsgruppe,
                        timestamp,
                        &rumpf,
                    ));
                    locked.queue(
                        *kontakt,
                        OutMessage {
                            id: kennung.clone(),
                            group: to_hex(&einladungsgruppe),
                            timestamp,
                            body: to_hex(&rumpf),
                            acked: false,
                            intern: false,
                            loesch_dauer: None,
                        },
                    );
                    // Die Kette fortschreiben -- das LEAVE ist ab jetzt unsere
                    // letzte eigene Nachricht in dieser Sitzung.
                    //
                    // Ohne diese Zeile stand hier fuer eine nie angenommene
                    // Einladung weiterhin None. Briars Ersteller merkt sich
                    // dagegen die Kennung unseres LEAVE (CreatorProtocolEngine
                    // onRemoteDecline) und macht sie zur Vorbedingung des
                    // naechsten JOIN (isValidDependency). Unser JOIN nach einer
                    // zweiten Einladung nannte also die falsche vorige
                    // Nachricht, Briar brach die Sitzung ab (ABORT) und stellte
                    // die Gruppe fuer uns auf unsichtbar: jeder weitere Beitrag
                    // von uns wurde dort weder gespeichert noch quittiert, und
                    // von drueben kam nichts mehr. Ein Weg zurueck gab es
                    // nicht. Der Kommentar darunter beschrieb die Regel schon,
                    // der Code hielt sie nur nicht ein.
                    if let Some(s) = locked.sitzung_mut(&group_hex, *kontakt) {
                        s.letzte_eigene = Some(kennung);
                        s.eigener_zeitstempel = timestamp;
                    }
                }
            }
            // Die Sitzungen ueberleben die Gruppe. Entfernen ist auf der
            // Leitung eine Ablehnung -- Briar verbucht unser LEAVE als solche,
            // geht nach START und darf neu einladen. Kommt diese neue Einladung,
            // muss unser JOIN die Kette fortsetzen: Briar erwartet als vorige
            // Nachricht unser LEAVE (isValidDependency) und bricht sonst ab.
            if let Some(g) = locked.group(&group_hex) {
                let sitzungen = g.einladungen.clone();
                if !sitzungen.is_empty() {
                    locked
                        .state
                        .verlassene_einladungen
                        .insert(group_hex.clone(), sitzungen);
                }
            }
            // Und die eigene Gruppenpost aus dem Korb: wir gehen, also wird sie
            // niemand mehr annehmen. Bei einem echten Briar bliebe ein vorher
            // abgewiesener Beitrag sonst fuer immer unquittiert liegen und
            // stuende dauerhaft im Zaehler am Kontakt. Das LEAVE selbst liegt in
            // der Einladungsgruppe und bleibt davon unberuehrt.
            for kontakt in &kontakte {
                locked.verwerfe_gruppenpost(*kontakt, &group_hex);
            }
            locked.state.groups.retain(|g| g.id != group_hex);
            let _ = locked.save();
            drop(locked);
            spawn_poll(&store);
            json!({"ok": true})
        }

        _ => json!({"error": "unknown request"}),
    }
}

/// A content type from the file's ending, for the common cases.
fn guess_content_type(path: &str) -> String {
    let lower = path.to_lowercase();
    let kind = if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else if lower.ends_with(".txt") {
        "text/plain"
    } else {
        "application/octet-stream"
    };
    kind.to_string()
}

fn group_json(store: &Store, group: &PrivateGroup) -> Value {
    let our_author = store
        .identity()
        .map(|i| i.author_id.clone())
        .unwrap_or_default();
    json!({
        "id": group.id,
        "name": group.name,
        "joined": group.joined,
        "creator": group.creator_name,
        "isCreator": group.creator_author_id == our_author,
        "invitedBy": group.invited_by,
        "members": group.member_names.len(),
        "messages": group.messages.iter().filter(|m| !m.join).count(),
        "lastText": group.messages.iter().filter(|m| !m.join).last().map(|m| m.text.clone()),
        "contacts": group.contacts,
        "dissolved": group.aufgeloest,
        // Nur die Art und der Name, nicht der Satz: die Worte macht die
        // Oberflaeche, sonst stuende deutsche Schrift im Dienst und die
        // Sprachumschaltung griffe hier nicht.
        "event": group.letztes_ereignis.as_ref().map(|e| json!({
            "kind": match e.art {
                crate::store::Ereignisart::Angenommen => "accepted",
                crate::store::Ereignisart::Abgelehnt => "declined",
                crate::store::Ereignisart::Gegangen => "left",
                crate::store::Ereignisart::Aufgeloest => "dissolved",
                crate::store::Ereignisart::Abgebrochen => "aborted",
            },
            "who": e.wer,
            "at": e.wann,
        })),
    })
}

fn status(store: &Shared) -> Value {
    let locked = store.lock().unwrap();
    // Zugesperrt heisst zugesperrt: nur, was die Entsperrseite braucht.
    // Kontakte, Adressen und zuletzt der Text der letzten Nachricht blieben
    // sonst fuer jeden lesbar, der das Geheimnis hat (Sicherheitsbefund M1).
    if ist_gesperrt() {
        return json!({
            "locked": true,
            "running": true,
            "version": env!("CARGO_PKG_VERSION"),
            "encrypted": locked.verschluesselt(),
            "language": locked.state.language.clone().unwrap_or_else(|| "en".to_string()),
        });
    }
    let identity = locked.identity().map(|i| {
        json!({
            "name": i.name,
            "authorId": i.author_id,
        })
    });
    let contacts: Vec<Value> = locked
        .state
        .contacts
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "name": c.name,
                "address": c.address(LAN_TRANSPORT_ID),
                "bluetooth": c.address(BLUETOOTH_TRANSPORT_ID),
                "onion": c.address(TOR_TRANSPORT_ID),
                "unread": c.messages.iter()
                    .filter(|m| !m.outgoing && m.timestamp > c.last_read)
                    .count(),
                "lastSeen": c.last_seen,
                "messages": c.messages.len(),
                // Haushaltskram zaehlt nicht mit: Adressmeldung und
                // Versionsansage liegen im selben Korb, sind aber nichts, was
                // der Benutzer geschrieben hat.
                "unsent": c.outbox.iter().filter(|m| !m.acked && !m.intern).count(),
                "lastText": c.messages.last().map(|m| m.text.clone()),
                // Verschwindende Nachrichten: die Dauer in Millisekunden,
                // -1 heisst aus. "autoDeleteReady" sagt, ob die Gegenseite
                // sie ueberhaupt liest.
                "autoDelete": c.loesch_timer,
                "autoDeleteReady": c.zuenddauer_bestaetigt(),
            })
        })
        .collect();
    let pending: Vec<Value> = locked
        .state
        .pending
        .iter()
        .map(|p| {
            json!({
                "publicKey": p.public_key,
                "alias": p.alias,
                "address": p.address,
                "bluetooth": p.bluetooth,
                "onion": p.onion,
                "added": p.added,
                "lastError": p.last_error,
            })
        })
        .collect();
    let groups: Vec<Value> = locked
        .state
        .groups
        .iter()
        .map(|g| group_json(&locked, g))
        .collect();
    // Alle Netze, durch Komma getrennt. Daraus baut die Oberflaeche den
    // briar://-Link und damit den QR-Code -- stuende hier nur eine Adresse,
    // waere jede Kopplung wieder an ein einziges Netz genagelt.
    let lan_port = locked.state.listen_port;
    let lan_addresses = {
        // Aus dem Gedaechtnis, nicht aus den gerade vorhandenen Adressen:
        // hier muss genau das stehen, was die Kontakte gemeldet bekommen,
        // sonst traegt der QR-Code etwas anderes als der Ausgangskorb.
        let list = if locked.state.lan_recent.is_empty() {
            crate::net::local_ips()
                .iter()
                .map(|ip| format!("{}:{}", ip, lan_port))
                .collect::<Vec<_>>()
                .join(",")
        } else {
            locked.state.lan_recent.join(",")
        };
        if list.is_empty() {
            None
        } else {
            Some(list)
        }
    };
    json!({
        "identity": identity,
        "link": locked.link(),
        "port": locked.state.listen_port,
        "bluetooth": locked.state.bluetooth,
        "language": locked.state.language.clone().unwrap_or_else(|| "en".to_string()),
        "notificationPreview": locked.state.notification_preview,
        "bluetoothAddress": crate::bt::local_address(),
        // Our own address on this network, so the QR code can carry it.
        "unread": locked
            .state
            .contacts
            .iter()
            .map(|c| c.messages.iter()
                .filter(|m| !m.outgoing && m.timestamp > c.last_read)
                .count())
            .sum::<usize>(),
        // Alle Netze, durch Komma getrennt. Daraus baut die Oberflaeche den
        // briar://-Link und damit den QR-Code -- stuende hier nur eine
        // Adresse, waere jede Kopplung wieder an ein einziges Netz genagelt.
        "lanAddress": lan_addresses,
        "locked": ist_gesperrt(),
        "encrypted": locked.verschluesselt(),
        "lockAfter": locked.state.sperre_nach_minuten,
        "tor": locked.state.tor,
        "onion": locked.state.tor_onion,
        // Steht der erste Tor-Start noch aus? Dann fehlt der Verzeichniscache,
        // und Tor zieht beim Start rund 23 MB ueber die Leitung (gemessen
        // 29.09.2026) -- auf 2G eine Viertelstunde bis eine Stunde. Danach
        // sind es Kilobyte. Die Oberflaeche sagt das neben dem Schalter.
        // Auch das Journal zaehlt: nach einem kurzen ersten Lauf liegt alles
        // in cached-microdescs.new, die eigentliche Datei kommt erst nach
        // zwei Minuten -- geladen wird dann trotzdem nichts mehr.
        "torFirstRun": locked
            .path
            .parent()
            .map(|p| {
                let tor = p.join("tor");
                !tor.join("cached-microdescs").exists()
                    && !tor.join("cached-microdescs.new").exists()
            })
            .unwrap_or(true),
        "revision": locked.state.revision,
        // Steht die Uhr dieses Geraets erkennbar falsch? Dann kommt nichts an,
        // ohne dass es jemand merkt: Briar verwirft eine Nachricht, deren
        // Zeitstempel mehr als einen Tag in seiner Zukunft liegt -- quittiert
        // sie aber vorher, also gilt sie bei uns als zugestellt. Und ein
        // Kontaktaustausch mit einer Uhr vor 2021 scheitert drueben ganz.
        // N9 und N950 haben keinen Zeitdienst; eine leere Pufferbatterie
        // setzt sie auf 1970.
        "clockWrong": net::uhr_steht_falsch(),
        // Der Kontakt, den das letzte Treffen angelegt oder wiedererkannt
        // hat -- 0 heisst keiner. Die Treffen-Seite las den Erfolg bisher
        // nur am Wachsen der Kontaktliste ab; trifft man einen, den man
        // schon hat, waechst da nichts, und die Seite blieb auf "Gelesen"
        // stehen, obwohl beide Dienste "Kontakt 1 steht" meldeten.
        "bqpContact": net::BQP_ERGEBNIS.lock().unwrap().unwrap_or(0),
        // Welche Fassung hier wirklich laeuft. Das Paket zu lesen sagt nur,
        // was auf der Platte liegt -- der Dienst ueberlebt eine
        // Aktualisierung, wenn ihn niemand beendet.
        "version": env!("CARGO_PKG_VERSION"),
        "contacts": contacts,
        "pending": pending,
        "groups": groups,
    })
}

// --- Die Sprechweise der Nachrichtenbrücke -------------------------------
//
// Die Brücke auf dem N9 (Telepathy-Verbindungsmanager, ~/ps/nachrichtenbruecke)
// spricht mit den Diensten von WhatsApp und Flüsterwind über eine kleine
// HTTP-Schnittstelle: /chats, /messages?jid=, /send?to=&text=, /events?since=.
// Damit Briar in der Nachrichten-App des Geräts auftaucht, muss der Dienst
// nur dieselben vier Wege können -- die Brücke selbst braucht dann keinen
// eigenen Briar-Code, nur einen Eintrag mehr.
//
// Eine Kennung ("jid") ist hier c<Kontaktnummer> oder g<Gruppenkennung>.

/// Zerlegt eine Brücken-Kennung: "c3" -> Kontakt 3, "gab12..." -> Gruppe.
fn bridge_target(jid: &str) -> Option<(bool, String)> {
    let mut chars = jid.chars();
    let kind = chars.next()?;
    let rest: String = chars.collect();
    match kind {
        'c' => Some((false, rest)),
        'g' => Some((true, rest)),
        _ => None,
    }
}

/// Die Nachrichten eines Chats in der Form, die die Brücke erwartet.
fn bridge_messages(store: &Shared, query: &str) -> Value {
    let jid = query_value(query, "jid").unwrap_or_default();
    let Some((group, rest)) = bridge_target(&jid) else {
        return Value::Array(Vec::new());
    };
    let locked = store.lock().unwrap();
    let own_name = locked
        .identity()
        .map(|i| i.name.clone())
        .unwrap_or_default();
    if group {
        let Some(entry) = locked.group(&rest) else {
            return Value::Array(Vec::new());
        };
        let messages: Vec<Value> = entry
            .messages
            .iter()
            .filter(|m| !m.join)
            .map(|m| {
                json!({
                    "id": m.id,
                    "chatJid": jid,
                    "sender": m.author_name,
                    "text": m.text,
                    "fromMe": m.author_name == own_name,
                    "timestamp": m.timestamp,
                    "mediaType": "",
                    "fileName": "",
                })
            })
            .collect();
        return Value::Array(messages);
    }
    let Ok(contact_id) = rest.parse::<u32>() else {
        return Value::Array(Vec::new());
    };
    let Some(contact) = locked.contact(contact_id) else {
        return Value::Array(Vec::new());
    };
    let messages: Vec<Value> = contact
        .messages
        .iter()
        .map(|m| {
            json!({
                "id": m.id,
                "chatJid": jid,
                "sender": if m.outgoing { own_name.clone() } else { contact.name.clone() },
                "text": m.text,
                "fromMe": m.outgoing,
                "timestamp": m.timestamp,
                // Der gespeicherte, am Inhalt gepruefte Typ -- nicht der aus
                // dem Nachrichtenkopf, den die Gegenseite gemeldet hat (7b,
                // C7). Nur wenn der Anhang (noch) fehlt, der gemeldete.
                "mediaType": m
                    .attachment
                    .as_deref()
                    .and_then(|a| locked.attachment(a))
                    .map(|a| a.content_type.clone())
                    .or_else(|| m.attachment_type.clone())
                    .unwrap_or_default(),
                "fileName": "",
            })
        })
        .collect();
    Value::Array(messages)
}

/// Senden über die Brücken-Kennung. Der Weg dahinter ist derselbe wie bei
/// der eigenen Oberfläche: die Nachricht geht durch POST /send bzw.
/// /group/send, damit es nur eine Stelle gibt, die Nachrichten erzeugt.
fn bridge_send(store: &Shared, to: &str, text: &str) -> Value {
    let Some((group, rest)) = bridge_target(to) else {
        return json!({"error": "unknown chat"});
    };
    if text.trim().is_empty() {
        return json!({"error": "empty message"});
    }
    if group {
        handle(
            Arc::clone(store),
            "POST",
            "/group/send",
            "",
            &json!({"group": rest, "text": text}),
        )
    } else {
        let Ok(contact_id) = rest.parse::<u32>() else {
            return json!({"error": "unknown chat"});
        };
        handle(
            Arc::clone(store),
            "POST",
            "/send",
            "",
            &json!({"contact": contact_id, "text": text}),
        )
    }
}

#[cfg(test)]
mod gruppenablehnung_tests {
    use super::*;
    use crate::store::{Einladungssitzung, PrivateGroup, Sitzungszustand};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const IHR: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const GRUPPE: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn speicher() -> Shared {
        let mut p = std::env::temp_dir();
        p.push("briar-gruppenablehnung.json");
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.create_identity("ich").unwrap();
        store.state.contacts.push(crate::store::Contact {
            id: 1,
            name: "Einladende".to_string(),
            author_id: IHR.to_string(),
            signature_public: IHR.to_string(),
            handshake_public: Some(IHR.to_string()),
            master_key: IHR.to_string(),
            alice: true,
            creation_period: 0,
            transports: BTreeMap::new(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: crate::store::kein_timer(),
            loesch_vorher: crate::store::keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
            anforderungs_runden: Default::default(),
        });
        let mut einladungen = BTreeMap::new();
        einladungen.insert(
            1u32,
            Einladungssitzung {
                letzte_eigene: None,
                letzte_fremde: Some("ff01".to_string()),
                eigener_zeitstempel: 1_700_000_000_000,
                einladungs_zeitstempel: 1_700_000_000_000,
                zustand: Sitzungszustand::Eingeladen,
            },
        );
        store.state.groups.push(PrivateGroup {
            id: GRUPPE.to_string(),
            name: "Testgruppe".to_string(),
            salt: "44".to_string(),
            creator_name: "Einladende".to_string(),
            creator_public: IHR.to_string(),
            creator_author_id: IHR.to_string(),
            joined: false,
            invited_by: Some(1),
            invite_timestamp: Some(1_700_000_000_000),
            invite_signature: None,
            member_names: BTreeMap::new(),
            last_read: 0,
            messages: Vec::new(),
            our_previous: None,
            einladungen,
            einladung_previous: None,
            aufgeloest: false,
            letztes_ereignis: None,
            contacts: vec![1],
            wartend: Vec::new(),
            verworfen: Vec::new(),
        });
        Arc::new(Mutex::new(store))
    }

    /// Eine Einladung abzulehnen heisst hier, die Gruppe zu entfernen -- auf
    /// der Leitung ist das ein LEAVE. Dessen Kennung MUSS in der Sitzung
    /// stehenbleiben: Briars Ersteller macht sie zur Vorbedingung des
    /// naechsten JOIN (isValidDependency). Stand dort weiter None, brach Briar
    /// die Sitzung nach einer zweiten Einladung ab und stellte die Gruppe fuer
    /// uns auf unsichtbar -- ohne Weg zurueck.
    #[test]
    fn ablehnen_merkt_sich_die_kennung_des_leave() {
        let store = speicher();
        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/group/remove",
            "",
            &json!({"group": GRUPPE}),
        );
        assert!(antwort.get("error").is_none(), "{}", antwort);

        let locked = store.lock().unwrap();
        let sitzung = locked
            .state
            .verlassene_einladungen
            .get(GRUPPE)
            .and_then(|m| m.get(&1))
            .expect("die Sitzung ueberlebt die Gruppe");
        let kennung = sitzung
            .letzte_eigene
            .clone()
            .expect("das LEAVE steht als letzte eigene Nachricht");

        // Und es ist wirklich die Kennung der Nachricht, die hinausgeht.
        let korb = &locked.state.contacts[0].outbox;
        assert!(
            korb.iter().any(|m| m.id == kennung),
            "die gemerkte Kennung liegt so auch im Korb: {:?}",
            korb.iter().map(|m| m.id.clone()).collect::<Vec<_>>()
        );
        assert_eq!(sitzung.eigener_zeitstempel, korb.iter().find(|m| m.id == kennung).unwrap().timestamp);
    }
}

#[cfg(test)]
mod gruppenversand_tests {
    use super::*;
    use crate::store::{Einladungssitzung, PrivateGroup, Sitzungszustand};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn kontakt(id: u32) -> crate::store::Contact {
        crate::store::Contact {
            id,
            name: format!("k{}", id),
            author_id: format!("{:064x}", id),
            signature_public: format!("{:064x}", id),
            handshake_public: None,
            master_key: format!("{:064x}", id),
            alice: true,
            creation_period: 0,
            transports: BTreeMap::new(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: crate::store::kein_timer(),
            loesch_vorher: crate::store::keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
            anforderungs_runden: Default::default(),
        }
    }

    /// Ein Beitrag geht an Mitglieder, nicht an offene Einladungen: fuer ein
    /// echtes Briar gibt es die Gruppe vor der Zusage nicht, es verwirft ohne
    /// Quittung, und der Korb schickte bis 0.39.0 in jeder Runde erneut.
    #[test]
    fn beitrag_geht_nicht_an_offene_einladungen() {
        let mut p = std::env::temp_dir();
        p.push("briar-gruppenversand.json");
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        let ich = store.create_identity("ich").unwrap();
        store.state.contacts.push(kontakt(1));
        store.state.contacts.push(kontakt(2));
        let gruppe = "cc".repeat(32);
        let mut einladungen = BTreeMap::new();
        let mut offen = Einladungssitzung::default();
        offen.zustand = Sitzungszustand::Eingeladen;
        einladungen.insert(1, offen);
        let mut drin = Einladungssitzung::default();
        drin.zustand = Sitzungszustand::Beigetreten;
        einladungen.insert(2, drin);
        store.state.groups.push(PrivateGroup {
            id: gruppe.clone(),
            name: "g".to_string(),
            salt: "00".repeat(32),
            creator_name: "ich".to_string(),
            creator_public: ich.signature_public.clone(),
            creator_author_id: ich.author_id.clone(),
            joined: true,
            invited_by: None,
            invite_timestamp: None,
            invite_signature: None,
            member_names: BTreeMap::new(),
            last_read: 0,
            // Unser eigenes JOIN: ohne das laesst /group/send nichts hinaus.
            messages: vec![GroupPost {
                id: "j1".to_string(),
                author_id: ich.author_id.clone(),
                author_name: "ich".to_string(),
                timestamp: 1_700_000_000_000,
                text: String::new(),
                body: String::new(),
                join: true,
            }],
            our_previous: Some("j1".to_string()),
            einladungen,
            einladung_previous: None,
            aufgeloest: false,
            letztes_ereignis: None,
            contacts: vec![1, 2],
            wartend: Vec::new(),
            verworfen: Vec::new(),
        });
        let shared: Shared = Arc::new(Mutex::new(store));
        let antwort = handle(
            Arc::clone(&shared),
            "POST",
            "/group/send",
            "",
            &json!({"group": gruppe, "text": "hallo"}),
        );
        assert!(antwort.get("error").is_none(), "{}", antwort);
        let s = shared.lock().unwrap();
        let im_korb = |id: u32| s.contact(id).unwrap().outbox.iter().filter(|m| m.group == gruppe).count();
        assert_eq!(im_korb(1), 0, "die offene Einladung bekommt nichts");
        assert_eq!(im_korb(2), 1, "das Mitglied bekommt den Beitrag");
    }
}

#[cfg(test)]
mod loeschen_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const IHR: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    /// Der Anhang liegt unter seiner eigenen Kennung im Korb. Wird die
    /// Nachricht geloescht, bevor sie hinaus ist, muss er mitgehen -- vorher
    /// ging er beim naechsten Treffen doch noch hinaus, als Bild ohne Text.
    #[test]
    fn geloeschte_nachricht_nimmt_ihren_anhang_aus_dem_korb() {
        let mut p = std::env::temp_dir();
        p.push("briar-loeschen-test.json");
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.create_identity("ich").unwrap();
        store.state.contacts.push(crate::store::Contact {
            id: 1,
            name: "Gegenueber".to_string(),
            author_id: IHR.to_string(),
            signature_public: IHR.to_string(),
            handshake_public: Some(IHR.to_string()),
            master_key: IHR.to_string(),
            alice: true,
            creation_period: 0,
            transports: BTreeMap::new(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: crate::store::kein_timer(),
            loesch_vorher: crate::store::keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
            anforderungs_runden: Default::default(),
        });
        {
            let c = store.contact_mut(1).unwrap();
            c.messages.push(crate::store::Message {
                id: "t1".to_string(),
                timestamp: 1,
                text: String::new(),
                outgoing: true,
                acked: false,
                attachment: None,
                attachment_type: None,
                anhaenge: vec![crate::store::Anhangskopf {
                    id: "a1".to_string(),
                    content_type: Some("text/plain".to_string()),
                }],
                loesch_dauer: None,
                loesch_frist: None,
            });
            for id in ["t1", "a1", "bleibt"] {
                c.outbox.push(OutMessage {
                    id: id.to_string(),
                    group: String::new(),
                    timestamp: 1,
                    body: String::new(),
                    acked: false,
                    intern: false,
                    loesch_dauer: None,
                });
            }
        }
        let shared: Shared = Arc::new(Mutex::new(store));
        let antwort = handle(
            Arc::clone(&shared),
            "POST",
            "/message/delete",
            "",
            &json!({"contact": 1, "ids": ["t1"]}),
        );
        assert_eq!(antwort["ok"], json!(true), "{}", antwort);
        let s = shared.lock().unwrap();
        let korb: Vec<&str> = s.contact(1).unwrap().outbox.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(korb, vec!["bleibt"]);
        assert!(s.contact(1).unwrap().messages.is_empty());
    }
}

#[cfg(test)]
mod zeitstempel_tests {
    use super::*;
    use std::sync::Mutex;

    /// Der Zeitstempel einer Privatnachricht rueckt ueber den zuletzt an diese
    /// Gegenseite gemeldeten hinaus. Sonst verwirft Briar unsere Zuenddauer,
    /// weil sie nicht neuer ist als die zuletzt gesehene.
    #[test]
    fn zeitstempel_rueckt_ueber_den_zuletzt_gemeldeten() {
        let mut p = std::env::temp_dir();
        p.push("briar-zeitstempel-test.json");
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.create_identity("ich").unwrap();
        store.state.contacts.push(crate::store::Contact {
            id: 1,
            name: "Gegenueber".to_string(),
            author_id: "22".to_string(),
            signature_public: "22".to_string(),
            handshake_public: None,
            master_key: "22".to_string(),
            alice: true,
            creation_period: 0,
            transports: Default::default(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: 60_000,
            loesch_vorher: crate::store::keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
            anforderungs_runden: Default::default(),
        });
        // Die Gegenseite hat zuletzt einen Stempel weit in der Zukunft
        // gesehen -- so sieht es aus, wenn unsere eigene Uhr nachgeht.
        let weit = now_ms() + 3_600_000;
        store.contact_mut(1).unwrap().loesch_stempel = weit;
        let store: Shared = Arc::new(Mutex::new(store));

        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/send",
            "",
            &json!({"contact": 1, "text": "hallo"}),
        );
        assert!(antwort.get("error").is_none(), "{}", antwort);

        let locked = store.lock().unwrap();
        let nachricht = locked.state.contacts[0]
            .messages
            .last()
            .expect("die Nachricht steht im Verlauf");
        assert!(
            nachricht.timestamp > weit,
            "{} muss ueber {} liegen",
            nachricht.timestamp,
            weit
        );
        assert_eq!(locked.state.contacts[0].loesch_stempel, nachricht.timestamp);
        assert_eq!(nachricht.loesch_dauer, Some(60_000));
    }
}

#[cfg(test)]
mod zeigen_tests {
    use super::*;
    use crate::store::{Contact, Einladungssitzung, PrivateGroup, Sitzungszustand};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    const EINLADENDE: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const MITGLIED: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const FREMDE: &str = "6666666666666666666666666666666666666666666666666666666666666666";
    const GRUPPE: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn kontakt(id: u32, name: &str, autor: &str) -> Contact {
        Contact {
            id,
            name: name.to_string(),
            author_id: autor.to_string(),
            signature_public: autor.to_string(),
            handshake_public: Some(autor.to_string()),
            master_key: autor.to_string(),
            alice: true,
            creation_period: 0,
            transports: BTreeMap::new(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: crate::store::kein_timer(),
            loesch_vorher: crate::store::keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
            anforderungs_runden: Default::default(),
        }
    }

    /// Wir sind eingeladen worden von Kontakt 1. Kontakt 2 ist auch in der
    /// Gruppe, hat uns aber nicht eingeladen -- das ist die PEER-Rolle, und
    /// nur dort gibt es etwas zu zeigen. Kontakt 3 ist gar nicht drin.
    /// Je Pruefung eine eigene Datei: sie laufen nebeneinander, und drei
    /// Pruefungen auf demselben Pfad loeschen einander die Datei unter den
    /// Fuessen weg.
    fn speicher(wer: &str) -> Shared {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-zeigen-{}.json", wer));
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.create_identity("ich").unwrap();
        store.state.contacts.push(kontakt(1, "Einladende", EINLADENDE));
        store.state.contacts.push(kontakt(2, "Mitglied", MITGLIED));
        store.state.contacts.push(kontakt(3, "Fremde", FREMDE));

        let mut einladungen = BTreeMap::new();
        einladungen.insert(
            1u32,
            Einladungssitzung {
                letzte_eigene: Some("aa01".to_string()),
                letzte_fremde: Some("ff01".to_string()),
                eigener_zeitstempel: 1_700_000_000_000,
                einladungs_zeitstempel: 1_700_000_000_000,
                zustand: Sitzungszustand::Beigetreten,
            },
        );
        let mut mitglieder = BTreeMap::new();
        mitglieder.insert(EINLADENDE.to_string(), "Einladende".to_string());
        mitglieder.insert(MITGLIED.to_string(), "Mitglied".to_string());

        store.state.groups.push(PrivateGroup {
            id: GRUPPE.to_string(),
            name: "Testgruppe".to_string(),
            salt: "44".to_string(),
            creator_name: "Einladende".to_string(),
            creator_public: EINLADENDE.to_string(),
            creator_author_id: EINLADENDE.to_string(),
            joined: true,
            invited_by: Some(1),
            invite_timestamp: Some(1_700_000_000_000),
            invite_signature: None,
            member_names: mitglieder,
            last_read: 0,
            messages: Vec::new(),
            our_previous: Some("aa02".to_string()),
            einladungen,
            einladung_previous: None,
            aufgeloest: false,
            letztes_ereignis: None,
            contacts: vec![1, 2],
            wartend: Vec::new(),
            verworfen: Vec::new(),
        });
        Arc::new(Mutex::new(store))
    }

    #[test]
    fn nur_die_peer_rolle_laesst_sich_zeigen() {
        let store = speicher("rolle");
        let locked = store.lock().unwrap();
        // Kontakt 1 hat uns eingeladen -- das laeuft ueber die INVITEE-Rolle.
        assert!(net::zeigbarkeit(&locked, GRUPPE, 1).is_err());
        // Kontakt 2 ist Mitglied, ohne dass einer den anderen eingeladen hat.
        assert_eq!(net::zeigbarkeit(&locked, GRUPPE, 2), Ok(()));
        // Kontakt 3 ist gar nicht in der Gruppe.
        assert!(net::zeigbarkeit(&locked, GRUPPE, 3).is_err());
    }

    #[test]
    fn die_liste_nennt_genau_den_einen() {
        let store = speicher("liste");
        let antwort = handle(
            Arc::clone(&store),
            "GET",
            "/group/messages",
            &format!("group={}", GRUPPE),
            &json!({}),
        );
        let zeigbar = antwort["revealable"].as_array().unwrap();
        assert_eq!(zeigbar.len(), 1, "{}", antwort);
        assert_eq!(zeigbar[0]["id"], 2);
        assert!(antwort["revealed"].as_array().unwrap().is_empty());
    }

    /// Nach dem Zeigen liegt eine eigene Nachricht in der Sitzung -- und ein
    /// zweites Mal geht nicht mehr, sonst gabelte es die Kette.
    #[test]
    fn zeigen_schickt_ein_join_und_zaehlt_danach_als_gezeigt() {
        let store = speicher("join");
        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/group/reveal",
            "",
            &json!({"group": GRUPPE, "contact": 2}),
        );
        assert!(antwort.get("error").is_none(), "{}", antwort);

        let locked = store.lock().unwrap();
        let sitzung = locked.sitzung(GRUPPE, 2).expect("die Sitzung steht");
        assert!(
            sitzung.letzte_eigene.is_some(),
            "das JOIN muss in der Sitzung stehen"
        );
        assert!(
            locked
                .state
                .contacts
                .iter()
                .any(|c| c.id == 2 && !c.outbox.is_empty()),
            "das JOIN muss in der Ausgangspost liegen"
        );
        assert_eq!(net::zeigbarkeit(&locked, GRUPPE, 2), Err("schon gezeigt"));
    }
}

#[cfg(test)]
mod einstellungs_tests {
    use super::*;
    use std::sync::Mutex;

    fn speicher(wer: &str) -> (Shared, std::path::PathBuf) {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-einstellungen-{}-{}.json", wer, std::process::id()));
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.create_identity("ich").unwrap();
        (Arc::new(Mutex::new(store)), p)
    }

    #[test]
    fn status_zeigt_vorschau_zuerst_aus() {
        let (store, p) = speicher("aus");
        let antwort = handle(Arc::clone(&store), "GET", "/status", "", &Value::Null);
        assert_eq!(antwort["notificationPreview"], json!(false));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn settings_schaltet_vorschau_ein_und_status_zeigt_es() {
        let (store, p) = speicher("ein");
        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/settings",
            "",
            &json!({"notificationPreview": true}),
        );
        assert_eq!(antwort, json!({"ok": true}));
        let status = handle(Arc::clone(&store), "GET", "/status", "", &Value::Null);
        assert_eq!(status["notificationPreview"], json!(true));
        // Und es steht auch in der Datei, nicht nur im Speicher.
        assert!(Store::open(&p, 7327).unwrap().state.notification_preview);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn settings_schaltet_vorschau_wieder_aus() {
        let (store, p) = speicher("wieder");
        store.lock().unwrap().state.notification_preview = true;
        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/settings",
            "",
            &json!({"notificationPreview": false}),
        );
        assert_eq!(antwort, json!({"ok": true}));
        assert!(!store.lock().unwrap().state.notification_preview);
        let _ = std::fs::remove_file(&p);
    }

    /// Kein Wahrheitswert, keine Aenderung -- "false" als Zeichenkette waere
    /// sonst wahr oder falsch, je nachdem, wie man es liest.
    #[test]
    fn settings_verwirft_keinen_wahrheitswert() {
        let (store, p) = speicher("falsch");
        store.lock().unwrap().state.notification_preview = true;
        let antwort = handle(
            Arc::clone(&store),
            "POST",
            "/settings",
            "",
            &json!({"notificationPreview": "false"}),
        );
        assert!(antwort.get("error").is_some(), "{}", antwort);
        assert!(store.lock().unwrap().state.notification_preview);
        let _ = std::fs::remove_file(&p);
    }

    /// Das Aufraeumen beim Kontoloeschen, ohne den Dienst zu beenden: in einem
    /// Wegwerfordner mit allem, was dort liegt.
    #[test]
    fn konto_aufraeumen_entfernt_alle_dateien_des_kontos() {
        let mut ordner = std::env::temp_dir();
        ordner.push(format!("briar-aufraeumen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ordner);
        std::fs::create_dir_all(ordner.join("attachments")).unwrap();
        std::fs::create_dir_all(ordner.join("tor")).unwrap();
        let zustand = ordner.join("state.json");
        for datei in [
            zustand.clone(),
            zustand.with_extension("tmp"),
            ordner.join(GEHEIMNIS_DATEI),
            ordner.join(SOCKEL_DATEI),
            ordner.join("briard.log"),
            ordner.join("briard.log.1"),
            ordner.join("attachments").join("a1"),
            ordner.join("tor").join("torrc"),
        ] {
            std::fs::write(&datei, b"x").unwrap();
        }
        // Was nicht zum Konto gehoert, bleibt.
        std::fs::write(ordner.join("fremd.txt"), b"x").unwrap();

        konto_aufraeumen(&zustand);

        let uebrig: Vec<String> = std::fs::read_dir(&ordner)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(uebrig, vec!["fremd.txt".to_string()]);
        let _ = std::fs::remove_dir_all(&ordner);
    }
}
