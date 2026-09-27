//! The transports and the connection logic on top of them.
//!
//! Briar reaches a contact it has only a link for through a rendezvous over
//! Tor. That is here too: `run_rendezvous` below, the arithmetic in
//! `rendezvous.rs`. Beside it a peer's ip:port, Bluetooth address or onion
//! address can still go in next to the link, and then we dial that straight
//! away instead of waiting for a meeting.
//! Everything above the socket -- tags, stream encryption, handshake, contact
//! exchange, sync -- is Briar's.

use crate::bt;
use crate::tor;
use crate::crypto::SecretKey;
use crate::exchange::{self, ContactInfo};
use crate::groups::{self, Author, GroupMessage};
use crate::handshake;
use crate::ids;
use crate::record::read_record;
use crate::store::{key_from_hex, Contact, GroupPost, Message, OutMessage, Store, TransportState};
use crate::stream::{StreamReader, StreamWriter};
use crate::sync;
use crate::transport::*;
use crate::util::{from_hex, now_ms, to_hex};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How many stream numbers ahead of the expected one a tag is still
/// recognised -- Briar's reordering window.
const WINDOW: u64 = 32;
// Wie in Briars LanTcpPluginFactory. Zusammen mit dem Sieb in dial() faellt
// der schlimmste Fall von fuenf vollen Wartezeiten auf wenige Sekunden.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub type Shared = Arc<Mutex<Store>>;

pub fn log(message: &str) {
    println!("[{}] {}", now_ms() / 1000, message);
    let _ = std::io::stdout().flush();
}

/// A connection, over whichever transport carries it. Both are sockets, and
/// everything above this point only reads and writes.
pub enum Conn {
    Tcp(TcpStream),
    Bluetooth(UnixStream),
}

impl Conn {
    pub fn try_clone(&self) -> std::io::Result<Conn> {
        match self {
            Conn::Tcp(s) => Ok(Conn::Tcp(s.try_clone()?)),
            Conn::Bluetooth(s) => Ok(Conn::Bluetooth(s.try_clone()?)),
        }
    }

    fn set_timeouts(&self) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => {
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))
            }
            Conn::Bluetooth(s) => {
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                s.set_write_timeout(Some(IO_TIMEOUT))
            }
        }
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.read(buf),
            Conn::Bluetooth(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Tcp(s) => s.write(buf),
            Conn::Bluetooth(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Tcp(s) => s.flush(),
            Conn::Bluetooth(s) => s.flush(),
        }
    }
}

enum Recognised {
    Pending {
        index: usize,
        header_key: SecretKey,
        stream_number: u64,
        /// Der Abschnitt, zu dem die erkannte Marke gehoert -- nicht
        /// unbedingt der laufende: erkannt werden voriger, jetziger und
        /// naechster, und das Fenster gehoert zum Abschnitt der Marke.
        period: u64,
        alice: bool,
    },
    Contact {
        id: u32,
        header_key: SecretKey,
        stream_number: u64,
        period: u64,
    },
}

/// Handshake root key and our role for a pending contact.
/// Die beiden Rendezvous-Saaten fuer einen schwebenden Kontakt: erst unsere,
/// dann seine. Wer von beiden Alice ist, entscheidet derselbe Vergleich der
/// Handschlagschluessel wie ueberall sonst.
fn rendezvous_saaten(store: &Store, their_public_hex: &str) -> Option<([u8; 32], [u8; 32])> {
    let identity = store.identity()?;
    let their_public = key_from_hex(their_public_hex);
    let our_private = key_from_hex(&identity.handshake_private);
    let our_public = key_from_hex(&identity.handshake_public);
    let static_master = derive_static_master_key(&their_public, &our_private, &our_public)?;
    let rk = crate::rendezvous::rendezvous_key(&static_master);
    Some(crate::rendezvous::own_and_peer_seed(
        &rk,
        TOR_TRANSPORT_ID,
        is_alice(&their_public, &our_public),
    ))
}

fn pending_keys(store: &Store, their_public_hex: &str) -> Option<(SecretKey, bool)> {
    let identity = store.identity()?;
    let their_public = key_from_hex(their_public_hex);
    let our_private = key_from_hex(&identity.handshake_private);
    let our_public = key_from_hex(&identity.handshake_public);
    let static_master = derive_static_master_key(&their_public, &our_private, &our_public)?;
    let root = derive_handshake_root_key(&static_master, true);
    Some((root, is_alice(&their_public, &our_public)))
}

fn recognise_tag(store: &Store, transport_id: &str, tag: &[u8]) -> Option<Recognised> {
    let period = current_time_period();
    let periods = [period.saturating_sub(1), period, period + 1];
    for (index, pending) in store.state.pending.iter().enumerate() {
        let (root, alice) = match pending_keys(store, &pending.public_key) {
            Some(v) => v,
            None => continue,
        };
        // Derselbe Fusspunkt wie beim Kontakt weiter unten: die Gegenseite
        // zaehlt ihre Handschlagversuche hoch, also darf unser Fenster nicht
        // auf null stehen bleiben -- sonst ist ihre Nummer 32 in diesem
        // Abschnitt nicht mehr zu erkennen.
        let base = pending
            .transport(transport_id)
            .map(|t| t.in_stream.clone())
            .unwrap_or_default();
        for p in periods {
            // Incoming keys belong to the peer's role
            let keys = derive_handshake_keys(transport_id, &root, p, !alice);
            let first = *base.get(&p.to_string()).unwrap_or(&0);
            for stream_number in first..first + WINDOW {
                if encode_tag(&keys.tag_key, PROTOCOL_VERSION, stream_number) == tag[..] {
                    return Some(Recognised::Pending {
                        index,
                        header_key: keys.header_key,
                        stream_number,
                        period: p,
                        alice,
                    });
                }
            }
        }
    }
    for contact in &store.state.contacts {
        let root = contact.master_key_bytes();
        let base = contact
            .transport(transport_id)
            .map(|t| t.in_stream.clone())
            .unwrap_or_default();
        for p in periods {
            let keys = derive_rotation_keys(
                transport_id,
                &root,
                contact.creation_period,
                p,
                !contact.alice,
            );
            let first = *base.get(&p.to_string()).unwrap_or(&0);
            for stream_number in first..first + WINDOW {
                if encode_tag(&keys.tag_key, PROTOCOL_VERSION, stream_number) == tag[..] {
                    return Some(Recognised::Contact {
                        id: contact.id,
                        header_key: keys.header_key,
                        stream_number,
                        period: p,
                    });
                }
            }
        }
    }
    None
}

/// Briars eigene Pruefung (`LanTcpPlugin.isAcceptableAddress`): brauchbar ist
/// eine IPv4-Adresse aus einem link-lokalen oder standortlokalen Netz. Eine
/// oeffentliche Adresse -- die des Mobilfunks vor allem -- nuetzt einem
/// Gegenueber im selben Netz nichts.
fn reachable_by_a_contact(o: [u8; 4]) -> bool {
    (o[0] == 169 && o[1] == 254)
        || o[0] == 10
        || (o[0] == 172 && (16..32).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
}

/// Jede IPv4-Adresse dieses Geraets, unter der ein Kontakt im selben Netz es
/// erreichen koennte. Die laengste Netzmaske steht vorne: das engere Netz ist
/// das wahrscheinlichere. Frueher stand hier eine einzige Adresse, die eine
/// UDP-Verbindung zum fest eingetragenen 192.168.1.1 verriet -- ausserhalb des
/// Heimnetzes war das die Mobilfunkadresse, und die Gegenseite stand ohne Weg
/// da.
/// Wie `local_ips()`, aber mit der Netzmaskenlaenge -- die wird beim
/// Aufzaehlen ohnehin berechnet und war bisher nur zum Sortieren da.
/// Alle brauchbaren eigenen IPv4-Netze, engste Maske zuerst -- Adresse und
/// Maskenlaenge. `local_ips()` setzt darauf auf; die Maskenlaenge wird beim
/// Aufzaehlen ohnehin berechnet und war bisher nur zum Sortieren da, wird
/// beim Waehlen aber gebraucht.
pub fn local_nets() -> Vec<(std::net::Ipv4Addr, u32)> {
    let mut found: Vec<(u32, std::net::Ipv4Addr)> = Vec::new();
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return Vec::new();
        }
        let mut cur = list;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null()
                || ifa.ifa_flags & libc::IFF_UP as u32 == 0
                || ifa.ifa_flags & libc::IFF_LOOPBACK as u32 != 0
                || (*ifa.ifa_addr).sa_family != libc::AF_INET as libc::sa_family_t
            {
                continue;
            }
            let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
            let octets = addr.sin_addr.s_addr.to_ne_bytes();
            if !reachable_by_a_contact(octets) {
                continue;
            }
            // Ohne Netzmaske zaehlt die Adresse trotzdem, nur eben zuletzt.
            let prefix = if ifa.ifa_netmask.is_null() {
                0
            } else {
                let mask = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                mask.sin_addr.s_addr.count_ones()
            };
            // Dieselbe Adresse kann mit mehreren Masken eingetragen sein
            // (Mobilfunk meldet hier /8 und /24). Es zaehlt die engste.
            let ip = std::net::Ipv4Addr::from(octets);
            match found.iter_mut().find(|(_, a)| *a == ip) {
                Some(seen) => seen.0 = seen.0.max(prefix),
                None => found.push((prefix, ip)),
            }
        }
        libc::freeifaddrs(list);
    }
    // Wie bei Briar: nur nach Maskenlaenge, und stabil -- bei gleich engen
    // Netzen bleibt die Reihenfolge des Kernels. Welches von zwei gleich
    // engen privaten Netzen das richtige ist, sagt die Adresse nicht; das
    // entscheidet beim Waehlen der erste, der antwortet.
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found.into_iter().map(|(prefix, ip)| (ip, prefix)).collect()
}

/// Jede IPv4-Adresse dieses Geraets, unter der ein Kontakt im selben Netz es
/// erreichen koennte, engste Maske zuerst.
pub fn local_ips() -> Vec<String> {
    local_nets().into_iter().map(|(ip, _)| ip.to_string()).collect()
}

/// Die vorderste unserer Adressen -- fuer die Statusanzeige, die nur eine
/// zeigen kann.
pub fn local_ip() -> Option<String> {
    local_ips().into_iter().next()
}

/// Briars Obergrenze fuer den Wert einer Transporteigenschaft
/// (MAX_PROPERTY_LENGTH), gemessen in UTF-8-Bytes. Das ist keine Hoeflichkeit,
/// sondern eine Protokollgrenze: der Pruefer auf der Gegenseite laeuft ueber
/// **jede** eingehende Eigenschaftsnachricht und verwirft bei Ueberlaenge die
/// ganze Nachricht, nicht nur den zu langen Wert. Eine unbegrenzte Liste macht
/// uns damit fuer echtes Briar unsichtbar.
const MAX_PROPERTY_LENGTH: usize = 100;

/// Ein `ip:port` streng lesen. Streng heisst vor allem: die Adresse wird als
/// Zahlenform geparst und nie aufgeloest. Briar baut denselben Schutz mit
/// einem Punkt-Quad-Muster ein ("Ensure getByName() won't perform a DNS
/// lookup") -- sonst kann ein Kontakt uns mit einer gemeldeten Adresse zu
/// einer Namensabfrage verleiten.
fn parse_ip_port(entry: &str) -> Option<(std::net::Ipv4Addr, u16)> {
    let (host, port) = entry.trim().rsplit_once(':')?;
    let address: std::net::Ipv4Addr = host.trim().parse().ok()?;
    let port: u16 = port.trim().parse().ok()?;
    if port == 0 {
        return None;
    }
    Some((address, port))
}

/// Eine gemeldete Liste, wie wir sie aufbewahren: nur lesbare `ip:port`
/// bleiben, die Reihenfolge bleibt unangetastet -- die Gegenseite hat ihr
/// engstes Netz nach vorne gestellt. Ein kaputtes Stueck wird still
/// uebersprungen und verwirft nie die ganze Liste.
fn clean_address_list(list: &str) -> String {
    list.split(',')
        .filter_map(|e| parse_ip_port(e).map(|(a, p)| format!("{}:{}", a, p)))
        .collect::<Vec<_>>()
        .join(",")
}

/// Die eigenen Adressen ins Gedaechtnis aufnehmen, neueste zuerst, und auf
/// Briars Laengengrenze kuerzen. Gibt zurueck, ob eine davon neu war -- nur
/// dann muessen die Kontakte etwas erfahren. Ein blosses Umsortieren zwischen
/// zwei bekannten Netzen bleibt fuer sie unsichtbar, genau wie bei Briar.
pub fn note_local_addresses(state: &mut crate::store::State) -> bool {
    let port = state.listen_port;
    let mut neu = false;
    // Rueckwaerts einfuegen, damit am Ende die engste Maske vorne steht:
    // local_ips() liefert sie bereits in dieser Reihenfolge.
    for ip in local_ips().into_iter().rev() {
        let eintrag = format!("{}:{}", ip, port);
        if let Some(stelle) = state.lan_recent.iter().position(|e| *e == eintrag) {
            state.lan_recent.remove(stelle);
        } else {
            neu = true;
        }
        state.lan_recent.insert(0, eintrag);
    }
    // Am Ende kuerzen, bis die verbundene Zeichenkette hineinpasst. Rusts
    // String::len() zaehlt UTF-8-Bytes und misst damit genau das, was Briars
    // Pruefer misst.
    while state.lan_recent.len() > 1
        && state.lan_recent.join(",").len() > MAX_PROPERTY_LENGTH
    {
        state.lan_recent.pop();
    }
    neu
}

/// Was die Kontakte zu sehen bekommen: die zuletzt verteilte Liste. Sie
/// aendert sich nur, wenn eine neue Adresse dazugekommen ist -- ein
/// Umsortieren bleibt oertlich.
fn veroeffentlichte(state: &crate::store::State) -> Vec<String> {
    if state.lan_published.is_empty() {
        state.lan_recent.clone()
    } else {
        state.lan_published.split(',').map(str::to_string).collect()
    }
}

/// Sind ausser den LAN-Adressen keine anderen Eigenschaften dabei? Nur dann
/// darf eine unveraenderte Adressliste das Melden verhindern -- eine neue
/// Onion- oder Bluetooth-Adresse muss immer durch.

fn local_properties(
    port: u16,
    recent: &[String],
    recent6: &[String],
    bluetooth: bool,
    bt_uuid: Option<&str>,
    onion: Option<String>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut props = BTreeMap::new();
    let mut lan = BTreeMap::new();
    lan.insert("port".to_string(), port.to_string());
    // Die zuletzt benutzten Adressen, neueste zuerst -- nicht die gerade
    // vorhandenen. So bleibt die Heimadresse eingetragen, wenn man unterwegs
    // ist, und passt beim Heimkommen wieder.
    if !recent.is_empty() {
        lan.insert("ipPorts".to_string(), recent.join(","));
    }
    // IPv6 als eigene Eigenschaft, wie bei Briar: je 32 Hexzeichen, ohne
    // Port -- der steht schon in "port". Der Zonenindex bleibt absichtlich
    // weg, ihn bestimmt die waehlende Seite selbst.
    if !recent6.is_empty() {
        lan.insert("ipv6".to_string(), recent6.join(","));
    }
    props.insert(LAN_TRANSPORT_ID.to_string(), lan);
    if let Some(onion) = onion.filter(|o| !o.is_empty()) {
        let mut values = BTreeMap::new();
        values.insert("onion3".to_string(), onion);
        props.insert(TOR_TRANSPORT_ID.to_string(), values);
    }
    if bluetooth {
        if let Some(address) = bt::local_address() {
            let mut values = BTreeMap::new();
            values.insert("address".to_string(), address);
            // Die UUID, unter der wir zu finden sind. Ohne sie sucht ein
            // echtes Briar gar nicht erst: es bricht ab, wenn die
            // Eigenschaft fehlt (AbstractBluetoothPlugin.connect).
            if let Some(uuid) = bt_uuid {
                values.insert("uuid".to_string(), uuid.to_string());
            }
            // Der feste Kanal wird weiter mitgesagt, aber nur als Rueckfall:
            // unsere eigenen aelteren Fassungen melden keine UUID und suchen
            // nicht per SDP, die finden uns sonst nicht mehr. Wer die UUID
            // liest, schlaegt den Kanal ohnehin nachher per SDP nach.
            values.insert("channel".to_string(), bt::CHANNEL.to_string());
            props.insert(BLUETOOTH_TRANSPORT_ID.to_string(), values);
        }
    }
    props
}

/// Raises a notification for an incoming message -- on Sailfish; everywhere
/// else this does nothing, and the interface shows the message as before.
#[cfg(feature = "sfos")]
fn notify_chat(key: String, summary: String, body: String, group: bool) {
    // Off the sync thread: the notification talks to lipstick over D-Bus,
    // and a slow answer must not hold up the connection.
    std::thread::spawn(move || {
        crate::notify::message(&key, &summary, &body, &key, group, "Antworten");
    });
}

#[cfg(not(feature = "sfos"))]
fn notify_chat(_key: String, _summary: String, _body: String, _group: bool) {}

/// A short stand-in for the whole address set, to notice when it changes.
fn properties_fingerprint(
    properties: &BTreeMap<String, BTreeMap<String, String>>,
) -> String {
    let mut text = String::new();
    for (transport, values) in properties {
        text.push_str(transport);
        for (key, value) in values {
            text.push('\u{1}');
            text.push_str(key);
            text.push('=');
            text.push_str(value);
        }
        text.push('\u{2}');
    }
    to_hex(&crate::crypto::hash("org.briarproject.bramble/PROPERTIES", &[text.as_bytes()]))
}

/// The address to dial for a peer: what it advertised, falling back to the
/// address the connection came from plus its advertised port.
fn addresses_from_properties(
    properties: &BTreeMap<String, BTreeMap<String, String>>,
    peer_ip: Option<&str>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(lan) = properties.get(LAN_TRANSPORT_ID) {
        let mut address = None;
        if let Some(ip_ports) = lan.get("ipPorts") {
            // Die ganze Liste, nicht nur der erste Eintrag: beim Waehlen wird
            // jeder der Reihe nach versucht.
            let list = clean_address_list(ip_ports);
            if !list.is_empty() {
                address = Some(list);
            }
        }
        if address.is_none() {
            if let (Some(port), Some(ip)) = (lan.get("port"), peer_ip) {
                address = Some(format!("{}:{}", ip, port));
            }
        }
        if let Some(address) = address {
            out.insert(LAN_TRANSPORT_ID.to_string(), address);
        }
    }
    if let Some(bluetooth) = properties.get(BLUETOOTH_TRANSPORT_ID) {
        if let Some(address) = bluetooth.get("address") {
            out.insert(BLUETOOTH_TRANSPORT_ID.to_string(), address.clone());
        }
    }
    if let Some(onion) = properties.get(TOR_TRANSPORT_ID) {
        if let Some(address) = onion.get("onion3") {
            out.insert(TOR_TRANSPORT_ID.to_string(), address.clone());
        }
    }
    out
}

/// The peer's tag cannot be read before the handshake starts: whoever dialled
/// may have to speak first, and reading eagerly deadlocks both ends. So the
/// tag is read on the first actual read, and the stream keys are picked then.
///
/// Die Regel gilt fuer beide Richtungen und darf nicht aufgeweicht werden:
/// jede Seite schreibt ihren Stromkopf, bevor sie das erste Byte der anderen
/// erwartet -- ausgehend vor dem Lesen der Kennung, eingehend danach. Wird
/// hier eifrig gelesen, oder faellt eines der beiden fuehrenden flush() weg,
/// stehen wieder beide Seiten.
struct LazyHandshakeReader {
    conn: Conn,
    transport_id: String,
    root: SecretKey,
    peer_is_alice: bool,
    /// Zum Nachziehen des Fensters. Wenn wir selbst gewaehlt haben, ist die
    /// hier erkannte Nummer der einzige Ort, an dem wir erfahren, wie weit
    /// die Gegenseite gezaehlt hat.
    store: Shared,
    /// Der Wartende wird ueber seinen Handschlagschluessel nachgeschlagen,
    /// nicht ueber die Stelle in `state.pending`: die verschiebt sich, wenn
    /// der Benutzer einen anderen Wartenden streicht.
    public_key: String,
    stream: Option<StreamReader<Conn>>,
}

impl Read for LazyHandshakeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.stream.is_none() {
            let mut tag = [0u8; TAG_LEN];
            self.conn.read_exact(&mut tag)?;
            let period = current_time_period();
            let mut found = None;
            // Der Fusspunkt je Abschnitt, genau wie in recognise_tag.
            let base = {
                let store = self.store.lock().unwrap();
                store
                    .state
                    .pending
                    .iter()
                    .find(|p| p.public_key == self.public_key)
                    .and_then(|p| p.transport(&self.transport_id))
                    .map(|t| t.in_stream.clone())
                    .unwrap_or_default()
            };
            for p in [period.saturating_sub(1), period, period + 1] {
                let keys =
                    derive_handshake_keys(&self.transport_id, &self.root, p, self.peer_is_alice);
                let first = *base.get(&p.to_string()).unwrap_or(&0);
                for stream_number in first..first + WINDOW {
                    if encode_tag(&keys.tag_key, PROTOCOL_VERSION, stream_number) == tag {
                        found = Some((keys.header_key, stream_number, p));
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
            }
            let (header_key, stream_number, gesehen_in) =
                found.ok_or_else(|| bad("the peer's handshake tag was not recognised"))?;
            // Auch die antwortende Seite zaehlt bei jedem Versuch hoch, den
            // gescheiterten eingeschlossen -- also nachziehen, sonst laeuft
            // sie uns aus dem Fenster.
            fenster_vermerken(
                &self.store,
                &self.public_key,
                &self.transport_id,
                gesehen_in,
                stream_number,
            );
            self.stream = Some(StreamReader::new(
                self.conn.try_clone()?,
                header_key,
                stream_number,
            ));
        }
        self.stream.as_mut().unwrap().read(buf)
    }
}

pub struct Node {
    pub store: Shared,
}

impl Node {
    pub fn new(store: Shared) -> Node {
        Node { store }
    }

    pub fn listen_port(&self) -> u16 {
        self.store.lock().unwrap().state.listen_port
    }

    /// Accepts incoming LAN connections forever.
    /// Accepts incoming LAN connections. Binds again and again rather than
    /// giving up: the port can be busy for a moment after a restart (a
    /// socket in TIME_WAIT, an old daemon still dying), and a daemon without
    /// a listener is deaf until someone restarts it by hand.
    /// Derselbe Dienst noch einmal fuer link-lokales IPv6. Scheitert das
    /// Binden -- etwa weil der Kern ohne IPv6 laeuft --, bleibt es dabei und
    /// der IPv4-Weg traegt allein.
    pub fn run_listener6(&self, port: u16) {
        let lauscher = match bind_listener6(port) {
            Ok(l) => l,
            Err(e) => {
                log(&format!("no IPv6 listener on port {}: {}", port, e));
                return;
            }
        };
        log(&format!("listening on port {} over IPv6", port));
        for socket in lauscher.incoming() {
            match socket {
                Ok(socket) => {
                    let peer_ip = socket.peer_addr().ok().map(|a| a.ip().to_string());
                    self.spawn_incoming(Conn::Tcp(socket), LAN_TRANSPORT_ID, peer_ip);
                }
                Err(e) => {
                    log(&format!("IPv6 accept failed: {}", e));
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        }
    }

    pub fn run_listener(&self) {
        let port = self.listen_port();
        let mut complained = false;
        loop {
            let listener = match TcpListener::bind(("0.0.0.0", port)) {
                Ok(l) => l,
                Err(e) => {
                    // Only the first failure is logged; the retries are not
                    // news and would bury everything else.
                    if !complained {
                        log(&format!("cannot listen on port {} yet: {}", port, e));
                        complained = true;
                    }
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            complained = false;
            log(&format!("listening on port {}", port));
            // Beim Binden die eigenen Adressen ins Gedaechtnis nehmen -- das
            // ist Briars Zeitpunkt dafuer. Ohne das fuellt es sich erst beim
            // ersten Abgleich, und ein Geraet ohne Kontaktverkehr haette gar
            // keins.
            {
                let mut store = self.store.lock().unwrap();
                let v4 = note_local_addresses(&mut store.state);
                let v6 = note_local_addresses6(&mut store.state);
                if v4 || v6 {
                    let _ = store.save();
                }
            }
            // The socket is bound to 0.0.0.0, so it survives a change of
            // address; only a broken socket brings us back to binding.
            let mut failures = 0;
            for socket in listener.incoming() {
                match socket {
                    Ok(socket) => {
                        failures = 0;
                        let peer_ip = socket.peer_addr().ok().map(|a| a.ip().to_string());
                        self.spawn_incoming(Conn::Tcp(socket), LAN_TRANSPORT_ID, peer_ip);
                    }
                    Err(e) => {
                        log(&format!("accept failed: {}", e));
                        failures += 1;
                        if failures >= 3 {
                            break;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            log("the listening socket is gone -- binding again");
        }
    }

    /// Publishes the hidden service and accepts what comes through it.
    /// Without a Tor running on the device this simply does nothing.
    /// Das Rendezvous: schwebende Kontakte treffen, von denen wir nur den
    /// Link haben.
    ///
    /// Beide Seiten leiten aus dem gemeinsamen Geheimnis dieselben zwei
    /// Saaten ab, machen daraus je einen versteckten Dienst und treffen sich
    /// dort -- ohne dass je eine Adresse ausgetauscht wurde. Das ist der
    /// einzige Weg, mit einem echten Briar einen Kontakt anzulegen: dessen
    /// Oberflaeche bietet das Eintippen einer Adresse gar nicht an.
    ///
    /// Laeuft in einem eigenen Faden und im Minutentakt, wie Briars
    /// RendezvousPoller. Nach zwei Tagen gilt ein schwebender Kontakt als
    /// gescheitert und wird nicht mehr versucht.
    /// Briars Treffpunkt im Tor-Netz: einen Kontakt anlegen, ohne dass eine
    /// Seite die Adresse der anderen kennt.
    ///
    /// Die Steuerverbindung wird ueber die ganze Laufzeit gehalten, und das
    /// ist der Kern der Sache: ein Dienst aus ADD_ONION ohne `Flags=Detach`
    /// lebt genau so lange wie die Verbindung, die ihn angelegt hat. Stand
    /// `tor::connect()` im Schleifenrumpf, war der Treffpunkt wieder weg,
    /// bevor die Gegenseite ihn suchen konnte -- und weil er als
    /// "veroeffentlicht" vermerkt war, wurde er nie wieder angemeldet.
    pub fn run_rendezvous(&self, tor_port: u16) {
        let mut steuerung: Option<tor::Tor> = None;
        // Schwebender Kontakt -> Kennung des Dienstes, den Tor dafuer angelegt
        // hat. Gilt nur fuer die gerade gehaltene Verbindung: faellt sie,
        // fallen alle Dienste, also auch alles, was hier steht.
        let mut veroeffentlicht: BTreeMap<String, String> = BTreeMap::new();
        loop {
            std::thread::sleep(Duration::from_millis(
                crate::rendezvous::POLLING_INTERVAL_MS,
            ));
            // Wer einen Treffpunkt haben soll -- und, davon getrennt, wofuer
            // sich die Saaten gerade ableiten lassen. Getrennt, damit ein
            // Aussetzer beim Ableiten keinen Treffpunkt abraeumt, auf den noch
            // gewartet wird.
            let (tor_an, soll, arbeit) = {
                let store = self.store.lock().unwrap();
                let jetzt = crate::util::now_ms();
                let soll: std::collections::BTreeSet<String> = store
                    .state
                    .pending
                    .iter()
                    .filter(|p| {
                        // Wer schon eine Adresse hat, braucht kein Treffen.
                        p.onion.is_none()
                            && p.address.is_none()
                            && jetzt.saturating_sub(p.added)
                                < crate::rendezvous::TIMEOUT_MS
                    })
                    .map(|p| p.public_key.clone())
                    .collect();
                let arbeit: Vec<(String, [u8; 32], [u8; 32])> = soll
                    .iter()
                    .filter_map(|schluessel| {
                        let (eigene, fremde) = rendezvous_saaten(&store, schluessel)?;
                        Some((schluessel.clone(), eigene, fremde))
                    })
                    .collect();
                (store.state.tor, soll, arbeit)
            };
            // Tor abgeschaltet: die Verbindung fallen lassen genuegt, Tor
            // nimmt jeden Dienst mit, den sie angelegt hat.
            if !tor_an {
                if steuerung.take().is_some() {
                    log("rendezvous: Tor is off -- the meeting points go with the connection");
                }
                veroeffentlicht.clear();
                continue;
            }
            // Steht die Verbindung noch? Ist sie weg, sind auch die Dienste
            // weg: wer das nicht merkt, haelt Treffpunkte fuer angemeldet, die
            // es nicht gibt, und meldet sie nie wieder an.
            if !veroeffentlicht.is_empty()
                && steuerung.as_mut().map_or(false, |tor| !tor.alive())
            {
                log("rendezvous: the connection to Tor broke -- announcing again");
                steuerung = None;
                veroeffentlicht.clear();
            }
            if steuerung.is_none() {
                if soll.is_empty() {
                    // Niemand zu treffen: dann auch keine Verbindung halten.
                    continue;
                }
                steuerung = tor::connect();
                if steuerung.is_none() {
                    continue;
                }
            }
            let mut kaputt = false;
            if let Some(tor) = steuerung.as_mut() {
                // Erst abraeumen. Wer aus `soll` gefallen ist, braucht den
                // Treffpunkt nicht mehr: der Handschlag ist geglueckt (von
                // hier oder von drueben -- finish_handshake nimmt den
                // schwebenden Kontakt in beiden Faellen aus dem Speicher),
                // der Benutzer hat ihn entfernt, oder die Frist ist um.
                let ueberzaehlig: Vec<(String, String)> = veroeffentlicht
                    .iter()
                    .filter(|(schluessel, _)| !soll.contains(schluessel.as_str()))
                    .map(|(s, k)| (s.clone(), k.clone()))
                    .collect();
                for (schluessel, kennung) in ueberzaehlig {
                    match tor.unpublish(&kennung) {
                        Ok(bekannt) => {
                            veroeffentlicht.remove(&schluessel);
                            log(if bekannt {
                                "rendezvous: meeting point taken down"
                            } else {
                                "rendezvous: the meeting point was gone already"
                            });
                        }
                        Err(e) => {
                            log(&format!("rendezvous: cannot take it down: {}", e));
                            kaputt = true;
                        }
                    }
                }
                for (schluessel, eigene, fremde) in arbeit {
                    // Unseren Treffpunkt anmelden -- einmal je schwebendem
                    // Kontakt, danach laeuft er an dieser Verbindung weiter.
                    if !veroeffentlicht.contains_key(&schluessel) {
                        let blob = crate::rendezvous::private_key_blob(&eigene);
                        match tor.publish(tor_port, Some(&blob)) {
                            Ok(dienst) => {
                                // Mit Adresse: ohne sie laesst sich nicht
                                // nachsehen, ob beide Seiten dieselben beiden
                                // Treffpunkte meinen.
                                log(&format!(
                                    "rendezvous: own meeting point published ({}.onion)",
                                    dienst.onion
                                ));
                                // Die Kennung kommt von Tor, nicht aus unserer
                                // eigenen Rechnung: nur sie darf spaeter in
                                // DEL_ONION stehen.
                                veroeffentlicht.insert(schluessel.clone(), dienst.onion);
                            }
                            Err(e) => {
                                log(&format!("rendezvous: cannot publish: {}", e));
                                kaputt = true;
                                continue;
                            }
                        }
                    }
                    // Und die Gegenseite anwaehlen. Sie ist erst da, wenn sie
                    // ihren Dienst ebenfalls angemeldet hat -- deshalb der Takt.
                    let ziel = format!("{}.onion", crate::rendezvous::onion(&fremde));
                    let index = {
                        let store = self.store.lock().unwrap();
                        store
                            .state
                            .pending
                            .iter()
                            .position(|p| p.public_key == schluessel)
                    };
                    if let Some(index) = index {
                        match self.connect_pending_at(index, TOR_TRANSPORT_ID, &ziel) {
                            Ok(()) => log(&format!("rendezvous: met at {}", ziel)),
                            Err(e) => log(&format!("rendezvous: not yet at {} ({})", ziel, e)),
                        }
                    }
                }
            }
            if kaputt {
                // Etwas ging schief, das nicht am einzelnen Dienst liegt:
                // Verbindung fallen lassen. Das raeumt alles ab, und die
                // naechste Runde meldet neu an, was noch gebraucht wird.
                steuerung = None;
                veroeffentlicht.clear();
            }
        }
    }

    pub fn run_tor_listener(&self, tor_port: u16) {
        let data_dir = {
            let store = self.store.lock().unwrap();
            store
                .path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."))
        };
        let mut tor = match tor::connect_or_start(&data_dir) {
            Some(t) => t,
            None => {
                log("no Tor running and none bundled -- Tor transport off");
                return;
            }
        };
        log(&format!(
            "Tor on control port {}, SOCKS {}",
            tor.control_port, tor.socks_port
        ));
        let stored_key = {
            let store = self.store.lock().unwrap();
            store.state.tor_key.clone()
        };
        let service = match tor.publish(tor_port, stored_key.as_deref()) {
            Ok(s) => s,
            Err(e) => {
                log(&format!("Tor would not publish the hidden service: {}", e));
                return;
            }
        };
        {
            let mut store = self.store.lock().unwrap();
            store.state.tor_key = Some(service.private_key.clone());
            store.state.tor_onion = Some(service.onion.clone());
            let _ = store.save();
        }
        log(&format!("hidden service {}.onion", service.onion));
        let listener = match TcpListener::bind(("127.0.0.1", tor_port)) {
            Ok(l) => l,
            Err(e) => {
                log(&format!("cannot listen on the Tor port {}: {}", tor_port, e));
                return;
            }
        };
        // Not blocking on accept: the loop has to notice when the user
        // switches Tor off, and then let `tor` drop -- which takes the
        // hidden service and our own Tor process with it.
        let _ = listener.set_nonblocking(true);
        let mut runden: u32 = 0;
        loop {
            if !self.store.lock().unwrap().state.tor {
                log("Tor switched off -- stopping the hidden service");
                break;
            }
            // Alle 60 s (120 Runden zu 500 ms) nachfragen, ob die
            // Steuerverbindung noch steht. Tut sie es nicht, bricht die
            // Schleife ab; der Aufseher im Dienst veroeffentlicht den
            // versteckten Dienst danach neu -- mit demselben Schluessel,
            // also unter derselben Adresse.
            runden = runden.wrapping_add(1);
            if runden % 120 == 0 && !tor.alive() {
                log("the connection to Tor broke -- publishing the hidden service again");
                let mut store = self.store.lock().unwrap();
                store.state.tor_onion = None;
                let _ = store.save();
                return;
            }
            match listener.accept() {
                Ok((socket, _)) => {
                    let _ = socket.set_nonblocking(false);
                    self.spawn_incoming(Conn::Tcp(socket), TOR_TRANSPORT_ID, None);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => log(&format!("Tor accept failed: {}", e)),
            }
        }
        drop(tor);
        let mut store = self.store.lock().unwrap();
        store.state.tor_onion = None;
        let _ = store.save();
    }

    /// Accepts incoming Bluetooth connections forever.
    /// Accepts incoming Bluetooth connections, and keeps trying to bind.
    ///
    /// This used to give up when binding failed, and that was wrong in the
    /// most ordinary case of all: Bluetooth switched off when the daemon
    /// started. Switching it on afterwards then changed nothing until the
    /// daemon was restarted.
    pub fn run_bluetooth_listener(&self) {
        let mut complained = false;
        loop {
            if !self.store.lock().unwrap().state.bluetooth {
                log("Bluetooth switched off -- no longer listening");
                return;
            }
            let listener = match bt::Listener::bind(bt::CHANNEL) {
                Ok(l) => l,
                Err(e) => {
                    if !complained {
                        log(&format!(
                            "no Bluetooth listener on channel {} yet: {}",
                            bt::CHANNEL, e
                        ));
                        complained = true;
                    }
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            complained = false;
            log(&format!(
                "listening on Bluetooth channel {} ({})",
                bt::CHANNEL,
                bt::local_address().unwrap_or_else(|| "no adapter address".to_string())
            ));
            // A failing accept means the adapter went away; after a few of
            // them the socket is dropped and bound again, which is what
            // brings Bluetooth back after it was switched off and on.
            let mut failures = 0;
            loop {
                match listener.accept() {
                    Ok((socket, address)) => {
                        failures = 0;
                        log(&format!("Bluetooth connection from {}", address));
                        self.spawn_incoming(Conn::Bluetooth(socket), BLUETOOTH_TRANSPORT_ID, None);
                    }
                    Err(e) => {
                        failures += 1;
                        if failures == 1 {
                            log(&format!("Bluetooth accept failed: {}", e));
                        }
                        std::thread::sleep(Duration::from_secs(5));
                        if failures >= 3 {
                            break;
                        }
                    }
                }
                if !self.store.lock().unwrap().state.bluetooth {
                    log("Bluetooth switched off -- no longer listening");
                    return;
                }
            }
            log("the Bluetooth socket is gone -- binding again");
        }
    }

    /// Die naechste ausgehende Stromnummer fuer einen schwebenden Kontakt --
    /// vergeben, weggeschrieben, dann erst benutzt.
    ///
    /// Warum ueberhaupt gezaehlt wird: die Marke am Stromanfang ist ein
    /// BLAKE2b ueber Fassung und Stromnummer. Zweimal dieselbe Nummer heisst
    /// zweimal dieselbe Marke -- fuer einen Lauscher der Beweis, dass zwei
    /// Verbindungen zusammengehoeren, und fuer ein echtes Briar ein
    /// verbrauchtes Los: es streicht die Marke beim Erkennen aus seiner
    /// Tabelle (TransportKeyManagerImpl.java:430-437) und verwirft jeden
    /// weiteren Versuch im selben Abschnitt still. Ein Abschnitt ist hier
    /// gut einen Tag lang (30 s + 24 h) und der Taktgeber probiert jede
    /// Minute -- ohne Zaehler traegt jeder Versuch eines ganzen Tages
    /// dieselbe Marke.
    ///
    /// Erst wegschreiben, dann senden. Ein Absturz dazwischen laesst eine
    /// Nummer unbenutzt liegen; eine Luecke stoert niemanden, eine doppelte
    /// Nummer schon.
    fn stromnummer_vergeben(
        &self,
        schwebend: &str,
        transport_id: &str,
        period: u64,
    ) -> std::io::Result<u64> {
        let mut store = self.store.lock().unwrap();
        let nummer = {
            let pending = store
                .state
                .pending
                .iter_mut()
                .find(|p| p.public_key == schwebend)
                .ok_or_else(|| bad("pending contact vanished"))?;
            let zustand = pending.transport_mut(transport_id);
            let nummer = naechste_stromnummer(zustand, period);
            stromnummer_vormerken(zustand, period, nummer);
            nummer
        };
        store.save()?;
        Ok(nummer)
    }

    pub fn spawn_incoming(&self, conn: Conn, transport_id: &'static str, peer_ip: Option<String>) {
        let store = Arc::clone(&self.store);
        std::thread::spawn(move || {
            let node = Node { store };
            if let Err(e) = node.handle_incoming(conn, transport_id, peer_ip) {
                log(&format!("incoming connection failed: {}", e));
            }
        });
    }

    fn handle_incoming(
        &self,
        conn: Conn,
        transport_id: &str,
        peer_ip: Option<String>,
    ) -> std::io::Result<()> {
        conn.set_timeouts()?;
        let mut reader = conn.try_clone()?;
        let mut tag = [0u8; TAG_LEN];
        reader.read_exact(&mut tag)?;
        let recognised = {
            let store = self.store.lock().unwrap();
            recognise_tag(&store, transport_id, &tag)
        };
        match recognised {
            Some(Recognised::Pending {
                index,
                header_key,
                stream_number,
                period: gesehen_in,
                alice,
            }) => {
                log(&format!("incoming handshake connection ({})", transport_id));
                let (root, schwebend) = {
                    let store = self.store.lock().unwrap();
                    let pending = store
                        .state
                        .pending
                        .get(index)
                        .ok_or_else(|| bad("pending contact vanished"))?;
                    let schwebend = pending.public_key.clone();
                    let root = pending_keys(&store, &schwebend)
                        .ok_or_else(|| bad("no identity yet"))?
                        .0;
                    (root, schwebend)
                };
                // Die erkannte Nummer sagt, wie weit die Gegenseite gezaehlt
                // hat. Das Fenster zieht nach, damit ihr naechster Versuch im
                // selben Abschnitt nicht durchfaellt.
                fenster_vermerken(
                    &self.store,
                    &schwebend,
                    transport_id,
                    gesehen_in,
                    stream_number,
                );
                let period = current_time_period();
                let keys = derive_handshake_keys(transport_id, &root, period, alice);
                let nummer = self.stromnummer_vergeben(&schwebend, transport_id, period)?;
                let mut writer = StreamWriter::new(conn.try_clone()?, &keys, nummer);
                // Unseren Stromkopf hinaus, bevor wir zu lesen anfangen.
                // Briar tut das an genau dieser Stelle
                // (IncomingHandshakeConnection: "Flush the output stream to
                // send the outgoing stream header"). Ohne das warten beide:
                // die Gegenseite hat gewaehlt, unsere Kennung gelesen und
                // wartet auf unseren Kopf -- wir warten auf ihren ersten
                // Handschlagschritt. Das haelt bis zur Zeitgrenze, und weil
                // die Rolle am Schluesselpaar haengt, bei diesem Gegenueber
                // jedes Mal wieder.
                writer.flush()?;
                self.finish_handshake(
                    conn,
                    transport_id,
                    index,
                    writer,
                    Some((header_key, stream_number)),
                    alice,
                    peer_ip,
                )
            }
            Some(Recognised::Contact {
                id,
                header_key,
                stream_number,
                period,
            }) => {
                log(&format!(
                    "incoming sync connection from contact {} ({})",
                    id, transport_id
                ));
                self.run_sync(
                    conn,
                    transport_id,
                    id,
                    Some((header_key, stream_number, period)),
                    peer_ip,
                )
            }
            None => {
                log("unrecognised tag");
                Ok(())
            }
        }
    }

    /// Dials a pending contact and becomes its contact.
    /// Wie `connect_pending`, aber mit einer Adresse, die nicht im Speicher
    /// steht -- beim Rendezvous wird sie ja gerade erst ausgerechnet.
    pub fn connect_pending_at(
        &self,
        index: usize,
        transport_id: &str,
        address: &str,
    ) -> std::io::Result<()> {
        let (alice, root, schwebend) = {
            let store = self.store.lock().unwrap();
            let pending = store
                .state
                .pending
                .get(index)
                .ok_or_else(|| bad("no such pending contact"))?;
            let schwebend = pending.public_key.clone();
            let (root, alice) =
                pending_keys(&store, &schwebend).ok_or_else(|| bad("no identity yet"))?;
            (alice, root, schwebend)
        };
        let conn = dial(transport_id, address, None)?;
        let period = current_time_period();
        let keys = derive_handshake_keys(transport_id, &root, period, alice);
        let peer_ip = match &conn {
            Conn::Tcp(s) => s.peer_addr().ok().map(|a| a.ip().to_string()),
            Conn::Bluetooth(_) => None,
        };
        // Erst nach dem Waehlen vergeben: ein Versuch, der nicht einmal eine
        // Verbindung bekommt, hat keine Marke auf die Leitung gelegt und darf
        // darum keine Nummer verbrauchen. Der Treffpunkt wird jede Minute bis
        // zu zwei Tage lang angewaehlt und meist ist niemand dran -- sonst
        // waere das Fenster der Gegenseite binnen einer halben Stunde
        // ueberholt.
        let nummer = self.stromnummer_vergeben(&schwebend, transport_id, period)?;
        let mut writer = StreamWriter::new(conn.try_clone()?, &keys, nummer);
        writer.flush()?;
        self.finish_handshake(conn, transport_id, index, writer, None, alice, peer_ip)
    }

    pub fn connect_pending(&self, index: usize, transport_id: &str) -> std::io::Result<()> {
        let (address, alice, root, schwebend) = {
            let store = self.store.lock().unwrap();
            let pending = store
                .state
                .pending
                .get(index)
                .ok_or_else(|| bad("no such pending contact"))?;
            let address = if transport_id == BLUETOOTH_TRANSPORT_ID {
                pending.bluetooth.clone()
            } else if transport_id == TOR_TRANSPORT_ID {
                pending.onion.clone()
            } else {
                pending.address.clone()
            }
            .ok_or_else(|| bad("no address for this pending contact"))?;
            let schwebend = pending.public_key.clone();
            let (root, alice) =
                pending_keys(&store, &schwebend).ok_or_else(|| bad("no identity yet"))?;
            (address, alice, root, schwebend)
        };
        let conn = dial(transport_id, &address, None)?;
        let period = current_time_period();
        let keys = derive_handshake_keys(transport_id, &root, period, alice);
        let peer_ip = match &conn {
            Conn::Tcp(s) => s.peer_addr().ok().map(|a| a.ip().to_string()),
            Conn::Bluetooth(_) => None,
        };
        // Auch hier erst nach dem Waehlen: ein fehlgeschlagener Anwahlversuch
        // hat keine Marke gesendet.
        let nummer = self.stromnummer_vergeben(&schwebend, transport_id, period)?;
        let mut writer = StreamWriter::new(conn.try_clone()?, &keys, nummer);
        writer.flush()?;
        self.finish_handshake(conn, transport_id, index, writer, None, alice, peer_ip)
    }

    /// Runs the handshake and then the contact exchange, and stores the new
    /// contact.
    #[allow(clippy::too_many_arguments)]
    fn finish_handshake(
        &self,
        conn: Conn,
        transport_id: &str,
        index: usize,
        mut writer: StreamWriter<Conn>,
        incoming: Option<(SecretKey, u64)>,
        alice: bool,
        peer_ip: Option<String>,
    ) -> std::io::Result<()> {
        let (their_public_hex, alias, pending_bluetooth) = {
            let store = self.store.lock().unwrap();
            let pending = store
                .state
                .pending
                .get(index)
                .ok_or_else(|| bad("pending contact vanished"))?;
            (
                pending.public_key.clone(),
                pending.alias.clone(),
                pending.bluetooth.clone(),
            )
        };
        let their_handshake_public = key_from_hex(&their_public_hex);
        let (our_private, our_public, our_seed, our_name, our_signature_public,
             port, recent, recent6, bluetooth, bt_uuid, onion) = {
            let mut store = self.store.lock().unwrap();
            // Beim Handschlag ebenfalls erst das Adressgedaechtnis
            // fortschreiben: der frische Kontakt soll sofort alle Netze
            // kennen, in denen wir zuletzt standen.
            note_local_addresses(&mut store.state);
            note_local_addresses6(&mut store.state);
            let identity = store.identity().ok_or_else(|| bad("no identity yet"))?;
            (
                key_from_hex(&identity.handshake_private),
                key_from_hex(&identity.handshake_public),
                key_from_hex(&identity.signature_seed),
                identity.name.clone(),
                key_from_hex(&identity.signature_public),
                store.state.listen_port,
                store.state.lan_recent.clone(),
                store.state.lan6_recent.clone(),
                store.state.bluetooth,
                store.state.bt_uuid.clone(),
                store.state.tor_onion.clone(),
            )
        };

        let root = {
            let store = self.store.lock().unwrap();
            pending_keys(&store, &their_public_hex)
                .ok_or_else(|| bad("no identity yet"))?
                .0
        };
        let mut reader: Box<dyn Read> = match incoming {
            Some((header_key, stream_number)) => Box::new(StreamReader::new(
                conn.try_clone()?,
                header_key,
                stream_number,
            )),
            None => Box::new(LazyHandshakeReader {
                conn: conn.try_clone()?,
                transport_id: transport_id.to_string(),
                root,
                peer_is_alice: !alice,
                store: Arc::clone(&self.store),
                public_key: their_public_hex.clone(),
                stream: None,
            }),
        };

        let result = handshake::handshake(
            &mut reader,
            &mut writer,
            &their_handshake_public,
            &our_private,
            &our_public,
            alice,
        )?;
        writer.send_end_of_stream()?;
        let mut sink = Vec::new();
        let _ = reader.read_to_end(&mut sink);
        log("handshake succeeded");

        // Contact exchange, on the same connection but with its own streams
        let master_key = result.master_key;
        let mut exchange_writer = StreamWriter::untagged(
            conn.try_clone()?,
            exchange::derive_header_key(&master_key, alice),
        );
        let mut exchange_reader = StreamReader::new(
            conn.try_clone()?,
            exchange::derive_header_key(&master_key, !alice),
            0,
        );
        let signature = exchange::sign_nonce(&our_seed, &master_key, alice);
        let local = ContactInfo {
            name: our_name,
            public_key: our_signature_public.to_vec(),
            properties: local_properties(port, &recent, &recent6, bluetooth, bt_uuid.as_deref(), onion),
            timestamp: now_ms(),
        };
        let local_timestamp = local.timestamp;
        let (remote, remote_signature) = exchange::exchange(
            &mut exchange_reader,
            &mut exchange_writer,
            &local,
            &signature,
            alice,
        )?;
        exchange_writer.send_end_of_stream()?;
        let mut sink = Vec::new();
        let _ = exchange_reader.read_to_end(&mut sink);

        if !exchange::verify_nonce(&remote.public_key, &master_key, !alice, &remote_signature) {
            return Err(bad("the contact's signature did not verify"));
        }
        let timestamp = local_timestamp.min(remote.timestamp);
        let mut addresses = addresses_from_properties(&remote.properties, peer_ip.as_deref());
        if let Some(address) = pending_bluetooth {
            addresses
                .entry(BLUETOOTH_TRANSPORT_ID.to_string())
                .or_insert(address);
        }
        let author_id = ids::author_id(&remote.name, &remote.public_key);
        let creation_period = timestamp / time_period_length(LAN_MAX_LATENCY_MS);

        // A second handshake with someone we already have is not a second
        // contact: two taps on "connect" used to leave the same person in the
        // list twice. The old entry keeps its master key and its history, and
        // only learns any address it did not know yet -- and because both
        // sides do this, both keep the same key.
        {
            let mut store = self.store.lock().unwrap();
            let known = store
                .state
                .contacts
                .iter()
                .position(|c| c.handshake_public.as_deref() == Some(their_public_hex.as_str()));
            if let Some(index) = known {
                let contact = &mut store.state.contacts[index];
                let id = contact.id;
                for (transport, address) in &addresses {
                    contact
                        .transports
                        .entry(transport.clone())
                        .or_insert_with(|| TransportState {
                            address: Some(address.clone()),
                            out_stream: 0,
                            in_stream: BTreeMap::new(),
                            ..Default::default()
                        });
                }
                contact.last_seen = now_ms();
                store
                    .state
                    .pending
                    .retain(|p| p.public_key != their_public_hex);
                store.save()?;
                log(&format!(
                    "handshake with {} again -- staying contact {}",
                    remote.name, id
                ));
                return Ok(());
            }
        }

        let contact_id = {
            let mut store = self.store.lock().unwrap();
            // Steht der Wartende ueberhaupt noch da? Der Benutzer kann ihn
            // gestrichen haben, waehrend der Handschlag lief -- ohne diese
            // Frage kaeme er gleich darauf als Kontakt zurueck, und das
            // Streichen waere nicht verlaesslich. Bei einem Handschlag, den
            // wir selbst angestossen haben, gilt dasselbe.
            if !store
                .state
                .pending
                .iter()
                .any(|p| p.public_key == their_public_hex)
            {
                log("the waiting contact was removed while the handshake ran -- dropping it");
                return Ok(());
            }
            let id = store.state.next_contact_id;
            store.state.next_contact_id += 1;
            let name = if alias.is_empty() {
                remote.name.clone()
            } else {
                alias.clone()
            };
            let mut transports = BTreeMap::new();
            for (transport, address) in addresses {
                transports.insert(
                    transport.clone(),
                    TransportState {
                        address: Some(address),
                        out_stream: 0,
                        in_stream: BTreeMap::new(),
                        ..Default::default()
                    },
                );
            }
            store.state.contacts.push(Contact {
                id,
                name,
                author_id: to_hex(&author_id),
                signature_public: to_hex(&remote.public_key),
                handshake_public: Some(their_public_hex.clone()),
                master_key: to_hex(&master_key),
                alice,
                creation_period,
                transports,
                messages: Vec::new(),
                outbox: Vec::new(),
                to_ack: Vec::new(),
                to_request: Vec::new(),
                versioning_sent: String::new(),
                versioning_version: 0,
                last_seen: now_ms(),
                sent_versioning_update: false,
                sent_properties: None,
                last_read: 0,
            });
            store
                .state
                .pending
                .retain(|p| p.public_key != their_public_hex);
            store.save()?;
            id
        };
        log(&format!(
            "contact exchange succeeded: {} is contact {}",
            remote.name, contact_id
        ));
        Ok(())
    }

    /// Dials a contact over one transport and runs one sync round.
    pub fn connect_contact(&self, id: u32, transport_id: &str) -> std::io::Result<()> {
        let address = {
            let store = self.store.lock().unwrap();
            let contact = store.contact(id).ok_or_else(|| bad("no such contact"))?;
            let mut address = contact
                .address(transport_id)
                .ok_or_else(|| bad("no address for this contact"))?;
            // Zwei geratene Hotspot-Adressen anhaengen, sobald der Port der
            // Gegenseite bekannt ist. Spannt sie gerade selbst einen
            // Zugangspunkt auf, ist sie dort erreichbar, ohne dass wir je
            // davon gehoert haetten. Briar raet an derselben Stelle dieselben
            // beiden. Geraten wird nur beim Waehlen, nicht gespeichert --
            // sonst stuenden die Vermutungen dauerhaft im Kontakt und die
            // zwei Wege, auf denen eine Adresse ankommt, waeren verschieden.
            if transport_id == LAN_TRANSPORT_ID {
                if let Some(port) = contact
                    .transports
                    .get(LAN_TRANSPORT_ID)
                    .and_then(|t| t.port)
                {
                    for geraten in ["192.168.43.1", "192.168.49.1"] {
                        let eintrag = format!("{}:{}", geraten, port);
                        if !address.split(',').any(|e| e.trim() == eintrag) {
                            address.push(',');
                            address.push_str(&eintrag);
                        }
                    }
                    // Die link-lokalen IPv6-Adressen kommen als Hex ohne Port
                    // an; hier werden sie zu gewoehnlichen Kandidaten in
                    // Klammerschreibweise, mit dem gemeldeten Port.
                    if let Some(v6) = contact
                        .transports
                        .get(LAN_TRANSPORT_ID)
                        .and_then(|t| t.ipv6.clone())
                    {
                        for hex in v6.split(',') {
                            if let Some(ip) = ipv6_from_hex(hex) {
                                address.push_str(&format!(",[{}]:{}", ip, port));
                            }
                        }
                    }
                }
            }
            address
        };
        // Bei Bluetooth zuerst den Kanal zur gemeldeten UUID suchen. Schlaegt
        // das fehl, bleibt der feste Kanal als Rueckfall -- zwischen unseren
        // eigenen Geraeten reicht der.
        let kanal = if transport_id == BLUETOOTH_TRANSPORT_ID {
            let uuid = {
                let store = self.store.lock().unwrap();
                store
                    .contact(id)
                    .and_then(|c| c.transports.get(BLUETOOTH_TRANSPORT_ID))
                    .and_then(|t| t.bt_uuid.clone())
            };
            match uuid {
                Some(u) => match bt::lookup_channel(&address, &u) {
                    Ok(k) => {
                        log(&format!("Bluetooth: UUID gefunden, Kanal {}", k));
                        Some(k)
                    }
                    Err(e) => {
                        log(&format!("Bluetooth: SDP-Suche misslungen ({})", e));
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        };
        let conn = dial(transport_id, &address, kanal)?;
        let peer_ip = match &conn {
            Conn::Tcp(s) => s.peer_addr().ok().map(|a| a.ip().to_string()),
            Conn::Bluetooth(_) => None,
        };
        self.run_sync(conn, transport_id, id, None, peer_ip)
    }

    /// Tries a contact over every transport it has an address for, newest
    /// first: LAN when both are possible, Bluetooth when the LAN fails.
    pub fn reach_contact(&self, id: u32) -> std::io::Result<()> {
        let transports: Vec<String> = {
            let store = self.store.lock().unwrap();
            match store.contact(id) {
                Some(contact) => {
                    // Feste Folge statt der alphabetischen Ordnung der
                    // BTreeMap: dort stuende Bluetooth vorne. Briar ordnet
                    // ausdruecklich LAN vor Bluetooth ("Prefer LAN to
                    // Bluetooth"); Tor kommt zuletzt, weil es das langsamste
                    // und teuerste ist.
                    [LAN_TRANSPORT_ID, BLUETOOTH_TRANSPORT_ID, TOR_TRANSPORT_ID]
                        .iter()
                        .filter(|t| {
                            contact
                                .transports
                                .get(**t)
                                .map(|s| s.address.is_some())
                                .unwrap_or(false)
                        })
                        .map(|t| t.to_string())
                        .collect()
                }
                None => return Err(bad("no such contact")),
            }
        };
        let mut last = bad("no address for this contact");
        for transport in transports {
            match self.connect_contact(id, &transport) {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// One sync round: we send what the peer is missing and read what it
    /// sends us. Both sides do the same, so a connection settles both
    /// directions before it closes.
    fn run_sync(
        &self,
        conn: Conn,
        transport_id: &str,
        contact_id: u32,
        incoming: Option<(SecretKey, u64, u64)>,
        peer_ip: Option<String>,
    ) -> std::io::Result<()> {
        conn.set_timeouts()?;
        let period = current_time_period();
        let (
            out_keys,
            out_stream,
            to_send,
            to_ack,
            to_request,
            versioning_pending,
            versioning_fp,
            versioning_nummer,
        ) = {
            let mut store = self.store.lock().unwrap();
            let contact = store
                .contact(contact_id)
                .ok_or_else(|| bad("no such contact"))?;
            let keys = derive_rotation_keys(
                transport_id,
                &contact.master_key_bytes(),
                contact.creation_period,
                period,
                contact.alice,
            );
            let their_author = contact.author_id_bytes();
            // Our own addresses. They go through the outbox like any other
            // message, so they are repeated until the peer acknowledges them
            // -- a peer that was still running an older version when we first
            // announced them would otherwise never hear them again.
            // Erst das Gedaechtnis fortschreiben, dann daraus melden.
            let etwas_neu = note_local_addresses(&mut store.state)
                | note_local_addresses6(&mut store.state);
            let properties = local_properties(
                store.state.listen_port,
                &veroeffentlichte(&store.state),
                &store.state.lan6_recent,
                store.state.bluetooth,
                store.state.bt_uuid.as_deref(),
                store.state.tor_onion.clone(),
            );
            // Nur wenn wirklich eine neue Adresse dazugekommen ist, aendert
            // sich das, was die Kontakte zu sehen bekommen. Ein blosses
            // Umsortieren zwischen zwei bekannten Netzen aendert nur die
            // oertliche Liste -- genau so trennt Briar es auch
            // (updateRecentAddresses ruft mergeLocalProperties nur im
            // else-Zweig, also nur bei einer neuen Adresse).
            //
            // Frueher stand hier ein Gatter, das das Verteilen unterband.
            // Das war falsch: lan_published ist global, run_sync laeuft je
            // Kontakt -- der erste verbrauchte das "neu", und jeder weitere
            // erfuhr die neue Adresse nie. Gegen unnoetiges Wiederholen
            // schuetzt schon sent_properties, und das ist je Kontakt.
            if etwas_neu {
                store.state.lan_published = store.state.lan_recent.join(",");
            }
            let fingerprint = properties_fingerprint(&properties);
            let noch_nicht_gemeldet = store
                .contact(contact_id)
                .map(|c| c.sent_properties.as_deref() != Some(fingerprint.as_str()))
                .unwrap_or(false);
            if noch_nicht_gemeldet {
                let our_author = store
                    .identity()
                    .map(|i| key_from_hex(&i.author_id))
                    .ok_or_else(|| bad("no identity"))?;
                let properties_group = sync::properties_group_id(&our_author, &their_author);
                let group_hex = to_hex(&properties_group);
                // An older, still unacknowledged announcement is superseded.
                if let Some(c) = store.contact_mut(contact_id) {
                    c.outbox.retain(|m| m.group != group_hex);
                }
                let timestamp = now_ms();
                for (transport, values) in &properties {
                    let body = sync::properties_update_body(transport, timestamp as i64, values);
                    let id = crate::ids::message_id(&properties_group, timestamp, &body);
                    store.queue(
                        contact_id,
                        OutMessage {
                            id: to_hex(&id),
                            group: group_hex.clone(),
                            timestamp,
                            body: to_hex(&body),
                            acked: false,
                        },
                    );
                }
                if let Some(c) = store.contact_mut(contact_id) {
                    c.sent_properties = Some(fingerprint.clone());
                }
            }
            let contact = store.contact(contact_id).ok_or_else(|| bad("no contact"))?;
            let to_send: Vec<OutMessage> = contact
                .outbox
                .iter()
                .filter(|m| !m.acked)
                .cloned()
                .collect();
            let to_ack: Vec<SecretKey> = contact.to_ack.iter().map(|id| key_from_hex(id)).collect();
            // Was die Gegenseite in einer frueheren Runde angeboten hat. Ohne
            // diesen Satz schickt Briar ueber Duplex-Transporte gar nichts:
            // es sendet nur, was angefordert wurde.
            let to_request: Vec<SecretKey> =
                contact.to_request.iter().map(|id| key_from_hex(id)).collect();
            // Neu ansagen, sobald sich die Liste aendert -- nicht nur einmal
            // im Leben des Kontakts.
            let versioning_body = sync::versioning_update_body(0);
            let versioning_fp = to_hex(&crate::crypto::hash("vers", &[&versioning_body]));
            let versioning_pending = contact.versioning_sent != versioning_fp;
            let versioning_nummer = contact.versioning_version + 1;
            let out_stream = contact
                .transport(transport_id)
                .map(|t| naechste_stromnummer(t, period))
                .unwrap_or(0);
            if let Some(c) = store.contact_mut(contact_id) {
                stromnummer_vormerken(c.transport_mut(transport_id), period, out_stream);
            }
            store.save()?;
            (
                keys,
                out_stream,
                to_send,
                to_ack,
                to_request,
                versioning_pending,
                versioning_fp,
                versioning_nummer,
            )
        };

        let mut writer = StreamWriter::new(conn.try_clone()?, &out_keys, out_stream);
        sync::write_versions(&mut writer)?;
        sync::write_priority(&mut writer, &crate::util::random(16))?;
        if versioning_pending {
            // Tell the peer which clients we speak, the way Briar's
            // versioning client does -- without it the real Briar would never
            // make the messaging group visible.
            let versioning_group = {
                let store = self.store.lock().unwrap();
                let identity = store.identity().ok_or_else(|| bad("no identity"))?;
                let contact = store.contact(contact_id).ok_or_else(|| bad("no contact"))?;
                sync::versioning_group_id(
                    &key_from_hex(&identity.author_id),
                    &contact.author_id_bytes(),
                )
            };
            let body = sync::versioning_update_body(versioning_nummer as i64);
            sync::write_message(&mut writer, &versioning_group, now_ms(), &body)?;
        }
        sync::write_ack(&mut writer, &to_ack)?;
        sync::write_request(&mut writer, &to_request)?;
        for message in &to_send {
            let group = key_from_hex(&message.group);
            let body = from_hex(&message.body).unwrap_or_default();
            sync::write_message(&mut writer, &group, message.timestamp, &body)?;
        }
        writer.send_end_of_stream()?;

        // The peer's stream: if we dialled, its tag is still to come
        let mut raw_reader = conn.try_clone()?;
        let (in_header_key, in_stream_number, in_period) = match incoming {
            Some(v) => v,
            None => {
                let mut tag = [0u8; TAG_LEN];
                raw_reader.read_exact(&mut tag)?;
                let store = self.store.lock().unwrap();
                match recognise_tag(&store, transport_id, &tag) {
                    Some(Recognised::Contact {
                        id,
                        header_key,
                        stream_number,
                        period,
                    }) if id == contact_id => (header_key, stream_number, period),
                    _ => return Err(bad("the contact's tag was not recognised")),
                }
            }
        };
        let mut reader = StreamReader::new(raw_reader, in_header_key, in_stream_number);

        let mut acked_ids: Vec<SecretKey> = Vec::new();
        let mut offered_ids: Vec<SecretKey> = Vec::new();
        let mut received: Vec<(SecretKey, SecretKey, u64, Vec<u8>)> = Vec::new();
        loop {
            match read_record(&mut reader) {
                Ok(Some(record)) => {
                    if record.protocol_version != sync::PROTOCOL_VERSION {
                        continue;
                    }
                    match record.record_type {
                        sync::ACK => acked_ids.extend(sync::parse_ids(&record.payload)),
                        // Ein Angebot: die Gegenseite haelt diese Nachrichten
                        // bereit und schickt sie erst, wenn wir sie anfordern.
                        sync::OFFER => offered_ids.extend(sync::parse_ids(&record.payload)),
                        sync::MESSAGE => {
                            if let Some((group, timestamp, body)) =
                                ids::parse_raw_message(&record.payload)
                            {
                                let id = ids::message_id(&group, timestamp, &body);
                                received.push((id, group, timestamp, body));
                            }
                        }
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        break;
                    }
                    log(&format!("sync read stopped: {}", e));
                    break;
                }
            }
        }

        // Menge statt Liste: ab jetzt laufen hier wirklich tausende Kennungen
        // durch, und darunter stehen Schleifen, die fuer jede Nachricht der
        // ganzen Geschichte "contains" rufen. Mit einer Liste waere das
        // Geschichte mal Kennungen -- auf dem N9 Minuten unter dem
        // Speicherschloss, ausgerechnet in der Runde, die endlich aufraeumt.
        let acked_now: std::collections::BTreeSet<String> =
            to_ack.iter().map(|id| to_hex(id)).collect();
        let mut new_messages = 0;
        {
            let mut store = self.store.lock().unwrap();
            if let Some(contact) = store.contact_mut(contact_id) {
                // Angefordert ist angefordert: die Liste gilt als erledigt,
                // sobald der Satz draussen ist. Kommt die Nachricht nicht,
                // bietet die Gegenseite sie in der naechsten Runde erneut an.
                contact.to_request.clear();
                // Was neu angeboten wurde, kommt in die naechste Runde --
                // ausser wir haben es schon.
                let bekannt: std::collections::BTreeSet<String> = contact
                    .messages
                    .iter()
                    .map(|m| m.id.clone())
                    .collect();
                for id in &offered_ids {
                    let hex = to_hex(id);
                    if !bekannt.contains(&hex) && !contact.to_request.contains(&hex) {
                        contact.to_request.push(hex);
                    }
                }
                let peer_acked: std::collections::BTreeSet<String> =
                    acked_ids.iter().map(|id| to_hex(id)).collect();
                for message in contact.outbox.iter_mut() {
                    if peer_acked.contains(&message.id) {
                        message.acked = true;
                    }
                }
                for message in contact.messages.iter_mut() {
                    if message.outgoing && peer_acked.contains(&message.id) {
                        message.acked = true;
                    }
                }
                // Acknowledged means delivered, and the queue has done its
                // job. The message itself stays in the history; only the copy
                // waiting to be sent goes, so the state file cannot grow
                // without end.
                contact.outbox.retain(|m| !m.acked);
                // Our own acks count as sent only for what this round
                // actually acknowledged.
                contact.to_ack.retain(|id| !acked_now.contains(id));
                for message in contact.messages.iter_mut() {
                    if !message.outgoing && acked_now.contains(&message.id) {
                        message.acked = true;
                    }
                }
                contact.last_seen = now_ms();
                contact
                    .transport_mut(transport_id)
                    .in_stream
                    .insert(in_period.to_string(), in_stream_number + 1);
                if versioning_pending {
                    contact.sent_versioning_update = true;
                    contact.versioning_sent = versioning_fp.clone();
                    contact.versioning_version = versioning_nummer;
                }
                if transport_id == LAN_TRANSPORT_ID {
                    let state = contact.transport_mut(LAN_TRANSPORT_ID);
                    // Der Port kommt aus dem, was die Gegenseite gemeldet hat,
                    // nicht aus einer festen Nummer: echtes Briar wuerfelt
                    // ihn beim ersten Start aus 32768..65535, eine feste 7327
                    // waere dort immer falsch. Ohne bekannten Port wird gar
                    // nichts gelernt.
                    //
                    // HINZUFUEGEN, nicht zuweisen, und nicht nur bei leerem
                    // Feld. Die beobachtete Absenderadresse ist die beste,
                    // die es gibt -- durch einen beglaubigten Strom belegt,
                    // und bei Briar deckungsgleich mit dem Lauschsockel, weil
                    // es die ausgehende Verbindung daran bindet. Vorher
                    // wurde sie nur bei leerem Feld gelernt: kam einmal eine
                    // IPv6-Adresse herein, landete "fe80::...:7327" im Feld,
                    // das parse_ip_port nie waehlen kann -- und weil das Feld
                    // dann nicht mehr leer war, blockierte es das Lernen
                    // einer brauchbaren IPv4-Adresse dauerhaft.
                    if let (Some(ip), Some(port)) = (peer_ip, state.port) {
                        if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
                            if reachable_by_a_contact(v4.octets()) {
                                let eintrag = format!("{}:{}", v4, port);
                                let schon = state
                                    .address
                                    .as_deref()
                                    .map(|a| a.split(',').any(|e| e.trim() == eintrag))
                                    .unwrap_or(false);
                                if !schon {
                                    // Nach vorne: die zuletzt erfolgreiche
                                    // Adresse ist die aussichtsreichste.
                                    state.address = Some(match state.address.take() {
                                        Some(alt) if !alt.is_empty() => {
                                            format!("{},{}", eintrag, alt)
                                        }
                                        _ => eintrag,
                                    });
                                    // Nicht unbegrenzt wachsen lassen: jeder
                                    // Fehlversuch kostet drei Sekunden.
                                    if let Some(a) = state.address.take() {
                                        let gekuerzt: Vec<&str> =
                                            a.split(',').take(6).collect();
                                        state.address = Some(gekuerzt.join(","));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for (id, group, timestamp, body) in received {
                if self.receive_message(&mut store, contact_id, &id, &group, timestamp, &body) {
                    new_messages += 1;
                }
                if let Some(contact) = store.contact_mut(contact_id) {
                    let hex = to_hex(&id);
                    if !contact.to_ack.contains(&hex) {
                        contact.to_ack.push(hex);
                    }
                }
            }
            store.save()?;
        }
        log(&format!(
            "sync round with contact {} over {} done, {} new message(s)",
            contact_id,
            short_transport(transport_id),
            new_messages
        ));
        if new_messages > 0 {
            // Send the acks straight back rather than making the sender wait
            // for the next poll.
            let store = Arc::clone(&self.store);
            let transport = transport_id.to_string();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(2));
                let node = Node { store };
                if let Err(e) = node.connect_contact(contact_id, &transport) {
                    log(&format!(
                        "acknowledging to contact {} failed: {}",
                        contact_id, e
                    ));
                }
            });
        }
        Ok(())
    }

    /// Sorts an incoming message by the group it belongs to: a private
    /// message, an invitation, or a message in a private group.
    fn receive_message(
        &self,
        store: &mut Store,
        contact_id: u32,
        id: &SecretKey,
        group: &SecretKey,
        timestamp: u64,
        body: &[u8],
    ) -> bool {
        let identity = match store.identity() {
            Some(i) => i.clone(),
            None => return false,
        };
        let our_author = key_from_hex(&identity.author_id);
        let their_author = match store.contact(contact_id) {
            Some(c) => c.author_id_bytes(),
            None => return false,
        };

        if *group == sync::properties_group_id(&our_author, &their_author) {
            // An address the peer announced. A known transport keeps its
            // entry -- only the address inside it is refreshed -- so stream
            // counters survive.
            if let Some((transport, version, values)) = sync::parse_properties_update(body) {
                let address = match transport.as_str() {
                    t if t == LAN_TRANSPORT_ID => values
                        .get("ipPorts")
                        .or_else(|| values.get("ipPort"))
                        .map(|v| clean_address_list(v))
                        .filter(|v| !v.is_empty()),
                    t if t == BLUETOOTH_TRANSPORT_ID => values.get("address").cloned(),
                    t if t == TOR_TRANSPORT_ID => values.get("onion3").cloned(),
                    _ => None,
                };
                // Der gemeldete Lauschport. Briar wuerfelt ihn einmal und
                // behaelt ihn; ohne ihn laesst sich weder eine gelernte
                // Absenderadresse vervollstaendigen noch eine Hotspot-Adresse
                // raten.
                let gemeldete_v6 = values
                    .get("ipv6")
                    .map(|v| clean_ipv6_list(v))
                    .filter(|v| !v.is_empty());
                let gemeldeter_port = values
                    .get("port")
                    .and_then(|p| p.trim().parse::<u16>().ok())
                    .filter(|p| *p != 0);
                if let Some(contact) = store.contact_mut(contact_id) {
                    let entry = contact.transport_mut(&transport);
                    // Strikt die hoehere Fassung gewinnt. Ohne das kann eine
                    // verspaetet eintreffende alte Meldung eine neuere
                    // ueberschreiben -- Briar laesst das nicht zu.
                    let version = version.max(0) as u64;
                    if version != 0 && version <= entry.props_version {
                        return true;
                    }
                    if version != 0 {
                        entry.props_version = version;
                    }
                    if let Some(port) = gemeldeter_port {
                        entry.port = Some(port);
                    }
                    if let Some(v6) = gemeldete_v6 {
                        entry.ipv6 = Some(v6);
                    }
                    if let Some(u) = values.get("uuid") {
                        if !u.trim().is_empty() {
                            entry.bt_uuid = Some(u.trim().to_string());
                        }
                    }
                    if let Some(address) = address {
                        if entry.address.as_deref() != Some(address.as_str()) {
                            entry.address = Some(address.clone());
                            log(&format!(
                                "contact {} announced {} for {}",
                                contact_id, address, transport
                            ));
                        }
                    }
                }
                return true;
            }
            return false;
        }

        if *group == sync::messaging_group_id(&our_author, &their_author) {
            // An attachment arrives as a message of its own, possibly before
            // or after the message that refers to it.
            if sync::is_attachment(body) {
                if let Some((content_type, data)) = sync::parse_attachment(body) {
                    let hex = to_hex(id);
                    match store.store_attachment(&hex, &content_type, &data) {
                        Ok(_) => {
                            let kind = content_type.clone();
                            if let Some(contact) = store.contact_mut(contact_id) {
                                for message in contact.messages.iter_mut() {
                                    if message.attachment.as_deref() == Some(hex.as_str()) {
                                        message.attachment_type = Some(kind.clone());
                                    }
                                }
                            }
                            log(&format!("attachment received ({}, {} bytes)",
                                         content_type, data.len()));
                            return true;
                        }
                        Err(e) => {
                            log(&format!("cannot store the attachment: {}", e));
                            return false;
                        }
                    }
                }
                return false;
            }
            if let Some(text) = sync::private_message_text(body) {
                let attachments = sync::private_message_attachments(body);
                let (attachment, attachment_type) = match attachments.first() {
                    Some((id, content_type)) => {
                        (Some(to_hex(id)), Some(content_type.clone()))
                    }
                    None => (None, None),
                };
                let preview = if text.trim().is_empty() {
                    attachment_type
                        .clone()
                        .map(|t| format!("[{}]", t))
                        .unwrap_or_default()
                } else {
                    text.clone()
                };
                let stored = store.add_message(
                    contact_id,
                    Message {
                        id: to_hex(id),
                        timestamp,
                        text,
                        outgoing: false,
                        acked: false,
                        attachment,
                        attachment_type,
                    },
                );
                if stored {
                    let name = store
                        .contact(contact_id)
                        .map(|c| c.name.clone())
                        .unwrap_or_default();
                    notify_chat(contact_id.to_string(), name, preview, false);
                }
                return stored;
            }
            return false;
        }

        if *group == groups::invite_group_id(&our_author, &their_author) {
            return self.receive_invite(store, contact_id, timestamp, body);
        }

        let group_hex = to_hex(group);
        if store.group(&group_hex).is_some() {
            return self.receive_group_message(store, contact_id, id, group, timestamp, body);
        }
        false
    }

    fn receive_invite(
        &self,
        store: &mut Store,
        contact_id: u32,
        timestamp: u64,
        body: &[u8],
    ) -> bool {
        let invite = match groups::parse_invite(body) {
            Some(i) => i,
            None => return false,
        };
        let creator_author_id = invite.creator.id();
        let group_id = groups::group_id(&invite.creator, &invite.group_name, &invite.salt);
        let our_author = match store.identity() {
            Some(i) => key_from_hex(&i.author_id),
            None => return false,
        };
        if !groups::verify_invite_signature(
            &invite.creator.public_key,
            &creator_author_id,
            &our_author,
            &group_id,
            timestamp,
            &invite.signature,
        ) {
            log("an invitation arrived with a bad signature");
            return false;
        }
        let group_hex = to_hex(&group_id);
        if store.group(&group_hex).is_some() {
            return false;
        }
        let mut member_names = BTreeMap::new();
        member_names.insert(to_hex(&creator_author_id), invite.creator.name.clone());
        store.state.groups.push(crate::store::PrivateGroup {
            id: group_hex,
            name: invite.group_name.clone(),
            salt: to_hex(&invite.salt),
            creator_name: invite.creator.name.clone(),
            creator_public: to_hex(&invite.creator.public_key),
            creator_author_id: to_hex(&creator_author_id),
            joined: false,
            invited_by: Some(contact_id),
            invite_timestamp: Some(timestamp),
            invite_signature: Some(to_hex(&invite.signature)),
            member_names,
            last_read: 0,
            messages: Vec::new(),
            our_previous: None,
            einladung_previous: None,
            contacts: vec![contact_id],
        });
        log(&format!(
            "invited to the group \"{}\" by contact {}",
            invite.group_name, contact_id
        ));
        true
    }

    fn receive_group_message(
        &self,
        store: &mut Store,
        contact_id: u32,
        id: &SecretKey,
        group: &SecretKey,
        timestamp: u64,
        body: &[u8],
    ) -> bool {
        let parsed = match groups::parse_body(group, timestamp, body) {
            Some(p) => p,
            None => {
                log("a group message did not verify, or its text was out of bounds");
                return false;
            }
        };
        let group_hex = to_hex(group);
        let message_id = to_hex(id);
        let member = parsed.member().clone();
        let member_id = to_hex(&member.id());
        let (text, join) = match &parsed {
            GroupMessage::Join { .. } => (String::new(), true),
            GroupMessage::Post { text, .. } => (text.clone(), false),
        };
        let others: Vec<u32>;
        {
            let group_entry = match store.group_mut(&group_hex) {
                Some(g) => g,
                None => return false,
            };
            if group_entry.messages.iter().any(|m| m.id == message_id) {
                return false;
            }
            group_entry
                .member_names
                .insert(member_id.clone(), member.name.clone());
            group_entry.messages.push(GroupPost {
                id: message_id.clone(),
                author_id: member_id,
                author_name: member.name.clone(),
                timestamp,
                text,
                body: to_hex(body),
                join,
            });
            group_entry.messages.sort_by_key(|m| m.timestamp);
            if !join {
                notify_chat(
                    group_hex.clone(),
                    format!("{} - {}", group_entry.name, member.name),
                    group_entry
                        .messages
                        .last()
                        .map(|m| m.text.clone())
                        .unwrap_or_default(),
                    true,
                );
            }
            if !group_entry.contacts.contains(&contact_id) {
                group_entry.contacts.push(contact_id);
            }
            others = group_entry
                .contacts
                .iter()
                .copied()
                .filter(|c| *c != contact_id)
                .collect();
        }
        // Pass it on to the other members, unchanged: that is what makes a
        // group work when not everyone can reach everyone.
        for other in others {
            store.queue(
                other,
                OutMessage {
                    id: message_id.clone(),
                    group: group_hex.clone(),
                    timestamp,
                    body: to_hex(body),
                    acked: false,
                },
            );
        }
        true
    }

    /// Tries every pending contact and every contact with an address.
    /// Eine Runde. Gibt zurueck, ob dabei mindestens eine Verbindung
    /// zustande kam -- der Taktgeber setzt daraufhin seinen Abstand zurueck.
    pub fn poll(&self) -> bool {
        let (contacts, pending): (Vec<u32>, Vec<(usize, Vec<String>)>) = {
            let store = self.store.lock().unwrap();
            let pending = store
                .state
                .pending
                .iter()
                .enumerate()
                .map(|(index, p)| {
                    let mut transports = Vec::new();
                    if p.address.is_some() {
                        transports.push(LAN_TRANSPORT_ID.to_string());
                    }
                    if p.bluetooth.is_some() {
                        transports.push(BLUETOOTH_TRANSPORT_ID.to_string());
                    }
                    if p.onion.is_some() {
                        transports.push(TOR_TRANSPORT_ID.to_string());
                    }
                    (index, transports)
                })
                .filter(|(_, transports)| !transports.is_empty())
                .collect();
            (
                store.state.contacts.iter().map(|c| c.id).collect(),
                pending,
            )
        };
        let mut erreicht = false;
        for (index, transports) in pending {
            let mut error = None;
            for transport in &transports {
                match self.connect_pending(index, transport) {
                    Ok(()) => {
                        error = None;
                        erreicht = true;
                        break;
                    }
                    Err(e) => error = Some(e.to_string()),
                }
            }
            if let Some(message) = error {
                let mut store = self.store.lock().unwrap();
                if let Some(p) = store.state.pending.get_mut(index) {
                    p.last_error = Some(message);
                }
                let _ = store.save();
            }
        }
        for id in contacts {
            match self.reach_contact(id) {
                Ok(()) => erreicht = true,
                Err(e) => log(&format!("contact {} not reachable: {}", id, e)),
            }
        }
        erreicht
    }
}

/// Die naechste ausgehende Stromnummer fuer diesen Zeitabschnitt.
///
/// Sie faengt in **jedem** Abschnitt bei null an -- genau wie bei Briar, wo
/// jede Schluesseldrehung neue `OutgoingKeys` ueber den
/// Vierargumenten-Erbauer erzeugt und der `streamCounter` auf 0 setzt
/// (OutgoingKeys.java:20-23). Ein ewig wachsender Zaehler laeuft nach dem
/// ersten Abschnittswechsel aus dem Fenster der Gegenseite heraus, und zwar
/// dauerhaft, weil er nur steigt.
pub fn naechste_stromnummer(zustand: &crate::store::TransportState, period: u64) -> u64 {
    if let Some(n) = zustand.out_streams.get(&period.to_string()) {
        return *n;
    }
    // Eine Datei aus einer Fassung bis 0.24.0 kennt nur den einen alten
    // Zaehler. Der gilt im laufenden Abschnitt weiter -- sonst bekaeme eine
    // Stromnummer darin zweimal dieselbe Marke.
    if zustand.out_streams.is_empty() && zustand.out_stream > 0 {
        return zustand.out_stream;
    }
    0
}

/// Die vergebene Nummer festhalten und alte Abschnitte wegraeumen: die
/// Gegenseite haelt ohnehin nur den vorigen, den jetzigen und den naechsten.
pub fn stromnummer_vormerken(
    zustand: &mut crate::store::TransportState,
    period: u64,
    vergeben: u64,
) {
    zustand.out_streams.insert(period.to_string(), vergeben + 1);
    zustand.out_streams.retain(|a, _| {
        a.parse::<u64>()
            .map(|p| p.max(period) - p.min(period) <= 1)
            .unwrap_or(false)
    });
    zustand.out_stream = 0;
}

/// Das Fenster der empfangenden Seite nachziehen.
///
/// Briars `ReorderingWindow.setSeen` schiebt nach zwei Regeln
/// (ReorderingWindow.java:61-64). Regel 1 -- so weit schieben, dass alles
/// oberhalb der Fenstermitte unbenutzt ist -- uebernehmen wir: ohne sie
/// bliebe der Fusspunkt auf null stehen, und sobald die Gegenseite in einem
/// Abschnitt ueber 31 Handschlaege hinauskommt, faellt ihre Marke aus
/// unserem Fenster.
///
/// Regel 2 -- so weit schieben, dass der Fusspunkt selbst unbenutzt ist --
/// uebernehmen wir absichtlich NICHT. Sie verbraucht die Marke, und beim
/// schwebenden Kontakt kann das nur schaden: ein geglueckter Handschlag
/// nimmt den Wartenden aus dem Speicher, dieses Fenster sieht also
/// ausschliesslich **gescheiterte** Versuche -- und eine Gegenseite mit der
/// Fassung bis 0.26.0 schickt jeden davon wieder mit der Nummer 0. Wer die
/// Marke verbraucht, sperrt genau die Wiederholung aus, auf die es ankommt.
pub fn fenster_nachziehen(
    zustand: &mut crate::store::TransportState,
    period: u64,
    gesehen: u64,
) {
    let abschnitt = period.to_string();
    let alt = *zustand.in_stream.get(&abschnitt).unwrap_or(&0);
    // Regel 1: die gesehene Nummer landet auf der Fenstermitte. Bei Nummer 0
    // rechnet das 0 - 15 = 0 -- der Fusspunkt ruehrt sich nicht, und eine
    // alte Gegenseite bleibt beliebig oft erkennbar.
    let neu = alt.max(gesehen.saturating_sub(WINDOW / 2 - 1));
    zustand.in_stream.insert(abschnitt, neu);
    // Die Gegenseite haelt ohnehin nur voriger, jetziger und naechster.
    zustand.in_stream.retain(|a, _| {
        a.parse::<u64>()
            .map(|p| p.max(period) - p.min(period) <= 1)
            .unwrap_or(false)
    });
}

/// Dasselbe fuer einen Wartenden im Speicher, samt Wegschreiben. Gebraucht an
/// beiden Stellen, an denen eine Handschlagmarke erkannt wird -- bei der
/// angenommenen und bei der selbst gewaehlten Verbindung.
fn fenster_vermerken(
    store: &Shared,
    schwebend: &str,
    transport_id: &str,
    period: u64,
    gesehen: u64,
) {
    let mut store = store.lock().unwrap();
    if let Some(pending) = store
        .state
        .pending
        .iter_mut()
        .find(|p| p.public_key == schwebend)
    {
        fenster_nachziehen(pending.transport_mut(transport_id), period, gesehen);
    }
    // Ein missglueckter Schreibversuch darf den Handschlag nicht abbrechen:
    // dann laeuft er mit dem alten Fusspunkt weiter, und der ist nie zu hoch.
    let _ = store.save();
}

fn short_transport(transport_id: &str) -> &str {
    if transport_id == BLUETOOTH_TRANSPORT_ID {
        "Bluetooth"
    } else if transport_id == TOR_TRANSPORT_ID {
        "Tor"
    } else {
        "LAN"
    }
}

fn dial(transport_id: &str, address: &str, kanal: Option<u8>) -> std::io::Result<Conn> {
    if transport_id == TOR_TRANSPORT_ID {
        let socks = tor::connect()
            .map(|t| t.socks_port)
            .ok_or_else(|| bad("no Tor is running on this device"))?;
        // The control connection from the listener keeps Tor alive; here
        // only the SOCKS port matters.
        return Ok(Conn::Tcp(tor::connect_through_socks(socks, address)?));
    }
    if transport_id == BLUETOOTH_TRANSPORT_ID {
        // Der Kanal steht nicht fest: Briar veroeffentlicht seinen Dienst
        // unter einer UUID, und der Kanal kommt aus der SDP-Suche. Nur wenn
        // die Gegenseite keine UUID gemeldet hat -- also unsere eigene
        // aeltere Fassung ist -- bleibt es beim festen Kanal.
        let stream = bt::connect(address, kanal.unwrap_or(bt::CHANNEL))?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        return Ok(Conn::Bluetooth(stream));
    }
    // Die Gegenseite meldet jedes Netz, in dem sie zuletzt stand, das engste
    // zuerst. Welcher Eintrag antwortet, ist der, in dem wir zusammen stehen.
    //
    // Vorher wird gesiebt, und das ist kein Feinschliff: eine Liste mit fuenf
    // veralteten Adressen aus fremden Netzen kostete sonst fuenf volle
    // Zeitueberschreitungen, auf dem N9 spuerbare Sekunden. Briar siebt an
    // derselben Stelle.
    let eigene = local_nets();
    let eigene6 = local_nets6();
    let mut last = bad("no reachable address");

    // Zuerst die link-lokalen IPv6-Adressen: sie stehen in
    // Klammerschreibweise in der Liste und brauchen einen Zonenindex, den die
    // Gegenseite nicht mitliefern kann -- also wird jede eigene
    // link-lokale Schnittstelle durchprobiert.
    for eintrag in address.split(',').map(str::trim) {
        let Some(rest) = eintrag.strip_prefix('[') else { continue };
        let Some((ip_teil, port_teil)) = rest.split_once("]:") else { continue };
        let Ok(ziel): Result<std::net::Ipv6Addr, _> = ip_teil.parse() else { continue };
        let Ok(port) = port_teil.parse::<u16>() else { continue };
        if port == 0 || !ipv6_link_local(&ziel) {
            continue;
        }
        for (eigen, zone) in &eigene6 {
            if *eigen == ziel {
                continue;                   // das sind wir selbst
            }
            let kandidat = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                ziel, port, 0, *zone,
            ));
            let quelle = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                *eigen, 0, 0, *zone,
            ));
            match connect_bound(Some(quelle), kandidat, CONNECT_TIMEOUT) {
                Ok(socket) => {
                    socket.set_read_timeout(Some(IO_TIMEOUT))?;
                    socket.set_write_timeout(Some(IO_TIMEOUT))?;
                    return Ok(Conn::Tcp(socket));
                }
                Err(err) => last = err,
            }
        }
    }

    for (ziel, port) in address.split(',').filter_map(parse_ip_port) {
        // Nur Adressen, die ein Gegenueber im selben Netz haben kann -- und
        // nur solche, die zu einem unserer eigenen Netze praefixgleich sind.
        // Eine Adresse aus einem Netz, in dem wir gar nicht stehen, kann uns
        // nicht antworten.
        if !reachable_by_a_contact(ziel.octets()) {
            continue;
        }
        if eigene.iter().any(|(ip, _)| *ip == ziel) {
            continue;                       // das sind wir selbst
        }
        if !eigene
            .iter()
            .any(|(ip, prefix)| same_network(*ip, *prefix, ziel))
        {
            continue;
        }
        let candidate = std::net::SocketAddr::from((ziel, port));
        // An die eigene Adresse in genau diesem Netz binden -- das Ergebnis
        // des Siebs oben liegt dafuer schon vor.
        let quelle = eigene
            .iter()
            .find(|(ip, prefix)| same_network(*ip, *prefix, ziel))
            .map(|(ip, _)| std::net::SocketAddr::from((*ip, 0)));
        match connect_bound(quelle, candidate, CONNECT_TIMEOUT) {
            Ok(socket) => {
                socket.set_read_timeout(Some(IO_TIMEOUT))?;
                socket.set_write_timeout(Some(IO_TIMEOUT))?;
                return Ok(Conn::Tcp(socket));
            }
            Err(err) => last = err,
        }
    }
    Err(last)
}

/// Ein Lauscher fuer link-lokales IPv6. Ausdruecklich nur IPv6: Linux macht
/// einen `[::]`-Socket sonst zweistoeckig, und dann kollidiert er mit dem
/// `0.0.0.0`-Socket auf demselben Port. std::net kann V6ONLY nicht setzen.
fn bind_listener6(port: u16) -> std::io::Result<std::net::TcpListener> {
    use std::os::unix::io::FromRawFd;
    let griff = unsafe {
        libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    };
    if griff < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let lauscher = unsafe { std::net::TcpListener::from_raw_fd(griff) };
    let an: libc::c_int = 1;
    for (ebene, option) in [
        (libc::IPPROTO_IPV6, libc::IPV6_V6ONLY),
        (libc::SOL_SOCKET, libc::SO_REUSEADDR),
    ] {
        let ok = unsafe {
            libc::setsockopt(
                griff,
                ebene,
                option,
                &an as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ok != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let adresse = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        port,
        0,
        0,
    ));
    let (zeiger, laenge) = sockaddr_bytes(&adresse);
    if unsafe { libc::bind(griff, zeiger.as_ptr() as *const libc::sockaddr, laenge) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::listen(griff, 8) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(lauscher)
}

/// Briars Sieb fuer IPv6: **nur link-lokal** (`fe80::/10`). Standortlokale
/// IPv6-Adressen gibt es nicht mehr, und eine globale wuerde dem Kontakt
/// verraten, in welchem Netz man steht -- deshalb laesst Briar sie nicht zu.
fn ipv6_link_local(ip: &std::net::Ipv6Addr) -> bool {
    let s = ip.segments();
    s[0] & 0xffc0 == 0xfe80
}

/// Die eigenen link-lokalen IPv6-Adressen mit ihrem Zonenindex.
pub fn local_nets6() -> Vec<(std::net::Ipv6Addr, u32)> {
    let mut found: Vec<(std::net::Ipv6Addr, u32)> = Vec::new();
    unsafe {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return Vec::new();
        }
        let mut cur = list;
        while !cur.is_null() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null()
                || ifa.ifa_flags & libc::IFF_UP as u32 == 0
                || ifa.ifa_flags & libc::IFF_LOOPBACK as u32 != 0
                || (*ifa.ifa_addr).sa_family != libc::AF_INET6 as libc::sa_family_t
            {
                continue;
            }
            let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            if !ipv6_link_local(&ip) {
                continue;
            }
            if !found.iter().any(|(a, _)| *a == ip) {
                found.push((ip, addr.sin6_scope_id));
            }
        }
        libc::freeifaddrs(list);
    }
    found
}

/// Eine IPv6-Adresse als die 32 Hexzeichen, die Briar meldet.
fn ipv6_hex(ip: &std::net::Ipv6Addr) -> String {
    ip.octets().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Und zurueck. Alles, was keine 32 Hexzeichen sind, wird still verworfen.
fn ipv6_from_hex(hex: &str) -> Option<std::net::Ipv6Addr> {
    let hex = hex.trim();
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    let ip = std::net::Ipv6Addr::from(bytes);
    if ipv6_link_local(&ip) { Some(ip) } else { None }
}

/// Eine gemeldete IPv6-Liste saeubern: nur brauchbare Eintraege, Reihenfolge
/// unangetastet.
fn clean_ipv6_list(list: &str) -> String {
    list.split(',')
        .filter_map(|e| ipv6_from_hex(e).map(|ip| ipv6_hex(&ip)))
        .collect::<Vec<_>>()
        .join(",")
}

/// Wie `note_local_addresses`, nur fuer IPv6.
pub fn note_local_addresses6(state: &mut crate::store::State) -> bool {
    let mut neu = false;
    for (ip, _) in local_nets6().into_iter().rev() {
        let eintrag = ipv6_hex(&ip);
        if let Some(stelle) = state.lan6_recent.iter().position(|e| *e == eintrag) {
            state.lan6_recent.remove(stelle);
        } else {
            neu = true;
        }
        state.lan6_recent.insert(0, eintrag);
    }
    // Ein Eintrag ist 32 Byte, mit Komma 33 -- es passen also drei.
    while state.lan6_recent.len() > 1
        && state.lan6_recent.join(",").len() > MAX_PROPERTY_LENGTH
    {
        state.lan6_recent.pop();
    }
    neu
}

/// Verbinden und dabei die eigene Quelladresse festlegen.
///
/// Warum nicht `TcpStream::connect_timeout`: das kann keine Quelladresse
/// binden. Ohne sie waehlt der Kernel die Schnittstelle nach der Routentabelle
/// -- auf einem Geraet mit aktiver Mobilfunkverbindung heisst das, dass ein
/// Versuch ins WLAN womoeglich ueber das Mobilfunknetz hinausgeht und dort ins
/// Leere laeuft. Briar loest dasselbe Problem auf Android mit der
/// SocketFactory des WLAN-Netzes; auf Linux ist das Gegenstueck das Binden.
///
/// SOCK_CLOEXEC ist nicht kosmetisch: ein spaeter gestartetes Hilfsprogramm
/// (Tor) wuerde den Griff sonst erben und festhalten.
fn connect_bound(
    local: Option<std::net::SocketAddr>,
    ziel: std::net::SocketAddr,
    frist: Duration,
) -> std::io::Result<TcpStream> {
    use std::os::unix::io::FromRawFd;

    let familie = match ziel {
        std::net::SocketAddr::V4(_) => libc::AF_INET,
        std::net::SocketAddr::V6(_) => libc::AF_INET6,
    };
    let griff = unsafe {
        libc::socket(familie, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    };
    if griff < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Ab hier gehoert der Griff dem TcpStream, damit er auf jedem Rueckweg
    // geschlossen wird -- auch auf den Fehlerwegen unten.
    let strom = unsafe { TcpStream::from_raw_fd(griff) };

    if let Some(quelle) = local {
        let (zeiger, laenge) = sockaddr_bytes(&quelle);
        let ok = unsafe {
            libc::bind(griff, zeiger.as_ptr() as *const libc::sockaddr, laenge)
        };
        if ok != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Nicht blockierend verbinden und mit Frist warten: ein blockierendes
    // connect() haengt sonst an der Zeitgrenze des Kernels, die deutlich
    // laenger ist als unsere.
    unsafe {
        let flags = libc::fcntl(griff, libc::F_GETFL, 0);
        libc::fcntl(griff, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let (zeiger, laenge) = sockaddr_bytes(&ziel);
    let begonnen = unsafe {
        libc::connect(griff, zeiger.as_ptr() as *const libc::sockaddr, laenge)
    };
    if begonnen != 0 {
        let fehler = std::io::Error::last_os_error();
        if fehler.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(fehler);
        }
        let mut schreiben: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe { libc::FD_ZERO(&mut schreiben) };
        unsafe { libc::FD_SET(griff, &mut schreiben) };
        let mut wartezeit = libc::timeval {
            tv_sec: frist.as_secs() as libc::time_t,
            tv_usec: frist.subsec_micros() as libc::suseconds_t,
        };
        let bereit = unsafe {
            libc::select(
                griff + 1,
                std::ptr::null_mut(),
                &mut schreiben,
                std::ptr::null_mut(),
                &mut wartezeit,
            )
        };
        if bereit == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timed out",
            ));
        }
        if bereit < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // select() meldet auch einen gescheiterten Versuch als "schreibbar";
        // der Grund steht in SO_ERROR.
        let mut fehlernummer: libc::c_int = 0;
        let mut groesse = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let gelesen = unsafe {
            libc::getsockopt(
                griff,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut fehlernummer as *mut _ as *mut libc::c_void,
                &mut groesse,
            )
        };
        if gelesen != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if fehlernummer != 0 {
            return Err(std::io::Error::from_raw_os_error(fehlernummer));
        }
    }
    unsafe {
        let flags = libc::fcntl(griff, libc::F_GETFL, 0);
        libc::fcntl(griff, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }
    Ok(strom)
}

/// Eine Adresse in die Bytes, die bind()/connect() erwarten.
fn sockaddr_bytes(adresse: &std::net::SocketAddr) -> (Vec<u8>, libc::socklen_t) {
    match adresse {
        std::net::SocketAddr::V4(v4) => {
            let mut roh: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            roh.sin_family = libc::AF_INET as libc::sa_family_t;
            roh.sin_port = v4.port().to_be();
            roh.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            let groesse = std::mem::size_of::<libc::sockaddr_in>();
            let bytes = unsafe {
                std::slice::from_raw_parts(&roh as *const _ as *const u8, groesse).to_vec()
            };
            (bytes, groesse as libc::socklen_t)
        }
        std::net::SocketAddr::V6(v6) => {
            let mut roh: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            roh.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            roh.sin6_port = v6.port().to_be();
            roh.sin6_addr.s6_addr = v6.ip().octets();
            // Der Zonenindex: ohne ihn weiss der Kernel bei einer
            // link-lokalen Adresse nicht, ueber welche Schnittstelle.
            roh.sin6_scope_id = v6.scope_id();
            let groesse = std::mem::size_of::<libc::sockaddr_in6>();
            let bytes = unsafe {
                std::slice::from_raw_parts(&roh as *const _ as *const u8, groesse).to_vec()
            };
            (bytes, groesse as libc::socklen_t)
        }
    }
}

/// Liegen zwei Adressen im selben Netz? Verglichen werden die ersten `prefix`
/// Bits -- bitweise, nicht byteweise, sonst waere ein /20 falsch beurteilt.
fn same_network(local: std::net::Ipv4Addr, prefix: u32, remote: std::net::Ipv4Addr) -> bool {
    if prefix == 0 || prefix > 32 {
        return false;
    }
    let a = u32::from_be_bytes(local.octets());
    let b = u32::from_be_bytes(remote.octets());
    let maske = if prefix == 32 { u32::MAX } else { !(u32::MAX >> prefix) };
    a & maske == b & maske
}

fn bad(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg.to_string())
}

/// A fresh outgoing private message, for the API.
pub fn new_outgoing_message(group_id: &SecretKey, text: &str) -> (Message, OutMessage) {
    let timestamp = now_ms();
    let body = sync::private_message_body(text);
    let id = to_hex(&ids::message_id(group_id, timestamp, &body));
    (
        Message {
            id: id.clone(),
            timestamp,
            text: text.to_string(),
            outgoing: true,
            acked: false,
            attachment: None,
            attachment_type: None,
        },
        OutMessage {
            id,
            group: to_hex(group_id),
            timestamp,
            body: to_hex(&body),
            acked: false,
        },
    )
}

pub fn messaging_group_for(store: &Store, contact_id: u32) -> Option<SecretKey> {
    let identity = store.identity()?;
    let contact = store.contact(contact_id)?;
    Some(sync::messaging_group_id(
        &key_from_hex(&identity.author_id),
        &contact.author_id_bytes(),
    ))
}

/// The author record of the local identity, for signing group messages.
pub fn local_author(store: &Store) -> Option<(Author, SecretKey)> {
    let identity = store.identity()?;
    Some((
        Author {
            name: identity.name.clone(),
            public_key: from_hex(&identity.signature_public)?,
        },
        key_from_hex(&identity.signature_seed),
    ))
}

#[cfg(test)]
mod adress_tests {
    use super::*;

    #[test]
    fn ip_port_wird_streng_gelesen() {
        assert_eq!(
            parse_ip_port("192.168.1.21:7327"),
            Some(("192.168.1.21".parse().unwrap(), 7327))
        );
        // Kein Name: ein Kontakt darf uns nicht zu einer Namensabfrage
        // verleiten. Genau dagegen baut Briar sein Punkt-Quad-Muster ein.
        assert_eq!(parse_ip_port("briarproject.org:7327"), None);
        assert_eq!(parse_ip_port("192.168.1.21:0"), None);
        assert_eq!(parse_ip_port("192.168.1.21"), None);
        assert_eq!(parse_ip_port("nonsens"), None);
    }

    #[test]
    fn kaputte_stuecke_verwerfen_nicht_die_liste() {
        assert_eq!(
            clean_address_list("192.168.1.21:7327, murks, 10.0.0.2:9"),
            "192.168.1.21:7327,10.0.0.2:9"
        );
    }

    #[test]
    fn gleiches_netz_wird_bitweise_verglichen() {
        let a: std::net::Ipv4Addr = "192.168.1.21".parse().unwrap();
        assert!(same_network(a, 24, "192.168.1.99".parse().unwrap()));
        assert!(!same_network(a, 24, "192.168.2.99".parse().unwrap()));
        // /20 faellt byteweise auf die Nase, bitweise nicht.
        let b: std::net::Ipv4Addr = "10.0.16.1".parse().unwrap();
        assert!(same_network(b, 20, "10.0.31.255".parse().unwrap()));
        assert!(!same_network(b, 20, "10.0.32.1".parse().unwrap()));
        assert!(!same_network(a, 0, "192.168.1.22".parse().unwrap()));
    }

    #[test]
    fn gedaechtnis_bleibt_unter_briars_laengengrenze() {
        // Briars Pruefer verwirft bei Ueberlaenge die GANZE
        // Eigenschaftsnachricht, nicht nur den zu langen Wert -- eine
        // unbegrenzte Liste macht uns fuer echtes Briar unsichtbar.
        let mut liste: Vec<String> = Vec::new();
        for i in 1..=12 {
            liste.insert(0, format!("192.168.{}.21:45678", i));
            while liste.len() > 1 && liste.join(",").len() > MAX_PROPERTY_LENGTH {
                liste.pop();
            }
        }
        let verbunden = liste.join(",");
        assert!(
            verbunden.len() <= MAX_PROPERTY_LENGTH,
            "zu lang: {} Byte -- {}",
            verbunden.len(),
            verbunden
        );
        // Die zuletzt gesehene Adresse steht vorne.
        assert!(verbunden.starts_with("192.168.12.21:45678"));
        // Und es bleibt mehr als eine uebrig, sonst waere das Gedaechtnis
        // nutzlos.
        assert!(liste.len() >= 4, "nur {} Eintraege", liste.len());
    }
}

#[cfg(test)]
mod ipv6_tests {
    use super::*;

    #[test]
    fn nur_link_lokales_ipv6() {
        assert!(ipv6_link_local(&"fe80::1".parse().unwrap()));
        assert!(ipv6_link_local(&"febf::1".parse().unwrap()));
        // Global und eindeutig-lokal laesst Briar nicht zu: eine globale
        // Adresse verriete dem Kontakt, in welchem Netz man steht.
        assert!(!ipv6_link_local(&"2001:db8::1".parse().unwrap()));
        assert!(!ipv6_link_local(&"fc00::1".parse().unwrap()));
        assert!(!ipv6_link_local(&"fec0::1".parse().unwrap()));
    }

    #[test]
    fn hex_hin_und_zurueck() {
        let ip: std::net::Ipv6Addr = "fe80::215:5dff:fe01:203".parse().unwrap();
        let hex = ipv6_hex(&ip);
        assert_eq!(hex.len(), 32);
        assert_eq!(ipv6_from_hex(&hex), Some(ip));
        // Kaputtes wird still verworfen, nicht geraten.
        assert_eq!(ipv6_from_hex("kurz"), None);
        assert_eq!(ipv6_from_hex(&"z".repeat(32)), None);
        // Eine globale Adresse kommt auch als Hex nicht durch.
        let global: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(ipv6_from_hex(&ipv6_hex(&global)), None);
    }

    #[test]
    fn ipv6_liste_wird_gesaeubert() {
        let a = ipv6_hex(&"fe80::1".parse().unwrap());
        let b = ipv6_hex(&"2001:db8::1".parse().unwrap());
        assert_eq!(clean_ipv6_list(&format!("{},murks,{}", a, b)), a);
    }
}

#[cfg(test)]
mod stromnummer_tests {
    use super::*;
    use crate::store::TransportState;

    #[test]
    fn jeder_abschnitt_faengt_bei_null_an() {
        // Das ist Briars Verhalten: bei jeder Drehung entstehen neue
        // OutgoingKeys mit streamCounter 0.
        let mut z = TransportState::default();
        for n in 0..5u64 {
            assert_eq!(naechste_stromnummer(&z, 100), n);
            stromnummer_vormerken(&mut z, 100, n);
        }
        // Neuer Abschnitt -> wieder bei null.
        assert_eq!(naechste_stromnummer(&z, 101), 0);
    }

    #[test]
    fn alter_zaehler_gilt_im_laufenden_abschnitt_weiter() {
        // Sonst bekaeme eine Stromnummer in diesem Abschnitt zweimal
        // dieselbe Marke, und die Gegenseite verwuerfe sie als Wiederholung.
        let mut z = TransportState::default();
        z.out_stream = 17;
        assert_eq!(naechste_stromnummer(&z, 100), 17);
        stromnummer_vormerken(&mut z, 100, 17);
        assert_eq!(naechste_stromnummer(&z, 100), 18);
        // Im naechsten Abschnitt zaehlt der alte nicht mehr.
        assert_eq!(naechste_stromnummer(&z, 101), 0);
        assert_eq!(z.out_stream, 0, "der alte Zaehler wird nicht weitergefuehrt");
    }

    #[test]
    fn weit_zurueckliegende_abschnitte_werden_weggeraeumt() {
        let mut z = TransportState::default();
        stromnummer_vormerken(&mut z, 100, 0);
        stromnummer_vormerken(&mut z, 101, 0);
        stromnummer_vormerken(&mut z, 102, 0);
        // Die Gegenseite haelt nur voriger, jetziger und naechster.
        assert!(!z.out_streams.contains_key("100"));
        assert!(z.out_streams.contains_key("101"));
        assert!(z.out_streams.contains_key("102"));
    }

    #[test]
    fn fenster_folgt_der_gegenseite() {
        // Regel 1 aus Briars ReorderingWindow: die gesehene Nummer landet auf
        // der Fenstermitte. Ohne das bliebe der Fusspunkt auf null, und ab
        // Nummer 32 waere die Gegenseite in diesem Abschnitt stumm.
        let mut z = TransportState::default();
        fenster_nachziehen(&mut z, 100, 20);
        assert_eq!(z.in_stream["100"], 5, "20 - (32/2 - 1)");
        let fuss = z.in_stream["100"];
        assert!(20 >= fuss && 20 < fuss + WINDOW, "die gesehene Nummer bleibt drin");
        // Und der Fusspunkt geht nie zurueck.
        fenster_nachziehen(&mut z, 100, 6);
        assert_eq!(z.in_stream["100"], 5);
    }

    #[test]
    fn alte_gegenseite_bleibt_erreichbar() {
        // Eine Gegenseite mit der Fassung bis 0.26.0 schickt jeden Versuch
        // mit der Nummer 0. Regel 2 (Marke verbrauchen) fehlt absichtlich --
        // mit ihr waere der zweite Versuch nicht mehr zu erkennen, und das
        // ist genau der Fall, der heute zwischen Jolla, N9 und N950 laeuft.
        let mut z = TransportState::default();
        for _ in 0..50 {
            fenster_nachziehen(&mut z, 100, 0);
            assert_eq!(z.in_stream["100"], 0);
        }
    }

    #[test]
    fn zaehler_und_fenster_laufen_im_takt() {
        // Der eigentliche Beweis: was die eine Seite vergibt, muss die andere
        // in ihrem Fenster finden -- 200 Versuche im selben Abschnitt.
        let mut sender = TransportState::default();
        let mut empfaenger = TransportState::default();
        for _ in 0..200 {
            let n = naechste_stromnummer(&sender, 100);
            stromnummer_vormerken(&mut sender, 100, n);
            let fuss = *empfaenger.in_stream.get("100").unwrap_or(&0);
            assert!(
                n >= fuss && n < fuss + WINDOW,
                "Nummer {} liegt neben dem Fenster ab {}",
                n,
                fuss
            );
            fenster_nachziehen(&mut empfaenger, 100, n);
        }
    }

    #[test]
    fn schwebender_zaehlt_je_transport() {
        // LAN, Bluetooth und Tor haben eigene Schluessel, also eigene Marken
        // und eigene Zaehler -- ein Zaehler je Wartendem waere zu wenig.
        use crate::store::PendingContact;
        let mut p = PendingContact {
            public_key: "aa".into(),
            alias: String::new(),
            address: None,
            bluetooth: None,
            onion: None,
            added: 0,
            last_error: None,
            transports: std::collections::BTreeMap::new(),
        };
        for n in 0..3u64 {
            let z = p.transport_mut(LAN_TRANSPORT_ID);
            assert_eq!(naechste_stromnummer(z, 100), n);
            stromnummer_vormerken(z, 100, n);
        }
        let z = p.transport_mut(BLUETOOTH_TRANSPORT_ID);
        assert_eq!(naechste_stromnummer(z, 100), 0);
    }
}
