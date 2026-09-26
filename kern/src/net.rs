//! The transports and the connection logic on top of them.
//!
//! Briar reaches a contact it has only a link for through a rendezvous over
//! Tor. Here all three routes exist, but the meeting place does not: the
//! peer's ip:port, Bluetooth address or onion address goes in beside the
//! link, and we dial it.
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
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
        for p in periods {
            // Incoming keys belong to the peer's role
            let keys = derive_handshake_keys(transport_id, &root, p, !alice);
            for stream_number in 0..WINDOW {
                if encode_tag(&keys.tag_key, PROTOCOL_VERSION, stream_number) == tag[..] {
                    return Some(Recognised::Pending {
                        index,
                        header_key: keys.header_key,
                        stream_number,
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

/// Our own LAN address, as far as a UDP socket can tell us.
pub fn local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.168.1.1:9").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn local_properties(
    port: u16,
    bluetooth: bool,
    onion: Option<String>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut props = BTreeMap::new();
    let mut lan = BTreeMap::new();
    lan.insert("port".to_string(), port.to_string());
    if let Some(ip) = local_ip() {
        lan.insert("ipPorts".to_string(), format!("{}:{}", ip, port));
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
            // Briar publishes a UUID per device over SDP and looks the
            // channel up; without SDP the channel is fixed, and this says
            // which one.
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
            if let Some(first) = ip_ports.split(',').next() {
                if !first.trim().is_empty() {
                    address = Some(first.trim().to_string());
                }
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
struct LazyHandshakeReader {
    conn: Conn,
    transport_id: String,
    root: SecretKey,
    peer_is_alice: bool,
    stream: Option<StreamReader<Conn>>,
}

impl Read for LazyHandshakeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.stream.is_none() {
            let mut tag = [0u8; TAG_LEN];
            self.conn.read_exact(&mut tag)?;
            let period = current_time_period();
            let mut found = None;
            for p in [period.saturating_sub(1), period, period + 1] {
                let keys =
                    derive_handshake_keys(&self.transport_id, &self.root, p, self.peer_is_alice);
                for stream_number in 0..WINDOW {
                    if encode_tag(&keys.tag_key, PROTOCOL_VERSION, stream_number) == tag {
                        found = Some((keys.header_key, stream_number));
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
            }
            let (header_key, stream_number) =
                found.ok_or_else(|| bad("the peer's handshake tag was not recognised"))?;
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

    fn spawn_incoming(&self, conn: Conn, transport_id: &'static str, peer_ip: Option<String>) {
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
                alice,
            }) => {
                log(&format!("incoming handshake connection ({})", transport_id));
                let root = {
                    let store = self.store.lock().unwrap();
                    let pending = store
                        .state
                        .pending
                        .get(index)
                        .ok_or_else(|| bad("pending contact vanished"))?;
                    pending_keys(&store, &pending.public_key)
                        .ok_or_else(|| bad("no identity yet"))?
                        .0
                };
                let keys =
                    derive_handshake_keys(transport_id, &root, current_time_period(), alice);
                let writer = StreamWriter::new(conn.try_clone()?, &keys, 0);
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
    pub fn connect_pending(&self, index: usize, transport_id: &str) -> std::io::Result<()> {
        let (address, alice, root) = {
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
            let (root, alice) =
                pending_keys(&store, &pending.public_key).ok_or_else(|| bad("no identity yet"))?;
            (address, alice, root)
        };
        let conn = dial(transport_id, &address)?;
        let keys = derive_handshake_keys(transport_id, &root, current_time_period(), alice);
        let peer_ip = match &conn {
            Conn::Tcp(s) => s.peer_addr().ok().map(|a| a.ip().to_string()),
            Conn::Bluetooth(_) => None,
        };
        let mut writer = StreamWriter::new(conn.try_clone()?, &keys, 0);
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
        let (our_private, our_public, our_seed, our_name, our_signature_public, port, bluetooth, onion) = {
            let store = self.store.lock().unwrap();
            let identity = store.identity().ok_or_else(|| bad("no identity yet"))?;
            (
                key_from_hex(&identity.handshake_private),
                key_from_hex(&identity.handshake_public),
                key_from_hex(&identity.signature_seed),
                identity.name.clone(),
                key_from_hex(&identity.signature_public),
                store.state.listen_port,
                store.state.bluetooth,
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
            properties: local_properties(port, bluetooth, onion),
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
            store
                .contact(id)
                .and_then(|c| c.address(transport_id))
                .ok_or_else(|| bad("no address for this contact"))?
        };
        let conn = dial(transport_id, &address)?;
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
                Some(contact) => contact
                    .transports
                    .iter()
                    .filter(|(_, state)| state.address.is_some())
                    .map(|(transport, _)| transport.clone())
                    .collect(),
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
        let (out_keys, out_stream, to_send, to_ack, versioning_pending) = {
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
            let properties = local_properties(
                store.state.listen_port,
                store.state.bluetooth,
                store.state.tor_onion.clone(),
            );
            let fingerprint = properties_fingerprint(&properties);
            if store
                .contact(contact_id)
                .map(|c| c.sent_properties.as_deref() != Some(fingerprint.as_str()))
                .unwrap_or(false)
            {
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
            let versioning_pending = !contact.sent_versioning_update;
            let out_stream = contact
                .transport(transport_id)
                .map(|t| t.out_stream)
                .unwrap_or(0);
            if let Some(c) = store.contact_mut(contact_id) {
                c.transport_mut(transport_id).out_stream = out_stream + 1;
            }
            store.save()?;
            (keys, out_stream, to_send, to_ack, versioning_pending)
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
            let body = sync::versioning_update_body(1);
            sync::write_message(&mut writer, &versioning_group, now_ms(), &body)?;
        }
        sync::write_ack(&mut writer, &to_ack)?;
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
        let mut received: Vec<(SecretKey, SecretKey, u64, Vec<u8>)> = Vec::new();
        loop {
            match read_record(&mut reader) {
                Ok(Some(record)) => {
                    if record.protocol_version != sync::PROTOCOL_VERSION {
                        continue;
                    }
                    match record.record_type {
                        sync::ACK => acked_ids.extend(sync::parse_ids(&record.payload)),
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

        let acked_now: Vec<String> = to_ack.iter().map(|id| to_hex(id)).collect();
        let mut new_messages = 0;
        {
            let mut store = self.store.lock().unwrap();
            if let Some(contact) = store.contact_mut(contact_id) {
                let peer_acked: Vec<String> = acked_ids.iter().map(|id| to_hex(id)).collect();
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
                }
                if transport_id == LAN_TRANSPORT_ID {
                    let state = contact.transport_mut(LAN_TRANSPORT_ID);
                    if state.address.is_none() {
                        if let Some(ip) = peer_ip {
                            state.address = Some(format!("{}:{}", ip, DEFAULT_PORT));
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
            if let Some((transport, _version, values)) = sync::parse_properties_update(body) {
                let address = match transport.as_str() {
                    t if t == LAN_TRANSPORT_ID => values
                        .get("ipPorts")
                        .cloned()
                        .or_else(|| values.get("ipPort").cloned()),
                    t if t == BLUETOOTH_TRANSPORT_ID => values.get("address").cloned(),
                    t if t == TOR_TRANSPORT_ID => values.get("onion3").cloned(),
                    _ => None,
                };
                if let (Some(address), Some(contact)) = (address, store.contact_mut(contact_id)) {
                    let entry = contact.transport_mut(&transport);
                    if entry.address.as_deref() != Some(address.as_str()) {
                        entry.address = Some(address.clone());
                        log(&format!(
                            "contact {} announced {} for {}",
                            contact_id, address, transport
                        ));
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
                log("a group message did not verify");
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
    pub fn poll(&self) {
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
        for (index, transports) in pending {
            let mut error = None;
            for transport in &transports {
                match self.connect_pending(index, transport) {
                    Ok(()) => {
                        error = None;
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
            if let Err(e) = self.reach_contact(id) {
                log(&format!("contact {} not reachable: {}", id, e));
            }
        }
    }
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

fn dial(transport_id: &str, address: &str) -> std::io::Result<Conn> {
    if transport_id == TOR_TRANSPORT_ID {
        let socks = tor::connect()
            .map(|t| t.socks_port)
            .ok_or_else(|| bad("no Tor is running on this device"))?;
        // The control connection from the listener keeps Tor alive; here
        // only the SOCKS port matters.
        return Ok(Conn::Tcp(tor::connect_through_socks(socks, address)?));
    }
    if transport_id == BLUETOOTH_TRANSPORT_ID {
        let stream = bt::connect(address, bt::CHANNEL)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        return Ok(Conn::Bluetooth(stream));
    }
    let addresses: Vec<std::net::SocketAddr> = {
        use std::net::ToSocketAddrs;
        address.to_socket_addrs()?.collect()
    };
    let first = addresses
        .first()
        .ok_or_else(|| bad("cannot resolve address"))?;
    let socket = TcpStream::connect_timeout(first, CONNECT_TIMEOUT)?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(Conn::Tcp(socket))
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
