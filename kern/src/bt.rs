//! Bluetooth RFCOMM, without BlueZ.
//!
//! An RFCOMM socket is an ordinary socket: AF_BLUETOOTH, SOCK_STREAM,
//! BTPROTO_RFCOMM, with a sockaddr carrying the peer's address and a channel
//! number. That is all this module does -- no library, no D-Bus, which
//! matters because the two devices have BlueZ 4 (Harmattan) and BlueZ 5
//! (Sailfish) and nothing in common above the kernel.
//!
//! What is missing compared to Briar: SDP. Briar advertises a per-device
//! UUID and looks up the channel for it. Registering an SDP record needs
//! BlueZ, so this port uses one fixed channel instead and is told the peer's
//! address, exactly like the LAN transport is told ip:port.

use std::io;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;

const AF_BLUETOOTH: libc::c_int = 31;
const BTPROTO_RFCOMM: libc::c_int = 3;

/// The channel both sides use. Briar picks one per device and publishes it
/// over SDP; without SDP a fixed number is the honest substitute.
pub const CHANNEL: u8 = 11;

/// Die UUID, unter der ein Geraet seinen Dienst anbietet.
///
/// Briar adressiert einen Kontakt ueber Bluetooth nicht mit einem festen
/// Kanal, sondern mit einer **zufaelligen UUID je Geraet**: sie wird als
/// Transporteigenschaft `uuid` gemeldet, per SDP veroeffentlicht, und die
/// Gegenseite sucht damit den Kanal (BluetoothConstants.PROP_UUID,
/// UUID_BYTES = 16). Ein fester Kanal funktioniert nur im eigenen Kreis.
///
/// Briar erzeugt sie mit `UUID.nameUUIDFromBytes` aus 16 Zufallsbytes, also
/// als Fassung 3. Wir wuerfeln eine der Fassung 4. Das ist der einzige
/// bewusste Unterschied im ganzen Abgleich, und er ist folgenlos: die UUID
/// ist fuer die Gegenseite ein undurchsichtiger Bezeichner, den sie nur in
/// der SDP-Suche wiedererkennt -- die Fassungsziffer wird nirgends geprueft.
/// MD5 nur dafuer mitzuschleppen waere der schlechtere Tausch.
pub fn random_uuid() -> String {
    let mut b = [0u8; 16];
    b.copy_from_slice(&crate::util::random(16));
    b[6] = (b[6] & 0x0f) | 0x40; // Fassung 4
    b[8] = (b[8] & 0x3f) | 0x80; // Variante 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
    .replace(' ', "")
}

/// Eine UUID-Zeichenkette in ihre 16 Bytes, fuer die SDP-Suche.
pub fn uuid_bytes(uuid: &str) -> Option<[u8; 16]> {
    let hex: String = uuid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// struct sockaddr_rc. The kernel's version is not packed: the trailing
/// channel byte is followed by one byte of padding, and a connect() with the
/// shorter length is refused with EINVAL.
#[repr(C)]
struct SockaddrRc {
    family: libc::sa_family_t,
    bdaddr: [u8; 6],
    channel: u8,
    padding: u8,
}

/// Bluetooth addresses go over the wire in reverse byte order.
fn parse_address(address: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = address.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        let byte = u8::from_str_radix(part, 16).ok()?;
        out[5 - i] = byte;
    }
    Some(out)
}

pub fn format_address(bdaddr: &[u8; 6]) -> String {
    let mut parts = Vec::with_capacity(6);
    for i in (0..6).rev() {
        parts.push(format!("{:02X}", bdaddr[i]));
    }
    parts.join(":")
}

/// This device's own Bluetooth address, for telling contacts about.
///
/// Harmattan puts it in sysfs; Sailfish on this hardware does not, so the
/// second way is the HCI ioctl every BlueZ version has answered since the
/// beginning.
pub fn local_address() -> Option<String> {
    if let Ok(entries) = std::fs::read_dir("/sys/class/bluetooth") {
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path().join("address")) {
                let address = text.trim().to_uppercase();
                if address.len() == 17 {
                    return Some(address);
                }
            }
        }
    }
    // A device may have more than one adapter, and only one of them is up
    // -- this Jolla answers on hci1 while hci0 exists but is down.
    for device in 0..4 {
        if let Some((bdaddr, flags)) = device_info(device) {
            if flags & HCI_UP != 0 {
                return Some(format_address(&bdaddr));
            }
        }
    }
    for device in 0..4 {
        if let Some((bdaddr, _)) = device_info(device) {
            return Some(format_address(&bdaddr));
        }
    }
    None
}

/// The address of the adapter that is up, for binding outgoing connections
/// to it.
fn active_adapter() -> Option<[u8; 6]> {
    for device in 0..4 {
        if let Some((bdaddr, flags)) = device_info(device) {
            if flags & HCI_UP != 0 {
                return Some(bdaddr);
            }
        }
    }
    None
}

const BTPROTO_HCI: libc::c_int = 1;
/// HCIGETDEVINFO, _IOR('H', 211, int)
const HCIGETDEVINFO: u64 = 0x800448d3;

/// HCI_UP, the first flag bit of hci_dev_info.flags
const HCI_UP: u32 = 1;

fn device_info(device: u16) -> Option<([u8; 6], u32)> {
    // SOCK_CLOEXEC, or the bundled Tor we start later inherits this
    // socket -- a listener then keeps its RFCOMM channel after we are gone.
    let fd = unsafe { libc::socket(AF_BLUETOOTH, libc::SOCK_RAW | libc::SOCK_CLOEXEC, BTPROTO_HCI) };
    if fd < 0 {
        return None;
    }
    // struct hci_dev_info starts with the device number, an eight-byte name
    // and the address; the rest does not matter here, but the kernel writes
    // the whole struct, so the buffer has to be roomy.
    let mut info = [0u8; 256];
    info[0] = (device & 0xff) as u8;
    info[1] = (device >> 8) as u8;
    let result = unsafe { libc::ioctl(fd, HCIGETDEVINFO as _, info.as_mut_ptr()) };
    unsafe { libc::close(fd) };
    if result < 0 {
        return None;
    }
    let mut bdaddr = [0u8; 6];
    bdaddr.copy_from_slice(&info[10..16]);
    if bdaddr.iter().all(|b| *b == 0) {
        return None;
    }
    let flags = u32::from_ne_bytes([info[16], info[17], info[18], info[19]]);
    Some((bdaddr, flags))
}

fn socket() -> io::Result<libc::c_int> {
    let fd = unsafe {
        libc::socket(AF_BLUETOOTH, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, BTPROTO_RFCOMM)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub struct Listener {
    fd: libc::c_int,
}

impl Listener {
    /// Binds the channel on every local adapter.
    pub fn bind(channel: u8) -> io::Result<Listener> {
        let fd = socket()?;
        let address = SockaddrRc {
            family: AF_BLUETOOTH as libc::sa_family_t,
            bdaddr: [0u8; 6], // BDADDR_ANY
            channel,
            padding: 0,
        };
        let result = unsafe {
            libc::bind(
                fd,
                &address as *const SockaddrRc as *const libc::sockaddr,
                std::mem::size_of::<SockaddrRc>() as libc::socklen_t,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }
        if unsafe { libc::listen(fd, 4) } < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error);
        }
        Ok(Listener { fd })
    }

    /// Waits for a connection and returns it with the peer's address.
    pub fn accept(&self) -> io::Result<(UnixStream, String)> {
        let mut address = SockaddrRc {
            family: 0,
            bdaddr: [0u8; 6],
            channel: 0,
            padding: 0,
        };
        let mut length = std::mem::size_of::<SockaddrRc>() as libc::socklen_t;
        let fd = unsafe {
            libc::accept(
                self.fd,
                &mut address as *mut SockaddrRc as *mut libc::sockaddr,
                &mut length,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // A UnixStream is only a wrapper around a socket descriptor: read,
        // write, try_clone and the timeouts are the same system calls for
        // every socket family.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        Ok((stream, format_address(&address.bdaddr)))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

pub fn connect(address: &str, channel: u8) -> io::Result<UnixStream> {
    let bdaddr = parse_address(address)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a Bluetooth address"))?;
    let fd = socket()?;
    // Bind the source to the adapter that is actually up. Without this the
    // kernel takes the first one, which on this Jolla is a dead hci0 and
    // answers every connection with "host is unreachable".
    if let Some(local) = active_adapter() {
        let source = SockaddrRc {
            family: AF_BLUETOOTH as libc::sa_family_t,
            bdaddr: local,
            channel: 0,
            padding: 0,
        };
        unsafe {
            libc::bind(
                fd,
                &source as *const SockaddrRc as *const libc::sockaddr,
                std::mem::size_of::<SockaddrRc>() as libc::socklen_t,
            );
        }
    }
    let target = SockaddrRc {
        family: AF_BLUETOOTH as libc::sa_family_t,
        bdaddr,
        channel,
        padding: 0,
    };
    let result = unsafe {
        libc::connect(
            fd,
            &target as *const SockaddrRc as *const libc::sockaddr,
            std::mem::size_of::<SockaddrRc>() as libc::socklen_t,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

// --- SDP: den Kanal zu einer UUID finden ---------------------------------
//
// Briar veroeffentlicht seinen Dienst unter einer zufaelligen UUID und
// erwartet, dass die Gegenseite den RFCOMM-Kanal per SDP nachschlaegt. Ein
// fester Kanal wie unserer funktioniert nur im eigenen Kreis.
//
// Gesprochen wird SDP roh ueber L2CAP auf PSM 1 -- dasselbe, was sdptool tut.
// Der Weg ueber BlueZ' D-Bus waere umstaendlicher: dort gibt es keine
// Rohsuche mehr, und ConnectProfile liefert uns den Socket nicht heraus.

const BTPROTO_L2CAP: libc::c_int = 0;
const SDP_PSM: u16 = 0x0001;
const SDP_SERVICE_SEARCH_ATTR_REQ: u8 = 0x06;
const SDP_SERVICE_SEARCH_ATTR_RSP: u8 = 0x07;
/// Die Kennung des RFCOMM-Protokolls in einer Protokollbeschreibung.
const UUID_RFCOMM: u16 = 0x0003;
/// Das Attribut, in dem die Protokollbeschreibung steht.
const ATTR_PROTOCOL_DESCRIPTOR_LIST: u16 = 0x0004;

#[repr(C)]
struct SockaddrL2 {
    family: libc::sa_family_t,
    psm: u16,
    bdaddr: [u8; 6],
    cid: u16,
    bdaddr_type: u8,
}

/// Sucht den RFCOMM-Kanal, unter dem das Geraet den Dienst mit dieser UUID
/// anbietet.
pub fn lookup_channel(address: &str, uuid: &str) -> io::Result<u8> {
    let bdaddr = parse_address(address)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a Bluetooth address"))?;
    let uuid = uuid_bytes(uuid)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a UUID"))?;

    let fd = unsafe {
        libc::socket(
            AF_BLUETOOTH,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            BTPROTO_L2CAP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let strom = unsafe { UnixStream::from_raw_fd(fd) };

    if let Some(local) = active_adapter() {
        let quelle = SockaddrL2 {
            family: AF_BLUETOOTH as libc::sa_family_t,
            psm: 0,
            bdaddr: local,
            cid: 0,
            bdaddr_type: 0,
        };
        unsafe {
            libc::bind(
                fd,
                &quelle as *const SockaddrL2 as *const libc::sockaddr,
                std::mem::size_of::<SockaddrL2>() as libc::socklen_t,
            );
        }
    }
    let ziel = SockaddrL2 {
        family: AF_BLUETOOTH as libc::sa_family_t,
        psm: SDP_PSM.to_le(),
        bdaddr,
        cid: 0,
        bdaddr_type: 0,
    };
    if unsafe {
        libc::connect(
            fd,
            &ziel as *const SockaddrL2 as *const libc::sockaddr,
            std::mem::size_of::<SockaddrL2>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    use std::io::{Read, Write};
    let mut anfrage = Vec::new();
    // Suchmuster: eine Folge mit genau unserer 128-Bit-UUID.
    let mut muster = vec![0x1cu8]; // UUID, 16 Byte
    muster.extend_from_slice(&uuid);
    let mut rumpf = Vec::new();
    rumpf.push(0x35); // Folge, Laenge in einem Byte
    rumpf.push(muster.len() as u8);
    rumpf.extend_from_slice(&muster);
    rumpf.extend_from_slice(&0xffffu16.to_be_bytes()); // hoechstens so viele Bytes
    // Attributliste: nur die Protokollbeschreibung.
    rumpf.push(0x35);
    rumpf.push(3);
    rumpf.push(0x09); // uint16
    rumpf.extend_from_slice(&ATTR_PROTOCOL_DESCRIPTOR_LIST.to_be_bytes());
    rumpf.push(0x00); // kein Fortsetzungszustand

    anfrage.push(SDP_SERVICE_SEARCH_ATTR_REQ);
    anfrage.extend_from_slice(&1u16.to_be_bytes()); // Vorgangsnummer
    anfrage.extend_from_slice(&(rumpf.len() as u16).to_be_bytes());
    anfrage.extend_from_slice(&rumpf);

    let mut schreiber = &strom;
    schreiber.write_all(&anfrage)?;

    let mut antwort = vec![0u8; 4096];
    let mut leser = &strom;
    let gelesen = leser.read(&mut antwort)?;
    antwort.truncate(gelesen);
    if gelesen < 5 || antwort[0] != SDP_SERVICE_SEARCH_ATTR_RSP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SDP answered something else",
        ));
    }
    kanal_aus_antwort(&antwort[7..]).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "no RFCOMM channel for that UUID")
    })
}

/// Sucht in der Antwort die Stelle, an der die RFCOMM-Kennung steht, und
/// nimmt die Zahl dahinter.
///
/// Ein vollstaendiger SDP-Leser waere hier Aufwand ohne Gewinn: wir wollen
/// genau eine Zahl, und die steht in jeder gueltigen Protokollbeschreibung
/// unmittelbar hinter der 16-Bit-Kennung 0x0003.
fn kanal_aus_antwort(daten: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 4 < daten.len() {
        // 0x19 = UUID in 16 Bit
        if daten[i] == 0x19
            && u16::from_be_bytes([daten[i + 1], daten[i + 2]]) == UUID_RFCOMM
        {
            // Dahinter kommt der Kanal als uint8 (0x08) -- gelegentlich
            // steht eine Elementkopfzeile dazwischen.
            let mut j = i + 3;
            while j < daten.len() {
                if daten[j] == 0x08 && j + 1 < daten.len() {
                    return Some(daten[j + 1]);
                }
                if daten[j] == 0x09 && j + 2 < daten.len() {
                    return Some(daten[j + 2]);
                }
                if daten[j] == 0x19 || daten[j] == 0x1c {
                    break; // schon die naechste Schicht
                }
                j += 1;
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod sdp_tests {
    use super::*;

    #[test]
    fn uuid_hin_und_zurueck() {
        let u = random_uuid();
        assert_eq!(u.len(), 36, "{}", u);
        assert_eq!(u.as_bytes()[14], b'4', "Fassung 4");
        let b = uuid_bytes(&u).unwrap();
        assert_eq!(b[6] >> 4, 4);
        assert_eq!(b[8] >> 6, 2, "Variante 1");
        assert!(uuid_bytes("zu kurz").is_none());
    }

    #[test]
    fn kanal_wird_aus_der_beschreibung_gelesen() {
        // Eine Protokollbeschreibung, wie sie in einer SDP-Antwort steht:
        // Folge [ Folge [ UUID(L2CAP) ], Folge [ UUID(RFCOMM), uint8(11) ] ]
        let antwort = [
            0x35, 0x10, 0x35, 0x03, 0x19, 0x01, 0x00, 0x35, 0x05, 0x19, 0x00,
            0x03, 0x08, 0x0b,
        ];
        assert_eq!(kanal_aus_antwort(&antwort), Some(11));
    }

    #[test]
    fn ohne_rfcomm_kein_kanal() {
        let antwort = [0x35, 0x03, 0x19, 0x01, 0x00];
        assert_eq!(kanal_aus_antwort(&antwort), None);
    }
}
