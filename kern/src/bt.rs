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
