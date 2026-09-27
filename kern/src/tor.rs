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
use std::time::Duration;

pub const VIRTUAL_PORT: u16 = 80;
const TIMEOUT: Duration = Duration::from_secs(20);
/// Briar's own Tor listens here; a system Tor uses the usual 9050/9051.
const CANDIDATES: [(u16, u16); 2] = [(9051, 9050), (59051, 59050)];

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
pub fn connect() -> Option<Tor> {
    for (control_port, socks_port) in CANDIDATES {
        if let Ok(control) = open_control(control_port) {
            return Some(Tor {
                control_port,
                socks_port,
                control,
                child: None,
            });
        }
    }
    None
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
pub fn connect_or_start(data_dir: &std::path::Path) -> Option<Tor> {
    if let Some(tor) = connect() {
        return Some(tor);
    }
    let binary = BUNDLED.iter().find(|path| std::path::Path::new(path).exists())?;
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
    let (control_port, socks_port) = CANDIDATES[1];
    let torrc = tor_dir.join("torrc");
    let _ = std::fs::write(
        &torrc,
        format!(
            "SocksPort 127.0.0.1:{}\nControlPort 127.0.0.1:{}\nCookieAuthentication 0\n\
             DataDirectory {}\nAvoidDiskWrites 1\nClientOnly 1\n",
            socks_port,
            control_port,
            tor_dir.display()
        ),
    );
    let log = std::fs::File::create(tor_dir.join("tor.log")).ok()?;
    let errors = log.try_clone().ok()?;
    let mut child = std::process::Command::new(binary)
        .arg("-f")
        .arg(&torrc)
        .stdout(log)
        .stderr(errors)
        .spawn()
        .ok()?;
    // Bootstrapping takes a while on these radios; the control port itself
    // comes up long before that.
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(1));
        if let Ok(mut control) = open_control(control_port) {
            // Our Tor, so it may die with us: after TAKEOWNERSHIP it shuts
            // itself down when this control connection closes. That covers
            // the case where the daemon is killed and Drop never runs.
            let _ = command(&mut control, "TAKEOWNERSHIP\r\n");
            return Some(Tor {
                control_port,
                socks_port,
                control,
                child: Some(child),
            });
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
