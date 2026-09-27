//! Den eigenen Dienst per SDP veroeffentlichen, damit Briar uns findet.
//!
//! Briar sucht den RFCOMM-Kanal eines Kontakts ueber dessen gemeldete UUID.
//! Wer keinen SDP-Eintrag hat, ist fuer Briar unsichtbar -- unabhaengig
//! davon, ob ein Socket lauscht.
//!
//! BlueZ 5 hat keine Schnittstelle mehr, um nur einen Eintrag abzulegen: man
//! meldet ein Profil an, und BlueZ uebernimmt dabei auch das Lauschen und
//! reicht die Griffe ueber D-Bus herein. Das ist hier kein Nachteil, sondern
//! ein Gewinn -- wir geben **keinen** Kanal vor, BlueZ sucht sich einen
//! eigenen, und unser roher Lauscher auf Kanal 11 bleibt daneben bestehen.
//! Alte Gegenstellen finden uns also weiter auf 11, Briar ueber SDP.
//!
//! Auf Harmattan gibt es das nicht: BlueZ 4 kennt `org.bluez.Service.AddRecord`,
//! das nur den Eintrag ablegt. Dort bleibt es beim festen Kanal, bis das
//! gebaut ist.

use std::sync::{Arc, Mutex};

use crate::store::Store;

/// Das Profil, das BlueZ bei uns aufruft.
struct Profil {
    store: Arc<Mutex<Store>>,
}

#[zbus::interface(name = "org.bluez.Profile1")]
impl Profil {
    /// BlueZ hat eine eingehende Verbindung angenommen und reicht uns den
    /// Griff. Ab hier ist es derselbe Weg wie beim eigenen Lauscher.
    fn new_connection(
        &self,
        _device: zbus::zvariant::ObjectPath<'_>,
        fd: zbus::zvariant::OwnedFd,
        _eigenschaften: std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    ) {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        // Der Griff gehoert uns, sobald wir ihn verdoppelt haben -- zbus
        // schliesst seinen beim Verlassen.
        let roh = unsafe { libc::dup(fd.as_raw_fd()) };
        if roh < 0 {
            crate::net::log("Bluetooth: Griff liess sich nicht uebernehmen");
            return;
        }
        let strom = unsafe { std::os::unix::net::UnixStream::from_raw_fd(roh) };
        crate::net::log("Bluetooth: eingehende Verbindung ueber SDP");
        let node = crate::net::Node::new(Arc::clone(&self.store));
        std::thread::spawn(move || {
            node.spawn_incoming(
                crate::net::Conn::Bluetooth(strom),
                crate::transport::BLUETOOTH_TRANSPORT_ID,
                None,
            );
        });
    }

    fn request_disconnection(&self, _device: zbus::zvariant::ObjectPath<'_>) {}

    fn release(&self) {}
}

/// Meldet unser Profil an. Scheitert es -- etwa weil BlueZ zu alt ist --,
/// bleibt es beim festen Kanal, und das wird einmal gesagt.
pub fn serve(store: Arc<Mutex<Store>>, uuid: String) {
    std::thread::spawn(move || {
        let pfad = "/harbour/briar/bt";
        let gebaut = zbus::blocking::connection::Builder::system()
            .and_then(|b| b.serve_at(pfad, Profil { store }))
            .and_then(|b| b.build());
        let verbindung = match gebaut {
            Ok(v) => v,
            Err(e) => {
                crate::net::log(&format!("no SDP record: {}", e));
                return;
            }
        };
        // Ohne "Channel": BlueZ sucht sich einen und schreibt ihn in den
        // Eintrag. Genau das wollen wir -- Kanal 11 bleibt frei fuer die
        // eigenen aelteren Geraete.
        let mut optionen: std::collections::HashMap<&str, zbus::zvariant::Value> =
            std::collections::HashMap::new();
        optionen.insert("Name", zbus::zvariant::Value::from("Briar"));
        optionen.insert("Role", zbus::zvariant::Value::from("server"));
        optionen.insert("RequireAuthentication", zbus::zvariant::Value::from(false));
        optionen.insert("RequireAuthorization", zbus::zvariant::Value::from(false));
        optionen.insert("AutoConnect", zbus::zvariant::Value::from(false));

        let ergebnis: Result<(), zbus::Error> = verbindung.call_method(
            Some("org.bluez"),
            "/org/bluez",
            Some("org.bluez.ProfileManager1"),
            "RegisterProfile",
            &(
                zbus::zvariant::ObjectPath::try_from(pfad).unwrap(),
                uuid.as_str(),
                optionen,
            ),
        )
        .map(|_| ());
        match ergebnis {
            Ok(()) => crate::net::log(&format!("SDP record published for {}", uuid)),
            Err(e) => crate::net::log(&format!("no SDP record: {}", e)),
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });
}
