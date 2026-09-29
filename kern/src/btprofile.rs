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
//! Auf Harmattan gibt es das nicht -- dort laeuft BlueZ 4, und das kennt
//! `org.bluez.Service.AddRecord`: einen Eintrag ablegen, ohne zu lauschen.
//! Genau das passt hier, denn unser roher Lauscher auf Kanal 11 gibt es
//! ohnehin. Der Eintrag gehoert der D-Bus-Verbindung, die ihn abgelegt hat:
//! geht sie zu, nimmt BlueZ ihn wieder weg. Darum bleibt der Faden am Leben.

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
            // Die UUID ist dauerhaft und per SDP fuer jeden in Funkreichweite
            // zu sehen -- sie ordnete das Protokoll dem Geraet zu (7b, D3).
            Ok(()) => crate::net::log_vertraulich(
                &format!("SDP record published for {}", uuid),
                "SDP record published",
            ),
            Err(e) => {
                // BlueZ 5 kennt ProfileManager1, BlueZ 4 nicht. Auf Harmattan
                // ist das also kein Fehler, sondern der andere Weg.
                crate::net::log(&format!("no profile manager ({}) -- trying BlueZ 4", e));
                bluez4_eintrag_mit(&verbindung, &uuid, crate::bt::CHANNEL);
            }
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });
}

/// Der SDP-Eintrag auf BlueZ 4, wie Harmattan es fuehrt.
///
/// Ohne ihn ist das N9 fuer ein echtes Briar ueber Bluetooth unsichtbar: Briar
/// sucht den RFCOMM-Kanal eines Kontakts ueber dessen gemeldete UUID und findet
/// ohne Eintrag gar nichts -- auch wenn ein Sockel lauscht.
///
/// Der Kanal kommt von aussen; BlueZ 4 sucht sich hier keinen aus, es legt
/// nur ab, was man ihm gibt. Fuer den Abgleich ist das der feste Kanal 11,
/// fuer ein Treffen der, auf dem der BQP-Lauscher gerade sitzt.
///
/// Gibt den Griff zurueck, mit dem sich der Eintrag wieder entfernen laesst --
/// ein Treffen ist voruebergehend, sein Eintrag darf nicht stehenbleiben.
pub fn bluez4_eintrag_mit(
    verbindung: &zbus::blocking::Connection,
    uuid: &str,
    kanal: u8,
) -> Option<u32> {
    // Erst den Adapter finden -- sein Pfad traegt bei BlueZ 4 die
    // Prozessnummer des Dienstes, ist also nicht zu raten.
    let adapter: zbus::zvariant::OwnedObjectPath = match verbindung.call_method(
        Some("org.bluez"),
        "/",
        Some("org.bluez.Manager"),
        "DefaultAdapter",
        &(),
    ) {
        Ok(antwort) => match antwort.body().deserialize() {
            Ok(p) => p,
            Err(e) => {
                crate::net::log(&format!("no SDP record: adapter path unreadable ({})", e));
                return None;
            }
        },
        Err(e) => {
            crate::net::log(&format!("no SDP record: no adapter ({})", e));
            return None;
        }
    };

    // Der Eintrag als XML, wie BlueZ 4 ihn erwartet:
    //   0x0001 Dienstklassen -- unsere UUID, danach sucht Briar
    //   0x0004 Protokolle    -- L2CAP, dann RFCOMM mit dem Kanal
    //   0x0005 Sichtbarkeit  -- PublicBrowseGroup, sonst findet ihn kein
    //                           Durchsuchen
    //   0x0100 Name
    let eintrag = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\
<record>\
<attribute id=\"0x0001\"><sequence><uuid value=\"{uuid}\"/></sequence></attribute>\
<attribute id=\"0x0004\"><sequence>\
<sequence><uuid value=\"0x0100\"/></sequence>\
<sequence><uuid value=\"0x0003\"/><uint8 value=\"0x{kanal:02x}\"/></sequence>\
</sequence></attribute>\
<attribute id=\"0x0005\"><sequence><uuid value=\"0x1002\"/></sequence></attribute>\
<attribute id=\"0x0100\"><text value=\"Briar\"/></attribute>\
</record>",
        uuid = uuid,
        kanal = kanal
    );

    match verbindung.call_method(
        Some("org.bluez"),
        adapter.as_str(),
        Some("org.bluez.Service"),
        "AddRecord",
        &(eintrag.as_str(),),
    ) {
        Ok(antwort) => {
            let griff: u32 = antwort.body().deserialize().unwrap_or(0);
            crate::net::log_vertraulich(
                &format!(
                    "SDP record published for {} on channel {} (BlueZ 4, handle {})",
                    uuid, kanal, griff
                ),
                &format!(
                    "SDP record published on channel {} (BlueZ 4, handle {})",
                    kanal, griff
                ),
            );
            Some(griff)
        }
        Err(e) => {
            crate::net::log(&format!("no SDP record: AddRecord failed ({})", e));
            None
        }
    }
}

/// Einen BlueZ-4-Eintrag wieder entfernen. Ein Treffen ist voruebergehend;
/// bliebe sein Eintrag stehen, faende eine Gegenseite spaeter eine Kennung,
/// hinter der niemand mehr lauscht -- genau der Fehler, den wir bei den
/// Beschreibern vermeiden.
pub fn bluez4_eintrag_weg(griff: u32) {
    let Ok(verbindung) = zbus::blocking::Connection::system() else {
        return;
    };
    let adapter: zbus::zvariant::OwnedObjectPath = match verbindung.call_method(
        Some("org.bluez"),
        "/",
        Some("org.bluez.Manager"),
        "DefaultAdapter",
        &(),
    ) {
        Ok(a) => match a.body().deserialize() {
            Ok(p) => p,
            Err(_) => return,
        },
        Err(_) => return,
    };
    let _ = verbindung.call_method(
        Some("org.bluez"),
        adapter.as_str(),
        Some("org.bluez.Service"),
        "RemoveRecord",
        &(griff,),
    );
}

/// Ein Profil, das jede eingehende Verbindung an einen Rueckruf gibt.
///
/// Fuer das Treffen nebeneinander: dort wechselt die Kennung mit jedem Lauf
/// (sie wird aus der Verpflichtung gerechnet), und die Verbindung gehoert
/// nicht dem Abgleich, sondern der Schluesseleinigung.
struct RufProfil {
    ruf: Box<dyn Fn(std::os::unix::net::UnixStream) + Send + Sync>,
}

#[zbus::interface(name = "org.bluez.Profile1")]
impl RufProfil {
    fn new_connection(
        &self,
        _device: zbus::zvariant::ObjectPath<'_>,
        fd: zbus::zvariant::OwnedFd,
        _eigenschaften: std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
    ) {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let roh = unsafe { libc::dup(fd.as_raw_fd()) };
        if roh < 0 {
            crate::net::log("BQP: Bluetooth-Griff liess sich nicht uebernehmen");
            return;
        }
        (self.ruf)(unsafe { std::os::unix::net::UnixStream::from_raw_fd(roh) });
    }

    fn request_disconnection(&self, _device: zbus::zvariant::ObjectPath<'_>) {}

    fn release(&self) {}
}

/// Unter einer Kennung lauschen und jede Verbindung an den Rueckruf geben --
/// der Weg von BlueZ 5, wo das Lauschen BlueZ selbst gehoert.
///
/// Gibt die Verbindung zurueck, solange sie lebt: laesst man sie fallen, ist
/// das Profil abgemeldet. Genau das wollen wir am Ende eines Treffens.
pub fn bluez5_lauschen<F>(
    pfad: &'static str,
    uuid: &str,
    ruf: F,
) -> Option<zbus::blocking::Connection>
where
    F: Fn(std::os::unix::net::UnixStream) + Send + Sync + 'static,
{
    let gebaut = zbus::blocking::connection::Builder::system()
        .and_then(|b| b.serve_at(pfad, RufProfil { ruf: Box::new(ruf) }))
        .and_then(|b| b.build());
    let verbindung = match gebaut {
        Ok(v) => v,
        Err(e) => {
            crate::net::log(&format!("BQP: kein Bluetooth-Profil ({})", e));
            return None;
        }
    };
    let mut optionen: std::collections::HashMap<&str, zbus::zvariant::Value> =
        std::collections::HashMap::new();
    optionen.insert("Name", zbus::zvariant::Value::from("Briar Treffen"));
    optionen.insert("Role", zbus::zvariant::Value::from("server"));
    optionen.insert("RequireAuthentication", zbus::zvariant::Value::from(false));
    optionen.insert("RequireAuthorization", zbus::zvariant::Value::from(false));
    optionen.insert("AutoConnect", zbus::zvariant::Value::from(false));
    let ergebnis: Result<(), zbus::Error> = verbindung
        .call_method(
            Some("org.bluez"),
            "/org/bluez",
            Some("org.bluez.ProfileManager1"),
            "RegisterProfile",
            &(
                zbus::zvariant::ObjectPath::try_from(pfad).unwrap(),
                uuid,
                optionen,
            ),
        )
        .map(|_| ());
    match ergebnis {
        Ok(()) => {
            // Die UUID gehoert zum gezeigten QR-Code.
            crate::net::log_vertraulich(
                &format!("BQP: lauscht ueber Bluetooth unter {}", uuid),
                "BQP: lauscht ueber Bluetooth",
            );
            Some(verbindung)
        }
        Err(e) => {
            crate::net::log(&format!("BQP: RegisterProfile scheiterte ({})", e));
            None
        }
    }
}

/// Das Profil wieder abmelden. Ohne das bleibt die Kennung angemeldet, und
/// eine Gegenseite fände einen Dienst, hinter dem niemand mehr steht.
pub fn bluez5_abmelden(verbindung: &zbus::blocking::Connection, pfad: &str) {
    let _: Result<(), zbus::Error> = verbindung
        .call_method(
            Some("org.bluez"),
            "/org/bluez",
            Some("org.bluez.ProfileManager1"),
            "UnregisterProfile",
            &(zbus::zvariant::ObjectPath::try_from(pfad).unwrap(),),
        )
        .map(|_| ());
}
