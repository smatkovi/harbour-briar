//! Der Netzwächter: er wartet, statt zu fragen.
//!
//! Briar startet auf Android seine Transporte neu, sobald das System einen
//! Netzwechsel meldet. Hier ist die Quelle der Systembus, und zwar auf
//! beiden Geräten -- nur heißt der Melder anderswo:
//!
//!   Sailfish   ConnMan     net.connman.Manager / .Service  PropertyChanged
//!   Harmattan  ICd2        com.nokia.icd2                  state_sig
//!   BlueZ 5    Sailfish    org.freedesktop.DBus.Properties PropertiesChanged
//!   BlueZ 4    Harmattan   org.bluez.Adapter               PropertyChanged
//!
//! Alle vier Regeln werden angemeldet; welche davon je etwas liefert,
//! entscheidet das Gerät. Das ist billiger als jede Schleife und -- was auf
//! dem N9 mehr zählt -- es hält den Prozessor nicht wach: ohne Meldung
//! schläft der Faden im Empfangen.

use std::time::{Duration, Instant};

/// Die Regeln, die wir am Bus anmelden.
const REGELN: [&str; 5] = [
    "type='signal',interface='net.connman.Manager',member='PropertyChanged'",
    "type='signal',interface='net.connman.Service',member='PropertyChanged'",
    "type='signal',interface='com.nokia.icd2'",
    "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged',arg0='org.bluez.Adapter1'",
    "type='signal',interface='org.bluez.Adapter',member='PropertyChanged'",
];

/// Ruft `bei_aenderung` auf, sobald sich am Netz etwas tut.
///
/// Mehrere Meldungen kurz hintereinander sind der Normalfall (ConnMan
/// meldet jeden Zwischenzustand), darum wird zusammengefasst: höchstens
/// einmal in drei Sekunden.
pub fn beobachten<F>(bei_aenderung: F)
where
    F: Fn() + Send + 'static,
{
    std::thread::spawn(move || {
        let verbindung = match zbus::blocking::Connection::system() {
            Ok(c) => c,
            Err(e) => {
                crate::net::log(&format!("no system bus, no network watch: {}", e));
                return;
            }
        };
        for regel in REGELN {
            let _ = verbindung.call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "AddMatch",
                &(regel,),
            );
        }
        crate::net::log("watching the system bus for network changes");

        let mut zuletzt = Instant::now() - Duration::from_secs(60);
        for nachricht in zbus::blocking::MessageIterator::from(&verbindung) {
            if nachricht.is_err() {
                continue;
            }
            if zuletzt.elapsed() < Duration::from_secs(3) {
                continue;
            }
            zuletzt = Instant::now();
            bei_aenderung();
        }
        crate::net::log("the system bus went away -- no more network watch");
    });
}
