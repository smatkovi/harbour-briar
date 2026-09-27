//! Briar's Bramble protocols, reimplemented for devices no JVM will ever run
//! on again: the Nokia N9/N950 (Harmattan) and Sailfish OS.
//!
//! The wire formats are Briar's, byte for byte, and are checked against
//! reference values dumped from bramble-core itself (see ../vectors). What is
//! not Briar's: the storage format, and how a contact's address is found --
//! Briar rendezvouses over Tor, this port is told the LAN address.

pub mod api;
pub mod bdf;
pub mod bt;
pub mod crypto;
pub mod exchange;
pub mod groups;
pub mod handshake;
pub mod ids;
pub mod net;
#[cfg(feature = "dbus")]
pub mod netwatch;
#[cfg(feature = "sfos")]
pub mod notify;
pub mod record;
pub mod entsperren;
pub mod tresor;
pub mod store;
pub mod stream;
pub mod sync;
pub mod tor;
pub mod transport;
pub mod util;
