//! Briar's Bramble protocols, reimplemented for devices no JVM will ever run
//! on again: the Nokia N9/N950 (Harmattan) and Sailfish OS.
//!
//! The wire formats are Briar's, byte for byte, and are checked against
//! reference values dumped from bramble-core itself (see ../vectors). What is
//! not Briar's: the storage format -- which is its own business, and encrypted
//! (`tresor.rs`). Finding a contact is Briar's again since 0.24: the
//! rendezvous over Tor lives in `rendezvous.rs` and matches Briar's own values
//! byte for byte. An address may still be typed in instead, which Briar has no
//! field for.

pub mod api;
pub mod bdf;
pub mod bt;
#[cfg(feature = "dbus")]
pub mod bqp;
pub mod btprofile;
pub mod crypto;
pub mod exchange;
pub mod groups;
pub mod introduction;
pub mod handshake;
pub mod ids;
pub mod net;
#[cfg(feature = "dbus")]
pub mod netwatch;
#[cfg(feature = "sfos")]
pub mod notify;
pub mod record;
pub mod rendezvous;
pub mod entsperren;
pub mod tresor;
pub mod store;
pub mod stream;
pub mod sync;
pub mod tor;
pub mod transport;
pub mod util;
