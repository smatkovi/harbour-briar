//! Das Rendezvous ueber Tor.
//!
//! Zwei Leute, die nur den `briar://`-Link des anderen haben, kennen keine
//! Adresse voneinander. Briar loest das, ohne dass je eine ausgetauscht wird:
//! aus dem gemeinsamen Geheimnis leiten beide Seiten dieselben zwei Saaten
//! ab, machen daraus je einen versteckten Dienst, und treffen sich dort. Wer
//! zuhoert, sieht zwei Zwiebeladressen, die zu niemandem gehoeren und nach
//! dem Treffen nie wieder auftauchen.
//!
//! Bis 0.24.0 fehlte das hier ganz -- unser Port verlangte, dass eine Seite
//! die Adresse der anderen eintippt. Mit einem echten Briar geht das nicht:
//! seine Oberflaeche bietet es gar nicht an.
//!
//! Jeder Schritt unten ist gegen Briars eigene Klassen gemessen; die Werte
//! stehen in vectors/vectors.txt unter `rv_*`.

use crate::crypto::{derive_key, SecretKey};

/// RendezvousConstants.PROTOCOL_VERSION
const PROTOCOL_VERSION: u8 = 0;
const RENDEZVOUS_KEY_LABEL: &str = "org.briarproject.bramble.rendezvous/RENDEZVOUS_KEY";
const KEY_MATERIAL_LABEL: &str = "org.briarproject.bramble.rendezvous/KEY_MATERIAL";

/// So lange wird es versucht, dann gilt der schwebende Kontakt als
/// gescheitert (RENDEZVOUS_TIMEOUT_MS = 2 Tage).
pub const TIMEOUT_MS: u64 = 2 * 24 * 60 * 60 * 1000;
/// Und so oft (POLLING_INTERVAL_MS = 1 Minute).
pub const POLLING_INTERVAL_MS: u64 = 60 * 1000;

/// Der Rendezvous-Schluessel aus dem statischen Hauptschluessel des
/// Handschlags.
pub fn rendezvous_key(static_master_key: &SecretKey) -> SecretKey {
    derive_key(RENDEZVOUS_KEY_LABEL, static_master_key, &[&[PROTOCOL_VERSION]])
}

/// Die beiden Saaten fuer einen Transport: erst Alices, dann Bobs.
///
/// Briars Quelle ist ein Salsa20-Strom mit **Null-Nonce** -- rohes Salsa20 mit
/// 8 Byte Nonce, nicht XSalsa20 mit 24. Aus ihm werden nacheinander zweimal
/// 32 Byte entnommen (TorPlugin: `aliceSeed` zuerst, dann `bobSeed`).
pub fn seeds(rendezvous_key: &SecretKey, transport_id: &str) -> ([u8; 32], [u8; 32]) {
    use salsa20::cipher::{KeyIvInit, StreamCipher};
    let source_key = derive_key(
        KEY_MATERIAL_LABEL,
        rendezvous_key,
        &[transport_id.as_bytes()],
    );
    let mut strom = salsa20::Salsa20::new(
        (&source_key).into(),
        (&[0u8; 8]).into(),
    );
    let mut beide = [0u8; 64];
    strom.apply_keystream(&mut beide);
    let mut alice = [0u8; 32];
    let mut bob = [0u8; 32];
    alice.copy_from_slice(&beide[..32]);
    bob.copy_from_slice(&beide[32..]);
    (alice, bob)
}

/// Welche Saat uns gehoert und welche der Gegenseite.
pub fn own_and_peer_seed(
    rendezvous_key: &SecretKey,
    transport_id: &str,
    we_are_alice: bool,
) -> ([u8; 32], [u8; 32]) {
    let (alice, bob) = seeds(rendezvous_key, transport_id);
    if we_are_alice {
        (alice, bob)
    } else {
        (bob, alice)
    }
}

/// Der erweiterte Ed25519-Schluessel, den Tor als Blob will: SHA-512 der
/// Saat, mit den ueblichen Bits zurechtgebogen.
fn expanded(seed: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut h = [0u8; 64];
    h.copy_from_slice(&Sha512::digest(seed));
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    h
}

/// Was `ADD_ONION` als Schluessel erwartet.
pub fn private_key_blob(seed: &[u8; 32]) -> String {
    format!("ED25519-V3:{}", base64(&expanded(seed)))
}

/// Die Adresse des versteckten Dienstes zu dieser Saat -- ohne ".onion".
///
/// v3-Format: base32(Oeffentlicher Schluessel ‖ Pruefsumme ‖ Fassung), wobei
/// die Pruefsumme die ersten zwei Byte von
/// SHA3-256(".onion checksum" ‖ Schluessel ‖ Fassung) sind.
pub fn onion(seed: &[u8; 32]) -> String {
    use ed25519_dalek::SigningKey;
    use sha3::{Digest, Sha3_256};

    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key().to_bytes();

    let mut pruef = Sha3_256::new();
    pruef.update(b".onion checksum");
    pruef.update(public);
    pruef.update([3u8]);
    let pruefsumme = pruef.finalize();

    let mut roh = Vec::with_capacity(35);
    roh.extend_from_slice(&public);
    roh.extend_from_slice(&pruefsumme[..2]);
    roh.push(3);
    base32(&roh)
}

/// RFC 4648 base32, klein geschrieben und ohne Auffuellung -- so schreibt Tor
/// seine Adressen.
fn base32(daten: &[u8]) -> String {
    const ZEICHEN: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut aus = String::new();
    let mut puffer: u32 = 0;
    let mut bits = 0;
    for b in daten {
        puffer = (puffer << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            aus.push(ZEICHEN[((puffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        aus.push(ZEICHEN[((puffer << (5 - bits)) & 31) as usize] as char);
    }
    aus
}

/// Base64 mit Auffuellung, wie Tor es fuer den Blob erwartet.
fn base64(daten: &[u8]) -> String {
    const ZEICHEN: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut aus = String::new();
    for block in daten.chunks(3) {
        let b = [
            block[0],
            *block.get(1).unwrap_or(&0),
            *block.get(2).unwrap_or(&0),
        ];
        let dreissig = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        aus.push(ZEICHEN[((dreissig >> 18) & 63) as usize] as char);
        aus.push(ZEICHEN[((dreissig >> 12) & 63) as usize] as char);
        aus.push(if block.len() > 1 {
            ZEICHEN[((dreissig >> 6) & 63) as usize] as char
        } else {
            '='
        });
        aus.push(if block.len() > 2 {
            ZEICHEN[(dreissig & 63) as usize] as char
        } else {
            '='
        });
    }
    aus
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{from_hex, to_hex};

    /// Die Werte stammen aus Briars eigenen Klassen -- erzeugt mit
    /// vectors/java (Vectors6, Vectors7) gegen briar-headless 1.5.20.
    #[test]
    fn schluessel_und_saaten_wie_bei_briar() {
        let mut master = [0u8; 32];
        for (i, b) in master.iter_mut().enumerate() {
            *b = i as u8;
        }
        let rk = rendezvous_key(&master);
        assert_eq!(
            to_hex(&rk),
            "e6b0e3136c365b713c6511f2c82afd5b0a1969288e1a213cacf59fe16fa984e3"
        );

        let (alice, bob) = seeds(&rk, "org.briarproject.bramble.lan");
        assert_eq!(
            to_hex(&alice),
            "ddc617e583e7de38c0b5a09a50623907b96ae70eee47a6aeaa3e0d68898b4715"
        );
        assert_eq!(
            to_hex(&bob),
            "37cfa353dd287bc9b21e6642ccd894b4e99bdfd0a1e22ca011e9467595c128ce"
        );

        // Ein anderer Transport ergibt andere Saaten -- der Name geht in die
        // Ableitung ein.
        let (tor_a, tor_b) = seeds(&rk, "org.briarproject.bramble.tor");
        assert_eq!(
            to_hex(&tor_a),
            "c9714c4079aa80718bf9e5323a3d437ae5f2d9309937eea5a2f799e3e1e02ca8"
        );
        assert_eq!(
            to_hex(&tor_b),
            "d278854337b6e4e1fb390da5d416675166ea1cbfea79ad572a02499c6715517e"
        );
    }

    #[test]
    fn onion_und_blob_wie_bei_briar() {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = 0x40 + i as u8;
        }
        assert_eq!(
            onion(&seed),
            "evb3sl7rbfkrcr3k3sbwtw3n3sjtmznbdf4n3ikaj3qqm3fjkwoqp3ad"
        );
        assert_eq!(
            private_key_blob(&seed),
            "ED25519-V3:YCjUJ20DbXh7pN9YA+fRWukWXkhkF6065eSLSSkM1lYJDEa/\
             YccYOc8lNBWe4+ERE4K75DMXiSkYBJoPK1pT/Q=="
        );
    }

    #[test]
    fn alice_und_bob_tauschen_die_rollen() {
        let rk = rendezvous_key(&from_hex(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .map(|v| {
            let mut k = [0u8; 32];
            k.copy_from_slice(&v);
            k
        })
        .unwrap());
        let (meine_a, ihre_a) = own_and_peer_seed(&rk, "t", true);
        let (meine_b, ihre_b) = own_and_peer_seed(&rk, "t", false);
        // Was fuer Alice die eigene ist, ist fuer Bob die fremde.
        assert_eq!(meine_a, ihre_b);
        assert_eq!(ihre_a, meine_b);
        assert_ne!(meine_a, meine_b);
    }
}
