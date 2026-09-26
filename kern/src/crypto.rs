//! The crypto constructions of bramble-core, byte for byte.
//!
//! Everything is a length-prefixed, labelled BLAKE2b: the label and each
//! input are preceded by their length as a 32-bit big-endian integer, so no
//! two different input lists can produce the same digest. Verified against
//! reference bytes dumped from CryptoComponentImpl (see ../vectors).

use blake2::digest::{FixedOutput, KeyInit, Mac};
use blake2::{Blake2b, Blake2bMac};
use digest::consts::U32;
use digest::Digest;

pub const KEY_LEN: usize = 32;
pub type SecretKey = [u8; KEY_LEN];

fn length_prefix(len: usize) -> [u8; 4] {
    let mut b = [0u8; 4];
    crate::util::write_u32(&mut b, len as u32);
    b
}

/// CryptoComponentImpl.hash: unkeyed BLAKE2b-256.
pub fn hash(label: &str, inputs: &[&[u8]]) -> SecretKey {
    let mut d = Blake2b::<U32>::new();
    Digest::update(&mut d, length_prefix(label.len()));
    Digest::update(&mut d, label.as_bytes());
    for input in inputs {
        Digest::update(&mut d, length_prefix(input.len()));
        Digest::update(&mut d, input);
    }
    let out = d.finalize();
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&out);
    k
}

/// CryptoComponentImpl.mac: BLAKE2b-256 keyed with the secret key.
pub fn mac(label: &str, key: &SecretKey, inputs: &[&[u8]]) -> SecretKey {
    let mut d = <Blake2bMac<U32> as KeyInit>::new_from_slice(key)
        .expect("32 bytes is a valid BLAKE2b key");
    Mac::update(&mut d, &length_prefix(label.len()));
    Mac::update(&mut d, label.as_bytes());
    for input in inputs {
        Mac::update(&mut d, &length_prefix(input.len()));
        Mac::update(&mut d, input);
    }
    let out = d.finalize_fixed();
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&out);
    k
}

/// CryptoComponentImpl.deriveKey: the MAC, used as a key.
pub fn derive_key(label: &str, key: &SecretKey, inputs: &[&[u8]]) -> SecretKey {
    mac(label, key, inputs)
}

pub fn verify_mac(tag: &[u8], label: &str, key: &SecretKey, inputs: &[&[u8]]) -> bool {
    let expected = mac(label, key, inputs);
    if tag.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..tag.len() {
        diff |= tag[i] ^ expected[i];
    }
    diff == 0
}

/// What CryptoComponentImpl signs: the label and the message, both
/// length-prefixed.
fn signable(label: &str, to_sign: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + label.len() + to_sign.len());
    v.extend_from_slice(&length_prefix(label.len()));
    v.extend_from_slice(label.as_bytes());
    v.extend_from_slice(&length_prefix(to_sign.len()));
    v.extend_from_slice(to_sign);
    v
}

/// Ed25519. Briar's signature private key is the seed, its public key the
/// compressed point -- the same encoding ed25519-dalek uses.
pub fn signature_public_key(seed: &SecretKey) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

pub fn sign(label: &str, to_sign: &[u8], seed: &SecretKey) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    key.sign(&signable(label, to_sign)).to_bytes().to_vec()
}

pub fn verify_signature(sig: &[u8], label: &str, signed: &[u8], public: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    if sig.len() != 64 || public.len() != 32 {
        return false;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(public);
    let mut sg = [0u8; 64];
    sg.copy_from_slice(sig);
    match ed25519_dalek::VerifyingKey::from_bytes(&pk) {
        Ok(key) => key
            .verify(&signable(label, signed), &ed25519_dalek::Signature::from_bytes(&sg))
            .is_ok(),
        Err(_) => false,
    }
}

/// Curve25519 key agreement. An all-zero result means the public key was
/// invalid, which bramble treats as an error.
pub fn agree(private: &SecretKey, public: &[u8; 32]) -> Option<[u8; 32]> {
    let secret = x25519_dalek::StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*public));
    let bytes = shared.to_bytes();
    if bytes.iter().all(|b| *b == 0) {
        None
    } else {
        Some(bytes)
    }
}

pub fn agreement_public_key(private: &SecretKey) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).to_bytes()
}

/// A fresh agreement private key, clamped the way curve25519-java clamps.
pub fn generate_agreement_private_key() -> SecretKey {
    let mut k = [0u8; 32];
    k.copy_from_slice(&crate::util::random(32));
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

pub fn generate_secret_key() -> SecretKey {
    let mut k = [0u8; 32];
    k.copy_from_slice(&crate::util::random(32));
    k
}

/// CryptoComponentImpl.deriveSharedSecret with one key agreement.
pub fn derive_shared_secret(
    label: &str,
    their_public: &[u8; 32],
    our_private: &SecretKey,
    inputs: &[&[u8]],
) -> Option<SecretKey> {
    let raw = agree(our_private, their_public)?;
    let mut all: Vec<&[u8]> = vec![&raw];
    all.extend_from_slice(inputs);
    Some(hash(label, &all))
}

/// CryptoComponentImpl.deriveSharedSecret with three agreements, as the
/// handshake protocol (v0.1) uses it: ephemeral-ephemeral first, then the two
/// static-ephemeral pairs in Alice-then-Bob order.
#[allow(clippy::too_many_arguments)]
pub fn derive_shared_secret_3(
    label: &str,
    their_static_public: &[u8; 32],
    their_ephemeral_public: &[u8; 32],
    our_static_private: &SecretKey,
    our_ephemeral_private: &SecretKey,
    alice: bool,
    inputs: &[&[u8]],
) -> Option<SecretKey> {
    let ee = agree(our_ephemeral_private, their_ephemeral_public)?;
    let (second, third) = if alice {
        (
            agree(our_static_private, their_ephemeral_public)?,
            agree(our_ephemeral_private, their_static_public)?,
        )
    } else {
        (
            agree(our_ephemeral_private, their_static_public)?,
            agree(our_static_private, their_ephemeral_public)?,
        )
    };
    let mut all: Vec<&[u8]> = vec![&ee, &second, &third];
    all.extend_from_slice(inputs);
    Some(hash(label, &all))
}

/// NaCl's crypto_secretbox (XSalsa20-Poly1305): the 16-byte Poly1305 tag
/// first, then the ciphertext, which is what bramble's AuthenticatedCipher
/// writes.
pub const MAC_LEN: usize = 16;

pub fn secretbox_encrypt(key: &SecretKey, nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use crypto_secretbox::aead::AeadInPlace;
    use crypto_secretbox::{KeyInit as SbKeyInit, XSalsa20Poly1305};
    let cipher = XSalsa20Poly1305::new_from_slice(key).expect("32-byte key");
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), b"", &mut buffer)
        .expect("encryption cannot fail");
    let mut out = Vec::with_capacity(MAC_LEN + buffer.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&buffer);
    out
}

pub fn secretbox_decrypt(key: &SecretKey, nonce: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    use crypto_secretbox::aead::AeadInPlace;
    use crypto_secretbox::{KeyInit as SbKeyInit, XSalsa20Poly1305};
    if ciphertext.len() < MAC_LEN {
        return None;
    }
    let cipher = XSalsa20Poly1305::new_from_slice(key).expect("32-byte key");
    let tag = &ciphertext[..MAC_LEN];
    let mut buffer = ciphertext[MAC_LEN..].to_vec();
    cipher
        .decrypt_in_place_detached(nonce.into(), b"", &mut buffer, tag.into())
        .ok()?;
    Some(buffer)
}
