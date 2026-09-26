//! Identifiers and the handshake link. Every identifier is a labelled hash
//! over the same fields the Java code hashes, so ours match Briar's.

use crate::bdf::Bdf;
use crate::crypto::{self, SecretKey};
use crate::util::{base32_decode, base32_encode, write_u32, write_u64};

pub const ID_LEN: usize = 32;
pub const AUTHOR_FORMAT_VERSION: u32 = 1;
pub const GROUP_FORMAT_VERSION: u8 = 1;
pub const MESSAGE_FORMAT_VERSION: u8 = 1;

const AUTHOR_ID_LABEL: &str = "org.briarproject.bramble/AUTHOR_ID";
const GROUP_ID_LABEL: &str = "org.briarproject.bramble/GROUP_ID";
const MESSAGE_ID_LABEL: &str = "org.briarproject.bramble/MESSAGE_ID";
const MESSAGE_BLOCK_LABEL: &str = "org.briarproject.bramble/MESSAGE_BLOCK";
const HANDSHAKE_KEY_ID_LABEL: &str = "org.briarproject.bramble/HANDSHAKE_KEY_ID";

pub fn author_id(name: &str, signature_public_key: &[u8]) -> SecretKey {
    let mut fv = [0u8; 4];
    write_u32(&mut fv, AUTHOR_FORMAT_VERSION);
    crypto::hash(
        AUTHOR_ID_LABEL,
        &[&fv, name.as_bytes(), signature_public_key],
    )
}

pub fn group_id(client_id: &str, major_version: u32, descriptor: &[u8]) -> SecretKey {
    let mut mv = [0u8; 4];
    write_u32(&mut mv, major_version);
    crypto::hash(
        GROUP_ID_LABEL,
        &[
            &[GROUP_FORMAT_VERSION],
            client_id.as_bytes(),
            &mv,
            descriptor,
        ],
    )
}

/// The group two contacts share for one client: the descriptor is a BDF list
/// of both author identifiers, smaller one first.
pub fn contact_group_id(
    client_id: &str,
    major_version: u32,
    author_a: &SecretKey,
    author_b: &SecretKey,
) -> SecretKey {
    let (first, second) = if author_a[..] < author_b[..] {
        (author_a, author_b)
    } else {
        (author_b, author_a)
    };
    let descriptor = crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Raw(first.to_vec()),
        Bdf::Raw(second.to_vec()),
    ]));
    group_id(client_id, major_version, &descriptor)
}

pub fn local_group_id(client_id: &str, major_version: u32) -> SecretKey {
    group_id(client_id, major_version, &[])
}

pub fn message_id(group_id: &SecretKey, timestamp: u64, body: &[u8]) -> SecretKey {
    let root_hash = crypto::hash(MESSAGE_BLOCK_LABEL, &[&[MESSAGE_FORMAT_VERSION], body]);
    let mut time = [0u8; 8];
    write_u64(&mut time, timestamp);
    crypto::hash(
        MESSAGE_ID_LABEL,
        &[&[MESSAGE_FORMAT_VERSION], group_id, &time, &root_hash],
    )
}

/// The wire form of a message: group, timestamp, body.
pub fn raw_message(group_id: &SecretKey, timestamp: u64, body: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(ID_LEN + 8 + body.len());
    raw.extend_from_slice(group_id);
    let mut time = [0u8; 8];
    write_u64(&mut time, timestamp);
    raw.extend_from_slice(&time);
    raw.extend_from_slice(body);
    raw
}

pub fn parse_raw_message(raw: &[u8]) -> Option<(SecretKey, u64, Vec<u8>)> {
    if raw.len() <= ID_LEN + 8 {
        return None;
    }
    let mut group = [0u8; 32];
    group.copy_from_slice(&raw[..ID_LEN]);
    let timestamp = crate::util::read_u64(&raw[ID_LEN..ID_LEN + 8]);
    Some((group, timestamp, raw[ID_LEN + 8..].to_vec()))
}

pub const LINK_FORMAT_VERSION: u8 = 0;

/// briar://<base32 of format version + handshake public key>
pub fn handshake_link(handshake_public_key: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(33);
    raw.push(LINK_FORMAT_VERSION);
    raw.extend_from_slice(handshake_public_key);
    format!("briar://{}", base32_encode(&raw).to_lowercase())
}

/// Accepts the link with or without the prefix, and ignores anything around
/// it, the way PendingContactFactoryImpl does.
pub fn parse_handshake_link(link: &str) -> Option<[u8; 32]> {
    let lower = link.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let valid = |c: char| c.is_ascii_digit() && c >= '2' && c <= '7' || c.is_ascii_lowercase();
    // Find a run of exactly 53 base32 characters
    let mut i = 0;
    while i < chars.len() {
        if !valid(chars[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && valid(chars[i]) {
            i += 1;
        }
        let run: String = chars[start..i].iter().collect();
        if run.len() < 53 {
            continue;
        }
        for window_start in 0..=(run.len() - 53) {
            let candidate = &run[window_start..window_start + 53];
            if let Some(raw) = base32_decode(candidate) {
                if raw.len() == 33 && raw[0] == LINK_FORMAT_VERSION {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&raw[1..]);
                    return Some(key);
                }
            }
        }
    }
    None
}

pub fn pending_contact_id(handshake_public_key: &[u8; 32]) -> SecretKey {
    crypto::hash(HANDSHAKE_KEY_ID_LABEL, &[handshake_public_key])
}
