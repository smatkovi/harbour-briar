//! Transport keys and tags (bramble-core/transport, TransportCryptoImpl).

use crate::crypto::{self, SecretKey};
use crate::util::{write_u16, write_u64};

pub const PROTOCOL_VERSION: u16 = 4;
pub const TAG_LEN: usize = 16;
pub const STREAM_HEADER_NONCE_LEN: usize = 24;
pub const STREAM_HEADER_PLAINTEXT_LEN: usize = 2 + 8 + 32;
pub const STREAM_HEADER_LEN: usize =
    STREAM_HEADER_NONCE_LEN + STREAM_HEADER_PLAINTEXT_LEN + crypto::MAC_LEN;
pub const FRAME_NONCE_LEN: usize = 24;
pub const FRAME_HEADER_PLAINTEXT_LEN: usize = 4;
pub const FRAME_HEADER_LEN: usize = FRAME_HEADER_PLAINTEXT_LEN + crypto::MAC_LEN;
pub const MAX_FRAME_LEN: usize = 1024;
pub const MAX_PAYLOAD_LEN: usize = MAX_FRAME_LEN - FRAME_HEADER_LEN - crypto::MAC_LEN;
pub const MAX_CLOCK_DIFFERENCE_MS: u64 = 24 * 60 * 60 * 1000;

/// The LAN transport, the only one this port speaks. Its maximum latency
/// decides the length of a key rotation period.
pub const LAN_TRANSPORT_ID: &str = "org.briarproject.bramble.lan";

/// Briar's Bluetooth transport. Its maximum latency is the same 30 seconds,
/// so both transports share a time period length.
pub const BLUETOOTH_TRANSPORT_ID: &str = "org.briarproject.bramble.bluetooth";

/// Briar's Tor transport. Reaching a hidden service is slow, but it is the
/// only transport that works when the two devices are nowhere near each
/// other.
pub const TOR_TRANSPORT_ID: &str = "org.briarproject.bramble.tor";

/// The local port the hidden service points at. The LAN listener has its
/// own, so an incoming connection says by itself which transport's keys it
/// was encrypted with.
pub const DEFAULT_TOR_PORT: u16 = 7328;
pub const LAN_MAX_LATENCY_MS: u64 = 30_000;

/// The port this port listens on by default. Briar's LAN plugin picks a
/// random one and tells contacts about it in its transport properties; a
/// fixed default is friendlier when the address has to be typed in by hand.
pub const DEFAULT_PORT: u16 = 7327;

pub fn time_period_length(max_latency_ms: u64) -> u64 {
    max_latency_ms + MAX_CLOCK_DIFFERENCE_MS
}

pub fn current_time_period() -> u64 {
    crate::util::now_ms() / time_period_length(LAN_MAX_LATENCY_MS)
}

const STATIC_MASTER_KEY_LABEL: &str = "org.briarproject.bramble.transport/STATIC_MASTER_KEY";
const PENDING_CONTACT_ROOT_KEY_LABEL: &str =
    "org.briarproject.bramble.transport/PENDING_CONTACT_ROOT_KEY";
const CONTACT_ROOT_KEY_LABEL: &str = "org.briarproject.bramble.transport/CONTACT_ROOT_KEY";
const ALICE_TAG_LABEL: &str = "org.briarproject.bramble.transport/ALICE_TAG_KEY";
const BOB_TAG_LABEL: &str = "org.briarproject.bramble.transport/BOB_TAG_KEY";
const ALICE_HEADER_LABEL: &str = "org.briarproject.bramble.transport/ALICE_HEADER_KEY";
const BOB_HEADER_LABEL: &str = "org.briarproject.bramble.transport/BOB_HEADER_KEY";
const ROTATE_LABEL: &str = "org.briarproject.bramble.transport/ROTATE";
const ALICE_HANDSHAKE_TAG_LABEL: &str =
    "org.briarproject.bramble.transport/ALICE_HANDSHAKE_TAG_KEY";
const BOB_HANDSHAKE_TAG_LABEL: &str = "org.briarproject.bramble.transport/BOB_HANDSHAKE_TAG_KEY";
const ALICE_HANDSHAKE_HEADER_LABEL: &str =
    "org.briarproject.bramble.transport/ALICE_HANDSHAKE_HEADER_KEY";
const BOB_HANDSHAKE_HEADER_LABEL: &str =
    "org.briarproject.bramble.transport/BOB_HANDSHAKE_HEADER_KEY";

/// Whoever has the numerically smaller handshake public key is Alice.
pub fn is_alice(their_public: &[u8; 32], our_public: &[u8; 32]) -> bool {
    our_public[..] < their_public[..]
}

pub fn derive_static_master_key(
    their_public: &[u8; 32],
    our_private: &SecretKey,
    our_public: &[u8; 32],
) -> Option<SecretKey> {
    let alice = is_alice(their_public, our_public);
    let first: &[u8] = if alice { our_public } else { their_public };
    let second: &[u8] = if alice { their_public } else { our_public };
    crypto::derive_shared_secret(
        STATIC_MASTER_KEY_LABEL,
        their_public,
        our_private,
        &[first, second],
    )
}

pub fn derive_handshake_root_key(static_master_key: &SecretKey, pending_contact: bool) -> SecretKey {
    let label = if pending_contact {
        PENDING_CONTACT_ROOT_KEY_LABEL
    } else {
        CONTACT_ROOT_KEY_LABEL
    };
    crypto::derive_key(label, static_master_key, &[])
}

#[derive(Clone, Copy)]
pub struct StreamKeys {
    pub tag_key: SecretKey,
    pub header_key: SecretKey,
}

/// Handshake mode: keys depend on the time period directly.
pub fn derive_handshake_keys(
    transport_id: &str,
    root_key: &SecretKey,
    time_period: u64,
    key_belongs_to_alice: bool,
) -> StreamKeys {
    let mut period = [0u8; 8];
    write_u64(&mut period, time_period);
    let id = transport_id.as_bytes();
    let tag_label = if key_belongs_to_alice {
        ALICE_HANDSHAKE_TAG_LABEL
    } else {
        BOB_HANDSHAKE_TAG_LABEL
    };
    let header_label = if key_belongs_to_alice {
        ALICE_HANDSHAKE_HEADER_LABEL
    } else {
        BOB_HANDSHAKE_HEADER_LABEL
    };
    StreamKeys {
        tag_key: crypto::derive_key(tag_label, root_key, &[id, &period]),
        header_key: crypto::derive_key(header_label, root_key, &[id, &period]),
    }
}

fn rotate(key: &SecretKey, time_period: u64) -> SecretKey {
    let mut period = [0u8; 8];
    write_u64(&mut period, time_period);
    crypto::derive_key(ROTATE_LABEL, key, &[&period])
}

/// Rotation mode. The key derived from the root key belongs to the period
/// before the one in which the contact was added, so reaching a later period
/// means one rotation per period, each labelled with that period's number --
/// exactly TransportCryptoImpl.deriveRotationKeys followed by
/// updateRotationKeys.
pub fn derive_rotation_keys(
    transport_id: &str,
    root_key: &SecretKey,
    creation_period: u64,
    target_period: u64,
    key_belongs_to_alice: bool,
) -> StreamKeys {
    let id = transport_id.as_bytes();
    let tag_label = if key_belongs_to_alice {
        ALICE_TAG_LABEL
    } else {
        BOB_TAG_LABEL
    };
    let header_label = if key_belongs_to_alice {
        ALICE_HEADER_LABEL
    } else {
        BOB_HEADER_LABEL
    };
    let mut tag = crypto::derive_key(tag_label, root_key, &[id]);
    let mut header = crypto::derive_key(header_label, root_key, &[id]);
    // The unrotated key belongs to the period before the contact was added,
    // so a target before that period is as far back as we can go.
    if target_period >= creation_period {
        for p in creation_period..=target_period {
            tag = rotate(&tag, p);
            header = rotate(&header, p);
        }
    }
    StreamKeys {
        tag_key: tag,
        header_key: header,
    }
}

/// TransportCryptoImpl.encodeTag: a keyed BLAKE2b over the protocol version
/// and stream number, truncated to 16 bytes.
pub fn encode_tag(tag_key: &SecretKey, protocol_version: u16, stream_number: u64) -> [u8; TAG_LEN] {
    use blake2::digest::{FixedOutput, KeyInit, Mac};
    use blake2::Blake2bMac;
    use digest::consts::U32;
    let mut d = <Blake2bMac<U32> as KeyInit>::new_from_slice(tag_key).expect("32-byte key");
    let mut version = [0u8; 2];
    write_u16(&mut version, protocol_version);
    Mac::update(&mut d, &version);
    let mut stream = [0u8; 8];
    write_u64(&mut stream, stream_number);
    Mac::update(&mut d, &stream);
    let out = d.finalize_fixed();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out[..TAG_LEN]);
    tag
}
