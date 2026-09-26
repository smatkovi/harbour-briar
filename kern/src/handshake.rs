//! The handshake protocol (bramble-core HandshakeManagerImpl), version 0.1.
//!
//! Alice -- whoever's handshake public key sorts smaller -- speaks first:
//! minor version, ephemeral public key, then proof of ownership. The result is
//! a master key both peers can derive but nobody else can.

use crate::crypto::{self, SecretKey};
use crate::record::{read_record, write_record, Record};
use std::io::{Read, Write};

pub const PROTOCOL_MAJOR_VERSION: u8 = 0;
pub const PROTOCOL_MINOR_VERSION: u8 = 1;

const RECORD_TYPE_EPHEMERAL_PUBLIC_KEY: u8 = 0;
const RECORD_TYPE_PROOF_OF_OWNERSHIP: u8 = 1;
const RECORD_TYPE_MINOR_VERSION: u8 = 2;

const MASTER_KEY_LABEL_0_1: &str = "org.briarproject.bramble.handshake/MASTER_KEY_0_1";
const ALICE_PROOF_LABEL: &str = "org.briarproject.bramble.handshake/ALICE_PROOF";
const BOB_PROOF_LABEL: &str = "org.briarproject.bramble.handshake/BOB_PROOF";

pub struct HandshakeResult {
    pub master_key: SecretKey,
    pub alice: bool,
}

pub fn derive_master_key(
    their_static_public: &[u8; 32],
    their_ephemeral_public: &[u8; 32],
    our_static_private: &SecretKey,
    our_static_public: &[u8; 32],
    our_ephemeral_private: &SecretKey,
    our_ephemeral_public: &[u8; 32],
    alice: bool,
) -> Option<SecretKey> {
    let inputs: [&[u8]; 4] = if alice {
        [
            our_static_public,
            their_static_public,
            our_ephemeral_public,
            their_ephemeral_public,
        ]
    } else {
        [
            their_static_public,
            our_static_public,
            their_ephemeral_public,
            our_ephemeral_public,
        ]
    };
    crypto::derive_shared_secret_3(
        MASTER_KEY_LABEL_0_1,
        their_static_public,
        their_ephemeral_public,
        our_static_private,
        our_ephemeral_private,
        alice,
        &inputs,
    )
}

pub fn prove_ownership(master_key: &SecretKey, alice: bool) -> SecretKey {
    let label = if alice {
        ALICE_PROOF_LABEL
    } else {
        BOB_PROOF_LABEL
    };
    crypto::mac(label, master_key, &[])
}

pub fn verify_ownership(master_key: &SecretKey, alice: bool, proof: &[u8]) -> bool {
    let label = if alice {
        ALICE_PROOF_LABEL
    } else {
        BOB_PROOF_LABEL
    };
    crypto::verify_mac(proof, label, master_key, &[])
}

/// Runs the whole protocol over one already-encrypted stream pair.
pub fn handshake<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    their_static_public: &[u8; 32],
    our_static_private: &SecretKey,
    our_static_public: &[u8; 32],
    alice: bool,
) -> std::io::Result<HandshakeResult> {
    let our_ephemeral_private = crypto::generate_agreement_private_key();
    let our_ephemeral_public = crypto::agreement_public_key(&our_ephemeral_private);

    let send_keys = |writer: &mut W| -> std::io::Result<()> {
        write_record(
            writer,
            &Record::new(
                PROTOCOL_MAJOR_VERSION,
                RECORD_TYPE_MINOR_VERSION,
                vec![PROTOCOL_MINOR_VERSION],
            ),
        )?;
        write_record(
            writer,
            &Record::new(
                PROTOCOL_MAJOR_VERSION,
                RECORD_TYPE_EPHEMERAL_PUBLIC_KEY,
                our_ephemeral_public.to_vec(),
            ),
        )?;
        writer.flush()
    };

    let their_ephemeral_public;
    if alice {
        send_keys(writer)?;
        their_ephemeral_public = receive_ephemeral_key(reader)?;
    } else {
        their_ephemeral_public = receive_ephemeral_key(reader)?;
        send_keys(writer)?;
    }

    let master_key = derive_master_key(
        their_static_public,
        &their_ephemeral_public,
        our_static_private,
        our_static_public,
        &our_ephemeral_private,
        &our_ephemeral_public,
        alice,
    )
    .ok_or_else(|| bad("key agreement failed"))?;

    let our_proof = prove_ownership(&master_key, alice);
    let their_proof;
    if alice {
        send_proof(writer, &our_proof)?;
        their_proof = receive_proof(reader)?;
    } else {
        their_proof = receive_proof(reader)?;
        send_proof(writer, &our_proof)?;
    }
    if !verify_ownership(&master_key, !alice, &their_proof) {
        return Err(bad("the peer could not prove it owns its key"));
    }
    Ok(HandshakeResult { master_key, alice })
}

fn receive_ephemeral_key(reader: &mut impl Read) -> std::io::Result<[u8; 32]> {
    // Version 0.0 peers send no minor version record, so both orders are
    // accepted here, as in the Java code.
    loop {
        let rec = read_record(reader)?.ok_or_else(|| bad("stream ended during handshake"))?;
        if rec.protocol_version != PROTOCOL_MAJOR_VERSION {
            continue;
        }
        match rec.record_type {
            RECORD_TYPE_MINOR_VERSION => {
                if rec.payload.len() != 1 || rec.payload[0] == 0 {
                    return Err(bad("bad minor version record"));
                }
            }
            RECORD_TYPE_EPHEMERAL_PUBLIC_KEY => {
                if rec.payload.len() != 32 {
                    return Err(bad("bad ephemeral public key"));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&rec.payload);
                return Ok(key);
            }
            _ => {}
        }
    }
}

fn send_proof(writer: &mut impl Write, proof: &SecretKey) -> std::io::Result<()> {
    write_record(
        writer,
        &Record::new(
            PROTOCOL_MAJOR_VERSION,
            RECORD_TYPE_PROOF_OF_OWNERSHIP,
            proof.to_vec(),
        ),
    )?;
    writer.flush()
}

fn receive_proof(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    loop {
        let rec = read_record(reader)?.ok_or_else(|| bad("stream ended before the proof"))?;
        if rec.protocol_version == PROTOCOL_MAJOR_VERSION
            && rec.record_type == RECORD_TYPE_PROOF_OF_OWNERSHIP
        {
            if rec.payload.len() != 32 {
                return Err(bad("proof has the wrong length"));
            }
            return Ok(rec.payload);
        }
    }
}

fn bad(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}
