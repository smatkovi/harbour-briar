//! Contact exchange (bramble-core ContactExchangeManagerImpl): each peer
//! sends its author, its transport properties, a signature over a nonce
//! derived from the handshake's master key, and its clock.

use crate::bdf::Bdf;
use crate::crypto::{self, SecretKey};
use crate::record::{read_record, write_record, Record};
use std::collections::BTreeMap;
use std::io::{Read, Write};

pub const PROTOCOL_VERSION: u8 = 1;
const CONTACT_INFO: u8 = 0;

const ALICE_KEY_LABEL: &str = "org.briarproject.bramble.contact/ALICE_HEADER_KEY";
const BOB_KEY_LABEL: &str = "org.briarproject.bramble.contact/BOB_HEADER_KEY";
const ALICE_NONCE_LABEL: &str = "org.briarproject.bramble.contact/ALICE_NONCE";
const BOB_NONCE_LABEL: &str = "org.briarproject.bramble.contact/BOB_NONCE";
const SIGNING_LABEL: &str = "org.briarproject.briar.contact/EXCHANGE";

pub fn derive_header_key(master_key: &SecretKey, alice: bool) -> SecretKey {
    let label = if alice { ALICE_KEY_LABEL } else { BOB_KEY_LABEL };
    crypto::derive_key(label, master_key, &[&[PROTOCOL_VERSION]])
}

fn nonce(master_key: &SecretKey, alice: bool) -> SecretKey {
    let label = if alice {
        ALICE_NONCE_LABEL
    } else {
        BOB_NONCE_LABEL
    };
    crypto::mac(label, master_key, &[&[PROTOCOL_VERSION]])
}

pub fn sign_nonce(seed: &SecretKey, master_key: &SecretKey, alice: bool) -> Vec<u8> {
    crypto::sign(SIGNING_LABEL, &nonce(master_key, alice), seed)
}

pub fn verify_nonce(
    public_key: &[u8],
    master_key: &SecretKey,
    alice: bool,
    signature: &[u8],
) -> bool {
    crypto::verify_signature(signature, SIGNING_LABEL, &nonce(master_key, alice), public_key)
}

#[derive(Clone, Debug)]
pub struct ContactInfo {
    pub name: String,
    pub public_key: Vec<u8>,
    /// transport id -> property key -> value
    pub properties: BTreeMap<String, BTreeMap<String, String>>,
    pub timestamp: u64,
}

fn properties_to_bdf(props: &BTreeMap<String, BTreeMap<String, String>>) -> Bdf {
    let mut outer = BTreeMap::new();
    for (transport, values) in props {
        let mut inner = BTreeMap::new();
        for (k, v) in values {
            inner.insert(k.clone(), Bdf::Str(v.clone()));
        }
        outer.insert(transport.clone(), Bdf::Dict(inner));
    }
    Bdf::Dict(outer)
}

fn properties_from_bdf(value: &Bdf) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    if let Some(dict) = value.as_dict() {
        for (transport, inner) in dict {
            let mut values = BTreeMap::new();
            if let Some(d) = inner.as_dict() {
                for (k, v) in d {
                    if let Some(s) = v.as_str() {
                        values.insert(k.clone(), s.to_string());
                    }
                }
            }
            out.insert(transport.clone(), values);
        }
    }
    out
}

/// Exchanges contact info over the two contact-exchange streams and returns
/// what the peer sent, together with its signature.
pub fn exchange<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    local: &ContactInfo,
    signature: &[u8],
    alice: bool,
) -> std::io::Result<(ContactInfo, Vec<u8>)> {
    let payload = Bdf::List(vec![
        Bdf::List(vec![
            Bdf::Int(crate::ids::AUTHOR_FORMAT_VERSION as i64),
            Bdf::Str(local.name.clone()),
            Bdf::Raw(local.public_key.clone()),
        ]),
        properties_to_bdf(&local.properties),
        Bdf::Raw(signature.to_vec()),
        Bdf::Int(local.timestamp as i64),
    ]);
    let record = Record::new(PROTOCOL_VERSION, CONTACT_INFO, crate::bdf::to_bytes(&payload));

    let remote;
    if alice {
        write_record(writer, &record)?;
        writer.flush()?;
        remote = receive(reader)?;
    } else {
        remote = receive(reader)?;
        write_record(writer, &record)?;
        writer.flush()?;
    }
    Ok(remote)
}

pub fn receive(reader: &mut impl Read) -> std::io::Result<(ContactInfo, Vec<u8>)> {
    loop {
        let rec = read_record(reader)?.ok_or_else(|| bad("stream ended before contact info"))?;
        if rec.protocol_version != PROTOCOL_VERSION || rec.record_type != CONTACT_INFO {
            continue;
        }
        let list = crate::bdf::from_bytes(&rec.payload)?;
        let items = list.as_list().ok_or_else(|| bad("contact info is not a list"))?;
        if items.len() != 4 {
            return Err(bad("contact info has the wrong size"));
        }
        let author = items[0]
            .as_list()
            .ok_or_else(|| bad("author is not a list"))?;
        if author.len() != 3 {
            return Err(bad("author has the wrong size"));
        }
        let name = author[1]
            .as_str()
            .ok_or_else(|| bad("author name is not a string"))?
            .to_string();
        let public_key = author[2]
            .as_raw()
            .ok_or_else(|| bad("author key is not raw"))?
            .to_vec();
        // Wie Briar (ContactExchangeManagerImpl.parseContactInfo ->
        // parseAndValidateAuthor): ein Name ueber 50 Byte oder ein Schluessel
        // falscher Laenge ist ein Formfehler.
        if !crate::groups::autor_gueltig(&name, &public_key) {
            return Err(bad("author name or key out of bounds"));
        }
        let properties = properties_from_bdf(&items[1]);
        let signature = items[2]
            .as_raw()
            .ok_or_else(|| bad("signature is not raw"))?
            .to_vec();
        let timestamp = items[3].as_int().ok_or_else(|| bad("no timestamp"))? as u64;
        return Ok((
            ContactInfo {
                name,
                public_key,
                properties,
                timestamp,
            },
            signature,
        ));
    }
}

fn bad(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ein CONTACT_INFO-Satz, wie ihn die Gegenseite schickt.
    fn satz(name: &str, schluessel: usize) -> Vec<u8> {
        let payload = Bdf::List(vec![
            Bdf::List(vec![
                Bdf::Int(crate::ids::AUTHOR_FORMAT_VERSION as i64),
                Bdf::Str(name.to_string()),
                Bdf::Raw(vec![5u8; schluessel]),
            ]),
            Bdf::Dict(BTreeMap::new()),
            Bdf::Raw(vec![1u8; 64]),
            Bdf::Int(1000),
        ]);
        let mut aus = Vec::new();
        write_record(
            &mut aus,
            &Record::new(PROTOCOL_VERSION, CONTACT_INFO, crate::bdf::to_bytes(&payload)),
        )
        .unwrap();
        aus
    }

    #[test]
    fn kontaktinfo_mit_gueltigem_autor_wird_gelesen() {
        let roh = satz("Bob", 32);
        let (info, _) = receive(&mut &roh[..]).unwrap();
        assert_eq!(info.name, "Bob");
    }

    #[test]
    fn kontaktinfo_mit_zu_langem_namen_ist_ein_formfehler() {
        let roh = satz(&"b".repeat(51), 32);
        assert!(receive(&mut &roh[..]).is_err());
    }

    #[test]
    fn kontaktinfo_mit_falscher_schluessellaenge_ist_ein_formfehler() {
        let roh = satz("Bob", 16);
        assert!(receive(&mut &roh[..]).is_err());
    }
}
