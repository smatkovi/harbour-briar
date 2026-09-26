//! The sync protocol (BSP, bramble-core/sync) and the private messaging
//! client's message bodies (briar-core/messaging).

use crate::bdf::Bdf;
use crate::crypto::SecretKey;
use crate::ids;
use crate::record::{write_record, Record};
use std::io::Write;

pub const PROTOCOL_VERSION: u8 = 0;
pub const ACK: u8 = 0;
pub const MESSAGE: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const VERSIONS: u8 = 4;
pub const PRIORITY: u8 = 5;

pub const MESSAGING_CLIENT_ID: &str = "org.briarproject.briar.messaging";
pub const MESSAGING_MAJOR_VERSION: u32 = 0;
pub const MESSAGING_MINOR_VERSION: u32 = 3;
pub const VERSIONING_CLIENT_ID: &str = "org.briarproject.bramble.versioning";
pub const VERSIONING_MAJOR_VERSION: u32 = 0;
pub const PROPERTIES_CLIENT_ID: &str = "org.briarproject.bramble.properties";
pub const PROPERTIES_MAJOR_VERSION: u32 = 0;

const PRIVATE_MESSAGE: i64 = 0;
const ATTACHMENT: i64 = 1;

/// A message body may not exceed this, so an attachment has to fit in one
/// message -- which is why Briar compresses images before sending them.
pub const MAX_MESSAGE_BODY_LEN: usize = 32 * 1024;

/// The group in which two contacts exchange private messages.
pub fn messaging_group_id(author_a: &SecretKey, author_b: &SecretKey) -> SecretKey {
    ids::contact_group_id(
        MESSAGING_CLIENT_ID,
        MESSAGING_MAJOR_VERSION,
        author_a,
        author_b,
    )
}

/// A private message body: message type, text, attachment headers --
/// client version 0.1 to 0.2 shape, which 1.5 still accepts.
pub fn private_message_body(text: &str) -> Vec<u8> {
    private_message_body_with(Some(text), &[])
}

/// The same, with attachment headers: each names the identifier of an
/// attachment message and its content type.
pub fn private_message_body_with(
    text: Option<&str>,
    attachments: &[(SecretKey, String)],
) -> Vec<u8> {
    let headers = attachments
        .iter()
        .map(|(id, content_type)| {
            Bdf::List(vec![
                Bdf::Raw(id.to_vec()),
                Bdf::Str(content_type.clone()),
            ])
        })
        .collect();
    crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(PRIVATE_MESSAGE),
        match text {
            Some(t) => Bdf::Str(t.to_string()),
            None => Bdf::Null,
        },
        Bdf::List(headers),
    ]))
}

/// An attachment message: a two-element list saying what it is, and then the
/// file's bytes, straight after the list. Briar reads the list and takes
/// everything behind it as the data.
pub fn attachment_body(content_type: &str, data: &[u8]) -> Vec<u8> {
    let mut body = crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(ATTACHMENT),
        Bdf::Str(content_type.to_string()),
    ]));
    body.extend_from_slice(data);
    body
}

/// How much of a message body is left for an attachment's data.
pub fn attachment_capacity(content_type: &str) -> usize {
    let descriptor = crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(ATTACHMENT),
        Bdf::Str(content_type.to_string()),
    ]));
    MAX_MESSAGE_BODY_LEN.saturating_sub(descriptor.len())
}

/// Counts how many bytes a reader consumed, so the data after the
/// descriptor can be found.
struct Counting<'a> {
    inner: &'a [u8],
    read: usize,
}

impl<'a> std::io::Read for Counting<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let take = buf.len().min(self.inner.len() - self.read);
        buf[..take].copy_from_slice(&self.inner[self.read..self.read + take]);
        self.read += take;
        Ok(take)
    }
}

/// Splits an attachment message into its content type and its data.
pub fn parse_attachment(body: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut counting = Counting {
        inner: body,
        read: 0,
    };
    let (list, consumed) = {
        let mut reader = crate::bdf::Reader::new(&mut counting);
        let list = reader.read().ok()?;
        let buffered = reader.buffered();
        (list, buffered)
    };
    let consumed = counting.read - consumed;
    let items = list.as_list()?;
    if items.len() != 2 || items[0].as_int()? != ATTACHMENT {
        return None;
    }
    let content_type = items[1].as_str()?.to_string();
    Some((content_type, body[consumed..].to_vec()))
}

/// The attachment headers of a private message: identifier and content type.
pub fn private_message_attachments(body: &[u8]) -> Vec<(SecretKey, String)> {
    let mut out = Vec::new();
    let list = match crate::bdf::from_bytes(body) {
        Ok(l) => l,
        Err(_) => return out,
    };
    let items = match list.as_list() {
        Some(i) => i,
        None => return out,
    };
    if items.len() < 3 || items[0].as_int() != Some(PRIVATE_MESSAGE) {
        return out;
    }
    if let Some(headers) = items[2].as_list() {
        for header in headers {
            if let Some(parts) = header.as_list() {
                if parts.len() == 2 {
                    if let (Some(raw), Some(content_type)) =
                        (parts[0].as_raw(), parts[1].as_str())
                    {
                        if raw.len() == 32 {
                            let mut id = [0u8; 32];
                            id.copy_from_slice(raw);
                            out.push((id, content_type.to_string()));
                        }
                    }
                }
            }
        }
    }
    out
}

/// Reads the text out of a private message body, accepting the legacy
/// single-element shape as well.
pub fn private_message_text(body: &[u8]) -> Option<String> {
    let list = crate::bdf::from_bytes(body).ok()?;
    let items = list.as_list()?;
    if items.len() == 1 {
        return items[0].as_str().map(|s| s.to_string());
    }
    if items.is_empty() {
        return None;
    }
    if items[0].as_int() != Some(PRIVATE_MESSAGE) {
        return None;
    }
    // A message with an attachment and no text is still a message.
    Some(
        items
            .get(1)
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string(),
    )
}

/// True if this body is an attachment rather than a private message.
pub fn is_attachment(body: &[u8]) -> bool {
    match crate::bdf::from_bytes(body) {
        Ok(list) => match list.as_list() {
            Some(items) => items.len() == 2 && items[0].as_int() == Some(ATTACHMENT),
            None => false,
        },
        Err(_) => false,
    }
}

pub fn write_versions(out: &mut impl Write) -> std::io::Result<()> {
    write_record(
        out,
        &Record::new(PROTOCOL_VERSION, VERSIONS, vec![PROTOCOL_VERSION]),
    )
}

pub fn write_priority(out: &mut impl Write, nonce: &[u8]) -> std::io::Result<()> {
    write_record(
        out,
        &Record::new(PROTOCOL_VERSION, PRIORITY, nonce.to_vec()),
    )
}

pub fn write_ack(out: &mut impl Write, ids: &[SecretKey]) -> std::io::Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut payload = Vec::with_capacity(ids.len() * 32);
    for id in ids {
        payload.extend_from_slice(id);
    }
    write_record(out, &Record::new(PROTOCOL_VERSION, ACK, payload))
}

pub fn write_message(
    out: &mut impl Write,
    group_id: &SecretKey,
    timestamp: u64,
    body: &[u8],
) -> std::io::Result<()> {
    let raw = ids::raw_message(group_id, timestamp, body);
    write_record(out, &Record::new(PROTOCOL_VERSION, MESSAGE, raw))
}

/// The identifiers in an ack, offer or request record.
pub fn parse_ids(payload: &[u8]) -> Vec<SecretKey> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + 32 <= payload.len() {
        let mut id = [0u8; 32];
        id.copy_from_slice(&payload[offset..offset + 32]);
        out.push(id);
        offset += 32;
    }
    out
}

/// The versioning client's update message: a list of client states and an
/// update version. Briar only makes a client's group visible once it has seen
/// such an update, so a port that wants to talk to the real Briar has to send
/// one.
pub fn versioning_update_body(update_version: i64) -> Vec<u8> {
    let states = Bdf::List(vec![Bdf::List(vec![
        Bdf::Str(MESSAGING_CLIENT_ID.to_string()),
        Bdf::Int(MESSAGING_MAJOR_VERSION as i64),
        Bdf::Int(MESSAGING_MINOR_VERSION as i64),
        Bdf::Bool(true),
    ])]);
    crate::bdf::to_bytes(&Bdf::List(vec![states, Bdf::Int(update_version)]))
}

/// Where two contacts tell each other their addresses. Briar's properties
/// client does the same job; this is its shape -- transport, version,
/// dictionary -- without the rest of that client's machinery. It matters
/// because a contact made before Tor existed would otherwise never learn the
/// other side's onion address.
pub fn properties_group_id(author_a: &SecretKey, author_b: &SecretKey) -> SecretKey {
    ids::contact_group_id(
        PROPERTIES_CLIENT_ID,
        PROPERTIES_MAJOR_VERSION,
        author_a,
        author_b,
    )
}

pub fn properties_update_body(
    transport_id: &str,
    version: i64,
    values: &std::collections::BTreeMap<String, String>,
) -> Vec<u8> {
    let dict: std::collections::BTreeMap<String, Bdf> = values
        .iter()
        .map(|(k, v)| (k.clone(), Bdf::Str(v.clone())))
        .collect();
    crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Str(transport_id.to_string()),
        Bdf::Int(version),
        Bdf::Dict(dict),
    ]))
}

pub fn parse_properties_update(
    body: &[u8],
) -> Option<(String, i64, std::collections::BTreeMap<String, String>)> {
    let parsed = crate::bdf::from_bytes(body).ok()?;
    let list = match parsed {
        Bdf::List(items) => items,
        _ => return None,
    };
    if list.len() < 3 {
        return None;
    }
    let transport = match &list[0] {
        Bdf::Str(s) => s.clone(),
        _ => return None,
    };
    let version = match &list[1] {
        Bdf::Int(v) => *v,
        _ => return None,
    };
    let mut values = std::collections::BTreeMap::new();
    if let Bdf::Dict(entries) = &list[2] {
        for (key, value) in entries {
            if let Bdf::Str(text) = value {
                values.insert(key.clone(), text.clone());
            }
        }
    }
    Some((transport, version, values))
}

pub fn versioning_group_id(author_a: &SecretKey, author_b: &SecretKey) -> SecretKey {
    ids::contact_group_id(
        VERSIONING_CLIENT_ID,
        VERSIONING_MAJOR_VERSION,
        author_a,
        author_b,
    )
}
