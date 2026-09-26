//! On-disk state. Briar keeps everything in an encrypted H2 database; this
//! port keeps a JSON file, because the database format is nobody's business
//! but Briar's -- only the wire formats have to match.

use crate::crypto::{self, SecretKey};
use crate::ids;
use crate::util::{from_hex, to_hex};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    /// Ed25519 seed (Briar's "signature private key")
    pub signature_seed: String,
    pub signature_public: String,
    pub author_id: String,
    /// Curve25519 private key used for handshakes and links
    pub handshake_private: String,
    pub handshake_public: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TransportState {
    /// ip:port for the LAN, the Bluetooth address for Bluetooth
    pub address: Option<String>,
    pub out_stream: u64,
    /// Next expected incoming stream number, per time period
    pub in_stream: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingContact {
    pub public_key: String,
    pub alias: String,
    pub address: Option<String>,
    pub bluetooth: Option<String>,
    #[serde(default)]
    pub onion: Option<String>,
    pub added: u64,
    pub last_error: Option<String>,
}

/// A one-to-one message, as the interface shows it. A message may carry an
/// attachment, which travels as a message of its own and is named here by
/// its identifier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub timestamp: u64,
    pub text: String,
    pub outgoing: bool,
    pub acked: bool,
    #[serde(default)]
    pub attachment: Option<String>,
    #[serde(default)]
    pub attachment_type: Option<String>,
}

/// An attachment that has arrived or been sent: its bytes live in a file
/// beside the state, not in it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attachment {
    pub content_type: String,
    pub path: String,
    pub size: u64,
}

/// A message waiting to be delivered to one contact: the bytes as they go on
/// the wire, whatever client they belong to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutMessage {
    pub id: String,
    pub group: String,
    pub timestamp: u64,
    pub body: String,
    pub acked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    pub id: u32,
    pub name: String,
    pub author_id: String,
    pub signature_public: String,
    pub handshake_public: Option<String>,
    pub master_key: String,
    pub alice: bool,
    pub creation_period: u64,
    #[serde(default)]
    pub transports: BTreeMap<String, TransportState>,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub outbox: Vec<OutMessage>,
    /// Identifiers we have received and still owe an acknowledgement for
    #[serde(default)]
    pub to_ack: Vec<String>,
    pub last_seen: u64,
    #[serde(default)]
    pub sent_versioning_update: bool,
    /// The addresses last announced to this contact. When ours change -- Tor
    /// switched on, a new WLAN -- the announcement goes out again.
    #[serde(default)]
    pub sent_properties: Option<String>,
    /// When the user last looked at this chat -- what came later counts as
    /// unread, and that is what a notification is raised for.
    #[serde(default)]
    pub last_read: u64,
}

impl Contact {
    pub fn master_key_bytes(&self) -> SecretKey {
        key_from_hex(&self.master_key)
    }

    pub fn author_id_bytes(&self) -> SecretKey {
        key_from_hex(&self.author_id)
    }

    pub fn transport(&self, id: &str) -> Option<&TransportState> {
        self.transports.get(id)
    }

    pub fn address(&self, transport_id: &str) -> Option<String> {
        self.transports
            .get(transport_id)
            .and_then(|t| t.address.clone())
    }

    pub fn transport_mut(&mut self, id: &str) -> &mut TransportState {
        self.transports.entry(id.to_string()).or_default()
    }
}

/// A message in a private group, as the interface shows it -- plus the bytes
/// it arrived as, because they have to be passed on to other members
/// unchanged: the identifier is a hash over them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupPost {
    pub id: String,
    pub author_id: String,
    pub author_name: String,
    pub timestamp: u64,
    pub text: String,
    pub body: String,
    pub join: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateGroup {
    pub id: String,
    pub name: String,
    pub salt: String,
    pub creator_name: String,
    pub creator_public: String,
    pub creator_author_id: String,
    /// False while an invitation is only offered and not accepted
    pub joined: bool,
    pub invited_by: Option<u32>,
    /// Timestamp and signature of the invitation, which our join message
    /// carries as proof
    pub invite_timestamp: Option<u64>,
    pub invite_signature: Option<String>,
    #[serde(default)]
    pub member_names: BTreeMap<String, String>,
    /// As with a contact: what came after this counts as unread
    #[serde(default)]
    pub last_read: u64,
    #[serde(default)]
    pub messages: Vec<GroupPost>,
    /// Our own last message in this group: the next one names it
    pub our_previous: Option<String>,
    /// Contacts this group is synced with
    #[serde(default)]
    pub contacts: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct State {
    pub identity: Option<Identity>,
    pub listen_port: u16,
    #[serde(default = "enabled")]
    pub bluetooth: bool,
    #[serde(default = "enabled")]
    pub tor: bool,
    /// The hidden service's key, so contacts keep reaching the same address
    #[serde(default)]
    pub tor_key: Option<String>,
    #[serde(default)]
    pub tor_onion: Option<String>,
    #[serde(default)]
    pub pending: Vec<PendingContact>,
    #[serde(default)]
    pub contacts: Vec<Contact>,
    #[serde(default)]
    pub groups: Vec<PrivateGroup>,
    /// Attachment identifier -> the file it was written to
    #[serde(default)]
    pub attachments: BTreeMap<String, Attachment>,
    #[serde(default)]
    pub next_contact_id: u32,
    /// Bumped on every change, so the user interface can poll cheaply
    #[serde(default)]
    pub revision: u64,
    /// Which migrations have already been applied to this file
    #[serde(default)]
    pub state_version: u32,
    /// "en" or "de" -- English unless the user switches, on both front ends
    #[serde(default)]
    pub language: Option<String>,
}

/// The newest layout this build knows.
const STATE_VERSION: u32 = 2;

/// Transports are on unless switched off -- a state file written before a
/// transport existed should not leave it disabled for ever.
fn enabled() -> bool {
    true
}

/// Whether Tor starts by itself. A Tor process costs some 30 MB, which is
/// a lot on Harmattan (armv7) and nothing much on the Jolla, so there the
/// user switches it on when they want it -- the help page says so.
pub fn tor_default() -> bool {
    !cfg!(target_arch = "arm")
}

pub struct Store {
    pub path: PathBuf,
    pub state: State,
}

pub fn key_from_hex(s: &str) -> SecretKey {
    let mut k = [0u8; 32];
    if let Some(b) = from_hex(s) {
        if b.len() == 32 {
            k.copy_from_slice(&b);
        }
    }
    k
}

impl Store {
    pub fn open(path: &Path, default_port: u16) -> std::io::Result<Store> {
        let state = if path.exists() {
            let text = std::fs::read_to_string(path)?;
            serde_json::from_str(&text).unwrap_or_default()
        } else {
            State {
                listen_port: default_port,
                next_contact_id: 1,
                bluetooth: true,
                tor: tor_default(),
                state_version: STATE_VERSION,
                ..Default::default()
            }
        };
        let mut store = Store {
            path: path.to_path_buf(),
            state,
        };
        if store.state.listen_port == 0 {
            store.state.listen_port = default_port;
        }
        if store.state.next_contact_id == 0 {
            store.state.next_contact_id = 1;
        }
        // Version 0 files were written before Tor existed and carry a
        // `tor: false` that the user never chose; give them the default
        // once, and never touch the flag again afterwards.
        if store.state.state_version < 1 {
            store.state.tor = tor_default();
        }
        // Version 1 noted addresses as announced even when the peer was
        // still running a version that did not understand the announcement.
        // Forget that note once, so every contact hears them again.
        if store.state.state_version < 2 {
            for contact in store.state.contacts.iter_mut() {
                contact.sent_properties = None;
            }
        }
        if store.state.state_version != STATE_VERSION {
            store.state.state_version = STATE_VERSION;
            let _ = store.save();
        }
        Ok(store)
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        self.state.revision += 1;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(&self.state)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)
    }

    pub fn create_identity(&mut self, name: &str) -> std::io::Result<Identity> {
        let seed = crypto::generate_secret_key();
        let signature_public = crypto::signature_public_key(&seed);
        let handshake_private = crypto::generate_agreement_private_key();
        let handshake_public = crypto::agreement_public_key(&handshake_private);
        let identity = Identity {
            name: name.to_string(),
            signature_seed: to_hex(&seed),
            signature_public: to_hex(&signature_public),
            author_id: to_hex(&ids::author_id(name, &signature_public)),
            handshake_private: to_hex(&handshake_private),
            handshake_public: to_hex(&handshake_public),
        };
        self.state.identity = Some(identity.clone());
        self.save()?;
        Ok(identity)
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.state.identity.as_ref()
    }

    pub fn author(&self) -> Option<crate::groups::Author> {
        let identity = self.identity()?;
        Some(crate::groups::Author {
            name: identity.name.clone(),
            public_key: from_hex(&identity.signature_public)?,
        })
    }

    pub fn link(&self) -> Option<String> {
        self.identity()
            .map(|i| ids::handshake_link(&key_from_hex(&i.handshake_public)))
    }

    pub fn contact(&self, id: u32) -> Option<&Contact> {
        self.state.contacts.iter().find(|c| c.id == id)
    }

    pub fn contact_mut(&mut self, id: u32) -> Option<&mut Contact> {
        self.state.contacts.iter_mut().find(|c| c.id == id)
    }

    pub fn group(&self, id: &str) -> Option<&PrivateGroup> {
        self.state.groups.iter().find(|g| g.id == id)
    }

    pub fn group_mut(&mut self, id: &str) -> Option<&mut PrivateGroup> {
        self.state.groups.iter_mut().find(|g| g.id == id)
    }

    pub fn add_message(&mut self, contact_id: u32, message: Message) -> bool {
        if let Some(contact) = self.contact_mut(contact_id) {
            if contact.messages.iter().any(|m| m.id == message.id) {
                return false;
            }
            contact.messages.push(message);
            contact.messages.sort_by_key(|m| m.timestamp);
            true
        } else {
            false
        }
    }

    /// Where attachment files live: beside the state file, so a wiped state
    /// takes its attachments with it.
    pub fn attachment_dir(&self) -> PathBuf {
        self.path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("attachments")
    }

    /// Writes an attachment's bytes to disk and remembers where.
    pub fn store_attachment(
        &mut self,
        id: &str,
        content_type: &str,
        data: &[u8],
    ) -> std::io::Result<String> {
        let dir = self.attachment_dir();
        std::fs::create_dir_all(&dir)?;
        let extension = match content_type {
            "image/jpeg" => "jpg",
            "image/png" => "png",
            "image/gif" => "gif",
            "text/plain" => "txt",
            _ => "bin",
        };
        let file = dir.join(format!("{}.{}", id, extension));
        std::fs::write(&file, data)?;
        let path = file.to_string_lossy().to_string();
        self.state.attachments.insert(
            id.to_string(),
            Attachment {
                content_type: content_type.to_string(),
                path: path.clone(),
                size: data.len() as u64,
            },
        );
        Ok(path)
    }

    pub fn attachment(&self, id: &str) -> Option<&Attachment> {
        self.state.attachments.get(id)
    }

    /// Queues a message for delivery to one contact.
    pub fn queue(&mut self, contact_id: u32, out: OutMessage) {
        if let Some(contact) = self.contact_mut(contact_id) {
            if contact.outbox.iter().any(|m| m.id == out.id) {
                return;
            }
            contact.outbox.push(out);
        }
    }
}
