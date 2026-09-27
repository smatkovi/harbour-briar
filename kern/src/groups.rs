//! Private groups (briar-core/privategroup) and their invitations.
//!
//! A private group is a sync group whose descriptor names its creator, its
//! name and a random salt. Every member's messages are signed and chained:
//! a member's first message is its JOIN, and each later message names the
//! member's previous one, so nobody can quietly drop a message from the
//! middle of someone's history.
//!
//! The wire formats here are Briar's. What this port does differently is how
//! an invitation reaches the other side: Briar runs a whole invitation
//! protocol with its own session state, this sends the single INVITE message
//! Briar's encoder produces and lets the user accept or decline it.

use crate::bdf::Bdf;
use crate::crypto::{self, SecretKey};
use crate::ids;

pub const CLIENT_ID: &str = "org.briarproject.briar.privategroup";
pub const MAJOR_VERSION: u32 = 0;
pub const INVITE_CLIENT_ID: &str = "org.briarproject.briar.privategroup.invitation";
pub const INVITE_MAJOR_VERSION: u32 = 0;
pub const SALT_LEN: usize = 32;

const SIGNING_LABEL_JOIN: &str = "org.briarproject.briar.privategroup/JOIN";
const SIGNING_LABEL_POST: &str = "org.briarproject.briar.privategroup/POST";
const SIGNING_LABEL_INVITE: &str = "org.briarproject.briar.privategroup.invitation/INVITE";

// Der Gruppenklient selbst: seine Nachrichten stehen IN der Gruppe.
const JOIN: i64 = 0;
const POST: i64 = 1;

// Der Einladungsklient: seine Nachrichten stehen in der Kontaktgruppe, die
// sich die beiden Kontakte teilen. Die Zahlen stammen aus MessageType.java:
//   INVITE(0), JOIN(1), LEAVE(2), ABORT(3)
const INVITE: i64 = 0;
const EINLADUNG_JOIN: i64 = 1;
const EINLADUNG_LEAVE: i64 = 2;
const EINLADUNG_ABORT: i64 = 3;

#[derive(Clone, Debug, PartialEq)]
pub struct Author {
    pub name: String,
    pub public_key: Vec<u8>,
}

impl Author {
    pub fn id(&self) -> SecretKey {
        ids::author_id(&self.name, &self.public_key)
    }

    pub fn to_bdf(&self) -> Bdf {
        Bdf::List(vec![
            Bdf::Int(ids::AUTHOR_FORMAT_VERSION as i64),
            Bdf::Str(self.name.clone()),
            Bdf::Raw(self.public_key.clone()),
        ])
    }

    pub fn from_bdf(value: &Bdf) -> Option<Author> {
        let items = value.as_list()?;
        if items.len() != 3 || items[0].as_int()? != ids::AUTHOR_FORMAT_VERSION as i64 {
            return None;
        }
        Some(Author {
            name: items[1].as_str()?.to_string(),
            public_key: items[2].as_raw()?.to_vec(),
        })
    }
}

/// The group descriptor: creator, name, salt -- and from it the group id.
pub fn descriptor(creator: &Author, name: &str, salt: &[u8]) -> Vec<u8> {
    crate::bdf::to_bytes(&Bdf::List(vec![
        creator.to_bdf(),
        Bdf::Str(name.to_string()),
        Bdf::Raw(salt.to_vec()),
    ]))
}

pub fn group_id(creator: &Author, name: &str, salt: &[u8]) -> SecretKey {
    ids::group_id(CLIENT_ID, MAJOR_VERSION, &descriptor(creator, name, salt))
}

/// A member's first message in the group. An invited member carries the
/// creator's invitation with it, the creator's own join carries nothing.
pub fn join_body(
    group: &SecretKey,
    timestamp: u64,
    member: &Author,
    member_seed: &SecretKey,
    invite: Option<(u64, Vec<u8>)>,
) -> Vec<u8> {
    let invite_bdf = match &invite {
        Some((invite_timestamp, signature)) => Bdf::List(vec![
            Bdf::Int(*invite_timestamp as i64),
            Bdf::Raw(signature.clone()),
        ]),
        None => Bdf::Null,
    };
    let to_sign = crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Raw(group.to_vec()),
        Bdf::Int(timestamp as i64),
        member.to_bdf(),
        invite_bdf.clone(),
    ]));
    let signature = crypto::sign(SIGNING_LABEL_JOIN, &to_sign, member_seed);
    crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(JOIN),
        member.to_bdf(),
        invite_bdf,
        Bdf::Raw(signature),
    ]))
}

/// A post. `previous` is the member's own previous message in this group --
/// its join message, or the post before this one.
pub fn post_body(
    group: &SecretKey,
    timestamp: u64,
    member: &Author,
    member_seed: &SecretKey,
    parent: Option<SecretKey>,
    previous: &SecretKey,
    text: &str,
) -> Vec<u8> {
    let parent_bdf = match parent {
        Some(id) => Bdf::Raw(id.to_vec()),
        None => Bdf::Null,
    };
    let to_sign = crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Raw(group.to_vec()),
        Bdf::Int(timestamp as i64),
        member.to_bdf(),
        parent_bdf.clone(),
        Bdf::Raw(previous.to_vec()),
        Bdf::Str(text.to_string()),
    ]));
    let signature = crypto::sign(SIGNING_LABEL_POST, &to_sign, member_seed);
    crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(POST),
        member.to_bdf(),
        parent_bdf,
        Bdf::Raw(previous.to_vec()),
        Bdf::Str(text.to_string()),
        Bdf::Raw(signature),
    ]))
}

/// Rueckt einen Zeitstempel vor, wenn die Uhr nicht weit genug ist: Briars
/// max(jetzt, vorher + 1) aus AbstractProtocolEngine. Zwei Regeln brauchen das,
/// und beide kosten uns sonst die Nachricht:
///
///   * Ein JOIN muss echt hinter der Einladung liegen, auf die es sich beruft.
///     GroupMessageValidator.validateJoin (Zeile 104-107) erklaert es sonst
///     fuer ungueltig, und in der Einladungsgruppe bricht die Sitzung des
///     Einladenden ab statt die Gruppe zu teilen
///     (CreatorProtocolEngine.onRemoteAccept, Zeile 190-191).
///   * Ein Beitrag muss echt hinter unserer vorigen eigenen Nachricht in
///     derselben Gruppe liegen. PrivateGroupManagerImpl.handleGroupMessage
///     (Zeile 588) wirft ihn sonst beim Zustellen weg -- endgueltig und ohne
///     ein Wort an den Absender.
///
/// `jetzt` kommt von aussen, damit die Regel ohne Uhr zu pruefen ist.
pub fn vorgerueckt(jetzt: u64, vorher: u64) -> u64 {
    jetzt.max(vorher.saturating_add(1))
}

#[derive(Clone, Debug)]
pub enum GroupMessage {
    Join {
        member: Author,
        invite: Option<(u64, Vec<u8>)>,
    },
    Post {
        member: Author,
        parent: Option<SecretKey>,
        previous: SecretKey,
        text: String,
    },
}

impl GroupMessage {
    pub fn member(&self) -> &Author {
        match self {
            GroupMessage::Join { member, .. } => member,
            GroupMessage::Post { member, .. } => member,
        }
    }
}

fn raw32(value: &Bdf) -> Option<SecretKey> {
    let raw = value.as_raw()?;
    if raw.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(raw);
    Some(id)
}

/// Parses a group message and checks its signature, which is what makes the
/// member's authorship worth anything.
pub fn parse_body(group: &SecretKey, timestamp: u64, body: &[u8]) -> Option<GroupMessage> {
    let list = crate::bdf::from_bytes(body).ok()?;
    let items = list.as_list()?;
    match items.first()?.as_int()? {
        JOIN => {
            if items.len() != 4 {
                return None;
            }
            let member = Author::from_bdf(&items[1])?;
            let invite = match &items[2] {
                Bdf::Null => None,
                Bdf::List(parts) if parts.len() == 2 => Some((
                    parts[0].as_int()? as u64,
                    parts[1].as_raw()?.to_vec(),
                )),
                _ => return None,
            };
            let signature = items[3].as_raw()?;
            let invite_bdf = match &invite {
                Some((t, s)) => Bdf::List(vec![Bdf::Int(*t as i64), Bdf::Raw(s.clone())]),
                None => Bdf::Null,
            };
            let to_sign = crate::bdf::to_bytes(&Bdf::List(vec![
                Bdf::Raw(group.to_vec()),
                Bdf::Int(timestamp as i64),
                member.to_bdf(),
                invite_bdf,
            ]));
            if !crypto::verify_signature(signature, SIGNING_LABEL_JOIN, &to_sign, &member.public_key)
            {
                return None;
            }
            Some(GroupMessage::Join { member, invite })
        }
        POST => {
            if items.len() != 6 {
                return None;
            }
            let member = Author::from_bdf(&items[1])?;
            let parent = match &items[2] {
                Bdf::Null => None,
                other => Some(raw32(other)?),
            };
            let previous = raw32(&items[3])?;
            let text = items[4].as_str()?.to_string();
            // So streng wie Briars Pruefer (GroupMessageValidator.validatePost:
            // 1 bis MAX_GROUP_POST_TEXT_LENGTH). Und nicht aus Formtreue: wir
            // reichen Beitraege unveraendert an die anderen Mitglieder weiter
            // -- ein zu langer Beitrag von einem alten Geraet ginge sonst
            // ueber uns hinaus und risse dort die Verbindung ab.
            if text.is_empty() || text.len() > crate::sync::MAX_GROUP_POST_TEXT_LEN {
                return None;
            }
            let signature = items[5].as_raw()?;
            let parent_bdf = match parent {
                Some(id) => Bdf::Raw(id.to_vec()),
                None => Bdf::Null,
            };
            let to_sign = crate::bdf::to_bytes(&Bdf::List(vec![
                Bdf::Raw(group.to_vec()),
                Bdf::Int(timestamp as i64),
                member.to_bdf(),
                parent_bdf,
                Bdf::Raw(previous.to_vec()),
                Bdf::Str(text.clone()),
            ]));
            if !crypto::verify_signature(signature, SIGNING_LABEL_POST, &to_sign, &member.public_key)
            {
                return None;
            }
            Some(GroupMessage::Post {
                member,
                parent,
                previous,
                text,
            })
        }
        _ => None,
    }
}

/// The group the invitation travels in: one per pair of contacts.
pub fn invite_group_id(author_a: &SecretKey, author_b: &SecretKey) -> SecretKey {
    ids::contact_group_id(INVITE_CLIENT_ID, INVITE_MAJOR_VERSION, author_a, author_b)
}

/// What the creator signs so the member can prove it was invited.
pub fn invite_signature(
    creator_seed: &SecretKey,
    creator_author_id: &SecretKey,
    member_author_id: &SecretKey,
    private_group_id: &SecretKey,
    timestamp: u64,
) -> Vec<u8> {
    let contact_group = invite_group_id(creator_author_id, member_author_id);
    let token = crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(timestamp as i64),
        Bdf::Raw(contact_group.to_vec()),
        Bdf::Raw(private_group_id.to_vec()),
    ]));
    crypto::sign(SIGNING_LABEL_INVITE, &token, creator_seed)
}

pub fn verify_invite_signature(
    creator_public_key: &[u8],
    creator_author_id: &SecretKey,
    member_author_id: &SecretKey,
    private_group_id: &SecretKey,
    timestamp: u64,
    signature: &[u8],
) -> bool {
    let contact_group = invite_group_id(creator_author_id, member_author_id);
    let token = crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(timestamp as i64),
        Bdf::Raw(contact_group.to_vec()),
        Bdf::Raw(private_group_id.to_vec()),
    ]));
    crypto::verify_signature(signature, SIGNING_LABEL_INVITE, &token, creator_public_key)
}

/// JOIN, LEAVE und ABORT, genau wie Briars MessageEncoderImpl sie schreibt:
///
///   JOIN  = [1, Gruppenkennung, vorige Nachricht]
///   LEAVE = [2, Gruppenkennung, vorige Nachricht]
///   ABORT = [3, Gruppenkennung]
///
/// "vorige Nachricht" ist die letzte Nachricht, die WIR in dieser
/// Einladungsgruppe geschrieben haben, oder Null beim ersten Mal. Briar fuehrt
/// damit eine Kette je Kontaktgruppe.
///
/// Ohne JOIN teilt der Einladende die Gruppe nie: seine Sitzung wartet darauf
/// und bleibt sonst ewig im Zustand INVITED. Umgekehrt steht eine von Android
/// angelegte Gruppe bei uns auf sichtbar statt geteilt -- wir bekommen die
/// Beitraege der anderen Mitglieder nie, obwohl wir formal beigetreten sind.
pub fn einladung_join_body(group_id: &[u8], previous: Option<&[u8]>) -> Vec<u8> {
    kette_body(EINLADUNG_JOIN, group_id, previous)
}

pub fn einladung_leave_body(group_id: &[u8], previous: Option<&[u8]>) -> Vec<u8> {
    kette_body(EINLADUNG_LEAVE, group_id, previous)
}

pub fn einladung_abort_body(group_id: &[u8]) -> Vec<u8> {
    crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(EINLADUNG_ABORT),
        Bdf::Raw(group_id.to_vec()),
    ]))
}

fn kette_body(art: i64, group_id: &[u8], previous: Option<&[u8]>) -> Vec<u8> {
    crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(art),
        Bdf::Raw(group_id.to_vec()),
        match previous {
            Some(p) => Bdf::Raw(p.to_vec()),
            None => Bdf::Null,
        },
    ]))
}

/// The INVITE message, in the shape Briar's MessageEncoder writes it.
pub fn invite_body(
    creator: &Author,
    group_name: &str,
    salt: &[u8],
    text: Option<&str>,
    signature: &[u8],
) -> Vec<u8> {
    crate::bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(INVITE),
        creator.to_bdf(),
        Bdf::Str(group_name.to_string()),
        Bdf::Raw(salt.to_vec()),
        match text {
            Some(t) => Bdf::Str(t.to_string()),
            None => Bdf::Null,
        },
        Bdf::Raw(signature.to_vec()),
    ]))
}

#[derive(Clone, Debug)]
pub struct Invite {
    pub creator: Author,
    pub group_name: String,
    pub salt: Vec<u8>,
    pub text: Option<String>,
    pub signature: Vec<u8>,
}

pub fn parse_invite(body: &[u8]) -> Option<Invite> {
    let list = crate::bdf::from_bytes(body).ok()?;
    let items = list.as_list()?;
    if items.len() < 6 || items[0].as_int()? != INVITE {
        return None;
    }
    let salt = items[3].as_raw()?.to_vec();
    if salt.len() != SALT_LEN {
        return None;
    }
    Some(Invite {
        creator: Author::from_bdf(&items[1])?,
        group_name: items[2].as_str()?.to_string(),
        salt,
        text: items[4].as_str().map(|s| s.to_string()),
        signature: items[5].as_raw()?.to_vec(),
    })
}

/// Was in der Einladungsgruppe ankommen kann. Bisher wurde alles ausser
/// INVITE stillschweigend weggeworfen: net.rs rief nur `parse_invite`, und der
/// Aufrufer quittiert die Nachricht trotzdem. Damit erfuhr die Einladende nie,
/// dass zugesagt wurde, und niemand erfuhr, dass ein Mitglied gegangen ist.
#[derive(Clone, Debug)]
pub enum Einladungsnachricht {
    Invite(Invite),
    Join {
        gruppe: SecretKey,
        vorige: Option<SecretKey>,
    },
    Leave {
        gruppe: SecretKey,
        vorige: Option<SecretKey>,
    },
    Abort {
        gruppe: SecretKey,
    },
}

pub fn parse_einladung(body: &[u8]) -> Option<Einladungsnachricht> {
    let list = crate::bdf::from_bytes(body).ok()?;
    let items = list.as_list()?;
    let art = items.first()?.as_int()?;
    // Die Laengen stehen im GroupInvitationValidator: Klientenfassung 0.0 hat
    // ein Glied weniger als 0.1, das den Loeschzeitgeber traegt. Wir lesen
    // beide, denn eine Gegenstelle darf neuer sein als wir.
    if art == INVITE {
        return parse_invite(body).map(Einladungsnachricht::Invite);
    }
    if (art == EINLADUNG_JOIN || art == EINLADUNG_LEAVE)
        && (items.len() == 3 || items.len() == 4)
    {
        let gruppe = raw32(&items[1])?;
        let vorige = match &items[2] {
            Bdf::Null => None,
            other => Some(raw32(other)?),
        };
        return Some(if art == EINLADUNG_JOIN {
            Einladungsnachricht::Join { gruppe, vorige }
        } else {
            Einladungsnachricht::Leave { gruppe, vorige }
        });
    }
    if art == EINLADUNG_ABORT && items.len() == 2 {
        return Some(Einladungsnachricht::Abort {
            gruppe: raw32(&items[1])?,
        });
    }
    None
}

#[cfg(test)]
mod einladung_tests {
    use super::*;

    #[test]
    fn die_nummern_sind_briars() {
        // MessageType.java: INVITE(0), JOIN(1), LEAVE(2), ABORT(3).
        // Nicht zu verwechseln mit dem Gruppenklienten, dessen JOIN 0 ist --
        // dieselben Namen, andere Zahlen, andere Gruppe.
        assert_eq!(INVITE, 0);
        assert_eq!(EINLADUNG_JOIN, 1);
        assert_eq!(EINLADUNG_LEAVE, 2);
        assert_eq!(EINLADUNG_ABORT, 3);
        assert_eq!(JOIN, 0);
        assert_eq!(POST, 1);
    }

    #[test]
    fn join_und_leave_tragen_die_kette() {
        let gruppe = [7u8; 32];
        let vorige = [9u8; 32];
        // Beim ersten Mal gibt es keine vorige Nachricht -- dann Null, nicht
        // etwa Nullbytes.
        let erste = crate::bdf::from_bytes(&einladung_join_body(&gruppe, None)).unwrap();
        let teile = erste.as_list().unwrap();
        assert_eq!(teile[0].as_int(), Some(1));
        assert_eq!(teile[1].as_raw().unwrap(), &gruppe);
        assert!(matches!(teile[2], Bdf::Null));

        let zweite = crate::bdf::from_bytes(&einladung_leave_body(&gruppe, Some(&vorige))).unwrap();
        let teile = zweite.as_list().unwrap();
        assert_eq!(teile[0].as_int(), Some(2));
        assert_eq!(teile[2].as_raw().unwrap(), &vorige);
    }

    #[test]
    fn abort_hat_nur_die_gruppe() {
        let gruppe = [3u8; 32];
        let liste = crate::bdf::from_bytes(&einladung_abort_body(&gruppe)).unwrap();
        let teile = liste.as_list().unwrap();
        assert_eq!(teile.len(), 2, "ABORT traegt keine vorige Nachricht");
        assert_eq!(teile[0].as_int(), Some(3));
    }

    #[test]
    fn parse_einladung_liest_was_wir_schreiben() {
        let gruppe = [7u8; 32];
        let vorige = [9u8; 32];
        // JOIN ohne vorige Nachricht: Null im dritten Glied.
        match parse_einladung(&einladung_join_body(&gruppe, None)) {
            Some(Einladungsnachricht::Join { gruppe: g, vorige: v }) => {
                assert_eq!(g, gruppe);
                assert!(v.is_none());
            }
            other => panic!("kein JOIN: {:?}", other),
        }
        // LEAVE mit Kette.
        match parse_einladung(&einladung_leave_body(&gruppe, Some(&vorige))) {
            Some(Einladungsnachricht::Leave { gruppe: g, vorige: v }) => {
                assert_eq!(g, gruppe);
                assert_eq!(v, Some(vorige));
            }
            other => panic!("kein LEAVE: {:?}", other),
        }
        match parse_einladung(&einladung_abort_body(&gruppe)) {
            Some(Einladungsnachricht::Abort { gruppe: g }) => assert_eq!(g, gruppe),
            other => panic!("kein ABORT: {:?}", other),
        }
        // Zu kurz, zu lang, und die Fassung 0.1 mit Loeschzeitgeber.
        let kurz = crate::bdf::to_bytes(&Bdf::List(vec![
            Bdf::Int(EINLADUNG_JOIN),
            Bdf::Raw(gruppe.to_vec()),
        ]));
        assert!(parse_einladung(&kurz).is_none());
        let lang = crate::bdf::to_bytes(&Bdf::List(vec![
            Bdf::Int(EINLADUNG_JOIN),
            Bdf::Raw(gruppe.to_vec()),
            Bdf::Raw(vorige.to_vec()),
            Bdf::Int(60_000),
            Bdf::Int(1),
        ]));
        assert!(parse_einladung(&lang).is_none());
        let mit_zeitgeber = crate::bdf::to_bytes(&Bdf::List(vec![
            Bdf::Int(EINLADUNG_JOIN),
            Bdf::Raw(gruppe.to_vec()),
            Bdf::Raw(vorige.to_vec()),
            Bdf::Int(60_000),
        ]));
        assert!(matches!(
            parse_einladung(&mit_zeitgeber),
            Some(Einladungsnachricht::Join { .. })
        ));
    }

    #[test]
    fn zeitstempel_rueckt_vor() {
        // Geht die Uhr weit genug, gilt die Uhr.
        assert_eq!(vorgerueckt(1_000, 500), 1_000);
        // Gleichstand oder Uhr zurueck: eine Millisekunde hinter dem
        // Vorgaenger, wie Briars max(jetzt, vorher + 1).
        assert_eq!(vorgerueckt(1_000, 1_000), 1_001);
        assert_eq!(vorgerueckt(900, 1_000), 1_001);
        // Ohne Vorgaenger -- eigene Gruppe, erste Nachricht -- bleibt die Uhr.
        assert_eq!(vorgerueckt(1_000, 0), 1_000);
        // Und eine Einladung aus der Zukunft zieht das JOIN mit: genau der
        // Fall, in dem die Uhr des N9 der Jolla nachgeht.
        let einladung = 1_700_000_060_000u64;
        assert!(vorgerueckt(1_700_000_000_000, einladung) > einladung);
    }

    /// Die beiden Regeln verkettet -- der Fall, der heute selbst mit richtig
    /// gestellter Uhr bricht: das vorgerueckte JOIN liegt vor der Uhr, und ein
    /// Beitrag mit blankem now_ms() waere kleiner als das JOIN.
    #[test]
    fn beitrag_bleibt_hinter_dem_vorgeruecktem_join() {
        let jetzt = 1_700_000_000_000u64;
        let einladung = jetzt + 60_000;
        let join = vorgerueckt(jetzt, einladung);
        let beitrag = vorgerueckt(jetzt, join);
        assert!(join > einladung, "JOIN muss hinter der Einladung liegen");
        assert!(beitrag > join, "Beitrag muss hinter dem JOIN liegen");
    }
}
