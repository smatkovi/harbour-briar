//! Das Vorstellen (introduction): Ingrid stellt Anna und Bert einander vor.
//!
//! Briars drittes Verfahren, aus zwei Fremden Kontakte zu machen -- ueber
//! einen Dritten, der beide kennt. Sechs Saetze, drei Rollen. Alles hier ist
//! gegen Referenzbytes aus briar-core geprueft (vectors/, `intro_*`), nicht
//! nur nachgebaut.
//!
//! Quelle: briar-core/.../introduction/{IntroductionCryptoImpl,
//! MessageEncoderImpl, IntroductionValidator, Introducee-/IntroducerProtocolEngine}.

use std::collections::BTreeMap;

use crate::bdf::{self, Bdf};
use crate::crypto::{self, SecretKey};
use crate::groups::Author;
use crate::ids;

pub const CLIENT_ID: &str = "org.briarproject.briar.introduction";
pub const MAJOR_VERSION: u32 = 1;
pub const MINOR_VERSION: u32 = 1;

pub const LABEL_SESSION_ID: &str = "org.briarproject.briar.introduction/SESSION_ID";
pub const LABEL_MASTER_KEY: &str = "org.briarproject.briar.introduction/MASTER_KEY";
pub const LABEL_ALICE_MAC_KEY: &str = "org.briarproject.briar.introduction/ALICE_MAC_KEY";
pub const LABEL_BOB_MAC_KEY: &str = "org.briarproject.briar.introduction/BOB_MAC_KEY";
pub const LABEL_AUTH_MAC: &str = "org.briarproject.briar.introduction/AUTH_MAC";
pub const LABEL_AUTH_SIGN: &str = "org.briarproject.briar.introduction/AUTH_SIGN";
pub const LABEL_AUTH_NONCE: &str = "org.briarproject.briar.introduction/AUTH_NONCE";
pub const LABEL_ACTIVATE_MAC: &str = "org.briarproject.briar.introduction/ACTIVATE_MAC";

/// MessageType.java: REQUEST(0), ACCEPT(1), DECLINE(2), AUTH(3), ACTIVATE(4), ABORT(5).
pub const REQUEST: i64 = 0;
pub const ACCEPT: i64 = 1;
pub const DECLINE: i64 = 2;
pub const AUTH: i64 = 3;
pub const ACTIVATE: i64 = 4;
pub const ABORT: i64 = 5;

/// Adressen je Verkehrsweg, wie Briar sie im ACCEPT mitschickt:
/// Verkehrsweg -> (Schluessel -> Wert).
pub type Adressen = BTreeMap<String, BTreeMap<String, String>>;

/// Die Kontaktgruppe des Vorstell-Klienten zwischen zwei Verfassern -- wie
/// ContactGroupFactoryImpl.createContactGroup(CLIENT_ID, MAJOR_VERSION, a, b).
pub fn contact_group(a: &SecretKey, b: &SecretKey) -> SecretKey {
    ids::contact_group_id(CLIENT_ID, MAJOR_VERSION, a, b)
}

/// IntroductionCryptoImpl.isAlice: die kleinere Verfasserkennung ist Alice.
pub fn ist_alice(local: &SecretKey, remote: &SecretKey) -> bool {
    local[..] < remote[..]
}

/// IntroductionCryptoImpl.getSessionId: hash(SESSION_ID, Vorstellende, Alice, Bob).
pub fn session_id(introducer: &SecretKey, local: &SecretKey, remote: &SecretKey) -> SecretKey {
    let (alice, bob) = if ist_alice(local, remote) { (local, remote) } else { (remote, local) };
    crypto::hash(LABEL_SESSION_ID, &[&introducer[..], &alice[..], &bob[..]])
}

/// IntroductionCryptoImpl.deriveMasterKey: ein Schluesseltausch, dazu die
/// Hauptfassung als ein Byte und die beiden fluechtigen oeffentlichen
/// Schluessel in Alice-Bob-Reihenfolge.
pub fn master_key(
    our_private: &SecretKey,
    our_public: &[u8; 32],
    their_public: &[u8; 32],
    alice: bool,
) -> Option<SecretKey> {
    let (a, b) = if alice { (our_public, their_public) } else { (their_public, our_public) };
    crypto::derive_shared_secret(
        LABEL_MASTER_KEY,
        their_public,
        our_private,
        &[&[MAJOR_VERSION as u8], &a[..], &b[..]],
    )
}

/// IntroductionCryptoImpl.deriveMacKey.
pub fn mac_key(master: &SecretKey, alice: bool) -> SecretKey {
    crypto::derive_key(
        if alice { LABEL_ALICE_MAC_KEY } else { LABEL_BOB_MAC_KEY },
        master,
        &[],
    )
}

/// Was eine Seite in den AUTH-MAC einbringt.
pub struct Seite<'a> {
    pub author_id: &'a SecretKey,
    pub accept_timestamp: u64,
    pub ephemeral_public: &'a [u8; 32],
    pub adressen: &'a Adressen,
}

fn adressen_bdf(a: &Adressen) -> Bdf {
    let mut aussen = BTreeMap::new();
    for (weg, werte) in a {
        let mut innen = BTreeMap::new();
        for (k, v) in werte {
            innen.insert(k.clone(), Bdf::Str(v.clone()));
        }
        aussen.insert(weg.clone(), Bdf::Dict(innen));
    }
    Bdf::Dict(aussen)
}

fn seite_bdf(s: &Seite) -> Bdf {
    Bdf::List(vec![
        Bdf::Raw(s.author_id.to_vec()),
        Bdf::Int(s.accept_timestamp as i64),
        Bdf::Raw(s.ephemeral_public.to_vec()),
        adressen_bdf(s.adressen),
    ])
}

/// IntroductionCryptoImpl.authMac: MAC ueber [Vorstellende, eigene Seite,
/// fremde Seite] als BDF-Bytes. Zum Pruefen des fremden MACs die Seiten
/// vertauschen (verifyAuthMac tut genau das).
pub fn auth_mac(key: &SecretKey, introducer: &SecretKey, local: &Seite, remote: &Seite) -> SecretKey {
    let liste = Bdf::List(vec![
        Bdf::Raw(introducer.to_vec()),
        seite_bdf(local),
        seite_bdf(remote),
    ]);
    crypto::mac(LABEL_AUTH_MAC, key, &[&bdf::to_bytes(&liste)])
}

pub fn auth_mac_stimmt(
    mac: &[u8],
    their_key: &SecretKey,
    introducer: &SecretKey,
    local: &Seite,
    remote: &Seite,
) -> bool {
    // Die Gegenseite hat IHRE Seite als "local" eingebracht.
    auth_mac(their_key, introducer, remote, local)[..] == mac[..]
}

/// IntroductionCryptoImpl.getNonce / sign.
pub fn auth_nonce(key: &SecretKey) -> SecretKey {
    crypto::mac(LABEL_AUTH_NONCE, key, &[])
}

pub fn auth_signature(key: &SecretKey, signature_seed: &SecretKey) -> Vec<u8> {
    crypto::sign(LABEL_AUTH_SIGN, &auth_nonce(key), signature_seed)
}

pub fn auth_signature_stimmt(sig: &[u8], their_key: &SecretKey, their_signature_public: &[u8]) -> bool {
    crypto::verify_signature(sig, LABEL_AUTH_SIGN, &auth_nonce(their_key), their_signature_public)
}

/// IntroductionCryptoImpl.activateMac.
pub fn activate_mac(key: &SecretKey) -> SecretKey {
    crypto::mac(LABEL_ACTIVATE_MAC, key, &[])
}

fn opt_raw(v: Option<&SecretKey>) -> Bdf {
    match v {
        Some(k) => Bdf::Raw(k.to_vec()),
        None => Bdf::Null,
    }
}

/// MessageEncoderImpl.encodeRequestMessage: [0, vorige?, Verfasser, Text?, Zuenddauer?].
pub fn request_body(previous: Option<&SecretKey>, author: &Author, text: Option<&str>, timer: Option<i64>) -> Vec<u8> {
    let mut l = vec![
        Bdf::Int(REQUEST),
        opt_raw(previous),
        author.to_bdf(),
        match text { Some(t) => Bdf::Str(t.to_string()), None => Bdf::Null },
    ];
    if let Some(t) = timer { l.push(Bdf::Int(t)); }
    bdf::to_bytes(&Bdf::List(l))
}

/// encodeAcceptMessage: [1, Sitzung, vorige?, fluechtiger Schluessel, Annahmezeit, Adressen, Zuenddauer?].
pub fn accept_body(
    session: &SecretKey,
    previous: Option<&SecretKey>,
    ephemeral_public: &[u8; 32],
    accept_timestamp: u64,
    adressen: &Adressen,
    timer: Option<i64>,
) -> Vec<u8> {
    let mut l = vec![
        Bdf::Int(ACCEPT),
        Bdf::Raw(session.to_vec()),
        opt_raw(previous),
        Bdf::Raw(ephemeral_public.to_vec()),
        Bdf::Int(accept_timestamp as i64),
        adressen_bdf(adressen),
    ];
    if let Some(t) = timer { l.push(Bdf::Int(t)); }
    bdf::to_bytes(&Bdf::List(l))
}

/// encodeDeclineMessage: [2, Sitzung, vorige?, Zuenddauer?].
pub fn decline_body(session: &SecretKey, previous: Option<&SecretKey>, timer: Option<i64>) -> Vec<u8> {
    let mut l = vec![Bdf::Int(DECLINE), Bdf::Raw(session.to_vec()), opt_raw(previous)];
    if let Some(t) = timer { l.push(Bdf::Int(t)); }
    bdf::to_bytes(&Bdf::List(l))
}

/// encodeAuthMessage: [3, Sitzung, vorige, MAC, Unterschrift].
pub fn auth_body(session: &SecretKey, previous: &SecretKey, mac: &[u8], signature: &[u8]) -> Vec<u8> {
    bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(AUTH),
        Bdf::Raw(session.to_vec()),
        Bdf::Raw(previous.to_vec()),
        Bdf::Raw(mac.to_vec()),
        Bdf::Raw(signature.to_vec()),
    ]))
}

/// encodeActivateMessage: [4, Sitzung, vorige, MAC].
pub fn activate_body(session: &SecretKey, previous: &SecretKey, mac: &[u8]) -> Vec<u8> {
    bdf::to_bytes(&Bdf::List(vec![
        Bdf::Int(ACTIVATE),
        Bdf::Raw(session.to_vec()),
        Bdf::Raw(previous.to_vec()),
        Bdf::Raw(mac.to_vec()),
    ]))
}

/// encodeAbortMessage: [5, Sitzung, vorige?].
pub fn abort_body(session: &SecretKey, previous: Option<&SecretKey>) -> Vec<u8> {
    bdf::to_bytes(&Bdf::List(vec![Bdf::Int(ABORT), Bdf::Raw(session.to_vec()), opt_raw(previous)]))
}
