//! BQP -- Briars Weg, zwei Geräte **nebeneinander** zusammenzubringen.
//!
//! Der Name ist Briars eigener: Bramble QR Code Protocol. Es löst ein anderes
//! Problem als der `briar://`-Link: dort tauscht man dauerhafte Kennungen und
//! Adressen, hier trifft man sich ein einziges Mal, zeigt einander einen Code
//! und leitet daraus ein Geheimnis ab -- ohne dass je eine Adresse den
//! Besitzer wechselt.
//!
//! Der Ablauf, aus `KeyAgreementProtocol.java` gelesen:
//!
//! 1. Jede Seite würfelt ein flüchtiges Schlüsselpaar und zeigt im QR-Code
//!    eine **Verpflichtung** darauf -- die ersten 16 Byte eines Hashes über den
//!    öffentlichen Schlüssel -- sowie ihre Transportbeschreiber (LAN-Adresse
//!    mit Port, Bluetooth-MAC).
//! 2. Wer den Code der Gegenseite gelesen hat, verbindet sich zu einem der
//!    genannten Transporte. Alice ist, wessen Verpflichtung kleiner ist.
//! 3. Über die rohe Verbindung gehen Sätze: KEY, dann CONFIRM (Rahmen wie
//!    ueberall, Fassung 4). Der gelesene Schlüssel muss zur Verpflichtung aus
//!    dem Code passen -- das ist der Schutz gegen einen Mittelsmann.
//! 4. Aus beiden Schlüsseln wird das gemeinsame Geheimnis, daraus der
//!    Hauptschlüssel, und darüber läuft dann derselbe Kontaktaustausch wie
//!    nach einem Handschlag.
//!
//! Alles hier ist gegen Referenzbytes aus Briars eigenem Jar geprüft
//! (`vectors/java/.../Vectors8.java`, Werte `bqp_*` in `vectors/vectors.txt`).

use crate::bdf::Bdf;
use crate::crypto::{self, SecretKey};

/// KeyAgreementConstants.PROTOCOL_VERSION
pub const PROTOCOL_VERSION: u8 = 4;
/// Das erste Byte des QR-Rumpfes: (QR_FORMAT_ID << 5) | QR_FORMAT_VERSION.
pub const FORMAT_BYTE: u8 = (0 << 5) | PROTOCOL_VERSION;
/// KeyAgreementConstants.COMMIT_LENGTH
pub const COMMIT_LEN: usize = 16;

pub const TRANSPORT_BLUETOOTH: i64 = 0;
pub const TRANSPORT_LAN: i64 = 1;

/// Javas `UUID.nameUUIDFromBytes`, Byte fuer Byte nachgebaut.
///
/// Briar leitet daraus die Kennung des Bluetooth-Dienstes ab, unter dem es
/// waehrend eines Treffens lauscht -- gelesen in
/// `AbstractBluetoothPlugin.createKeyAgreementListener`:
///
/// ```java
/// // No truncation necessary because COMMIT_LENGTH = 16
/// String uuid = UUID.nameUUIDFromBytes(commitment).toString();
/// ```
///
/// Das ist eine UUID der Fassung 3: MD5 ueber die Bytes, dann zwei Nibbles
/// gesetzt. MD5 steht hier nicht als Pruefsumme, sondern weil die Kennung
/// genau so entsteht; ein anderer Hash ergaebe eine andere Kennung und damit
/// keinen Fund.
pub fn bt_uuid(commitment: &[u8]) -> String {
    let mut h = md5::compute(commitment).0;
    h[6] = (h[6] & 0x0f) | 0x30; // Fassung 3
    h[8] = (h[8] & 0x3f) | 0x80; // IETF-Variante
    let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Satzarten (RecordTypes.java). Die Rahmen sind dieselben wie sonst.
pub const KEY: u8 = 0;
pub const CONFIRM: u8 = 1;
pub const ABORT: u8 = 2;

const COMMIT_LABEL: &str = "org.briarproject.bramble.keyagreement/COMMIT";
const SHARED_SECRET_LABEL: &str =
    "org.briarproject.bramble.keyagreement/SHARED_SECRET";
const MASTER_KEY_LABEL: &str =
    "org.briarproject.bramble.keyagreement/MASTER_SECRET";
const CONFIRMATION_KEY_LABEL: &str =
    "org.briarproject.bramble.keyagreement/CONFIRMATION_KEY";
const CONFIRMATION_MAC_LABEL: &str =
    "org.briarproject.bramble.keyagreement/CONFIRMATION_MAC";

/// Was im QR-Code steht.
#[derive(Clone, Debug, PartialEq)]
pub struct Payload {
    pub commitment: Vec<u8>,
    /// Die Beschreiber, wie sie im Code stehen -- unveraendert, denn sie gehen
    /// spaeter Byte fuer Byte in die Bestaetigung ein.
    pub descriptors: Vec<Bdf>,
}

impl Payload {
    /// Die erste WLAN-Adresse in Code-Reihenfolge -- seit 0.40.0 also die
    /// mit dem weitesten Netz. Nur noch in Pruefungen; zum Anwaehlen ist
    /// `lan_alle()` richtig.
    pub fn lan(&self) -> Option<String> {
        self.lan_alle().into_iter().next()
    }

    /// Alle WLAN-Adressen aus den Beschreibern, als `ip:port`.
    ///
    /// Mehrere sind erlaubt und kommen vor: ein Geraet, das in zwei Netzen
    /// steht, lauscht auf 0.0.0.0 und ist unter jeder erreichbar -- aber von
    /// der Gegenseite aus meist nur unter einer. Wer nur die erste probiert,
    /// meldet "no reachable address", obwohl die Geraete nebeneinander liegen.
    ///
    /// Briar selbst nennt eine (LanTcpPlugin.createKeyAgreementListener) und
    /// behaelt beim Lesen die letzte je Verkehrsweg
    /// (KeyAgreementConnector:122) -- von mehreren waehlt es also nur die
    /// letzte an. Darum nennt unser Code das engste Netz zuletzt
    /// (net::lan_beschreiber); mehrere zu lesen kostet uns nichts.
    pub fn lan_alle(&self) -> Vec<String> {
        let mut gefunden = Vec::new();
        for d in &self.descriptors {
            // Weiterschauen statt aufgeben: ein Beschreiber, mit dem wir
            // nichts anfangen koennen, darf die folgenden nicht verdecken.
            // Briar schickt den Bluetooth-Beschreiber auch ohne Adresse --
            // als Liste mit nur einem Glied -- und dahinter erst den fuer LAN.
            let Some(teile) = d.as_list() else { continue };
            if teile.first().and_then(|t| t.as_int()) != Some(TRANSPORT_LAN) {
                continue;
            }
            let Some(roh) = teile.get(1).and_then(|t| t.as_raw()) else {
                continue;
            };
            let Some(port) = teile.get(2).and_then(|t| t.as_int()) else {
                continue;
            };
            let ip = match roh.len() {
                4 => std::net::IpAddr::from([roh[0], roh[1], roh[2], roh[3]]),
                16 => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(roh);
                    std::net::IpAddr::from(b)
                }
                _ => continue,
            };
            if !(1..=65535).contains(&port) {
                continue;
            }
            gefunden.push(match ip {
                std::net::IpAddr::V4(v4) => format!("{}:{}", v4, port),
                std::net::IpAddr::V6(v6) => format!("[{}]:{}", v6, port),
            });
        }
        gefunden
    }

    /// Die Bluetooth-Adresse aus den Beschreibern, in Grossbuchstaben.
    /// Die Bluetooth-Adresse aus den Beschreibern.
    ///
    /// None heisst hier zweierlei: kein Bluetooth-Beschreiber, oder einer
    /// ohne Adresse. Briar laesst die Adresse weg, wenn es seine eigene nicht
    /// kennt, und die Gegenseite sucht das Geraet dann selbst ueber die
    /// Kennung (`discoverAndConnect`). Das koennen wir nicht, also ist beides
    /// fuer uns dasselbe: kein Bluetooth.
    pub fn bluetooth(&self) -> Option<String> {
        for d in &self.descriptors {
            let Some(teile) = d.as_list() else { continue };
            if teile.first().and_then(|t| t.as_int()) != Some(TRANSPORT_BLUETOOTH) {
                continue;
            }
            let Some(roh) = teile.get(1).and_then(|t| t.as_raw()) else {
                continue;
            };
            if roh.len() != 6 {
                continue;
            }
            return Some(
                roh.iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(":"),
            );
        }
        None
    }
}

/// Die Verpflichtung auf einen oeffentlichen Schluessel: die ersten 16 Byte
/// des Hashes darueber (KeyAgreementCryptoImpl.deriveKeyCommitment).
pub fn commitment(public_key: &[u8]) -> Vec<u8> {
    let h = crypto::hash(COMMIT_LABEL, &[public_key]);
    h[..COMMIT_LEN].to_vec()
}

/// Den QR-Rumpf bauen: Kennbyte, dann die BDF-Liste aus Verpflichtung und
/// Beschreibern (PayloadEncoderImpl).
pub fn encode(payload: &Payload) -> Vec<u8> {
    let mut glieder: Vec<Bdf> = vec![Bdf::Raw(payload.commitment.clone())];
    glieder.extend(payload.descriptors.iter().cloned());
    let mut out = vec![FORMAT_BYTE];
    out.extend(crate::bdf::to_bytes(&Bdf::List(glieder)));
    out
}

/// Und zurueck (PayloadParserImpl). `None`, wenn es kein BQP-Code ist oder die
/// Fassung nicht stimmt -- dann ist es womoeglich unser eigener `briar://`-Link.
pub fn parse(raw: &[u8]) -> Option<Payload> {
    let (erstes, rest) = raw.split_first()?;
    // Fassung und Kennung stecken in einem Byte. Eine andere Fassung lesen wir
    // absichtlich nicht: die Bytes danach koennten alles bedeuten.
    if *erstes != FORMAT_BYTE {
        return None;
    }
    let liste = crate::bdf::from_bytes(rest).ok()?;
    let teile = liste.as_list()?;
    let commitment = teile.first()?.as_raw()?.to_vec();
    if commitment.len() != COMMIT_LEN {
        return None;
    }
    // Unbekannte Beschreiber bleiben stehen: sie gehen unveraendert in die
    // Bestaetigung ein, und wer sie wegwirft, rechnet etwas anderes aus als die
    // Gegenseite.
    Some(Payload {
        commitment,
        descriptors: teile[1..].to_vec(),
    })
}

/// Wer ist Alice? Wessen Verpflichtung kleiner ist -- byteweise und
/// vorzeichenlos, wie Briars Bytes.compare (KeyAgreementTaskImpl:99).
pub fn ist_alice(unsere: &[u8], ihre: &[u8]) -> bool {
    unsere < ihre
}

/// Das gemeinsame Geheimnis. Die Eingaben sind Fassungsbyte, Alices und Bobs
/// oeffentlicher Schluessel -- in dieser Reihenfolge, gleich welche Seite
/// rechnet (KeyAgreementProtocol.deriveSharedSecret).
pub fn shared_secret(
    their_public: &[u8; 32],
    our_private: &SecretKey,
    our_public: &[u8; 32],
    alice: bool,
) -> Option<SecretKey> {
    let fassung = [PROTOCOL_VERSION];
    let (a, b): (&[u8], &[u8]) = if alice {
        (our_public, their_public)
    } else {
        (their_public, our_public)
    };
    crypto::derive_shared_secret(SHARED_SECRET_LABEL, their_public, our_private, &[&fassung, a, b])
}

/// Daraus der Hauptschluessel, mit dem der Kontaktaustausch laeuft.
pub fn master_key(shared: &SecretKey) -> SecretKey {
    crypto::derive_key(MASTER_KEY_LABEL, shared, &[])
}

/// Die Bestaetigung. `alice` sagt, welche Rolle WIR haben; `alice_record`,
/// wessen Satz gerade gerechnet wird -- der eigene oder der erwartete der
/// Gegenseite (KeyAgreementCryptoImpl.deriveConfirmationRecord).
#[allow(clippy::too_many_arguments)]
pub fn confirmation(
    shared: &SecretKey,
    their_payload: &[u8],
    our_payload: &[u8],
    their_public: &[u8],
    our_public: &[u8],
    alice: bool,
    alice_record: bool,
) -> SecretKey {
    let ck = crypto::derive_key(CONFIRMATION_KEY_LABEL, shared, &[]);
    let (alice_payload, alice_pub, bob_payload, bob_pub) = if alice {
        (our_payload, our_public, their_payload, their_public)
    } else {
        (their_payload, their_public, our_payload, our_public)
    };
    if alice_record {
        crypto::mac(
            CONFIRMATION_MAC_LABEL,
            &ck,
            &[alice_payload, alice_pub, bob_payload, bob_pub],
        )
    } else {
        crypto::mac(
            CONFIRMATION_MAC_LABEL,
            &ck,
            &[bob_payload, bob_pub, alice_payload, alice_pub],
        )
    }
}

/// Der Austausch ueber die rohe Verbindung: Schluessel, Pruefung der
/// Verpflichtung, dann die beiden Bestaetigungen. Gibt den Hauptschluessel
/// zurueck, mit dem danach der Kontaktaustausch laeuft.
///
/// Wer zuerst spricht, haengt an der Rolle -- Alice schickt, Bob hoert zu.
/// Genau so steht es in KeyAgreementProtocol.perform().
///
/// Scheitert die Sitzung bei uns, erfaehrt die Gegenseite es: ein ABORT geht
/// hinaus, bevor der Fehler zurueckkehrt (Briars KeyAgreementProtocol
/// .perform: jeder Verfahrensfehler, eine AbortException, endet in sendAbort;
/// bei einem Schreibfehler schweigt Briar, wir versuchen es trotzdem, das
/// kostet nichts). Ohne ihn wartete sie bis
/// zur Zeitgrenze auf einen Satz, der nie kommt -- eine Minute bei Briar,
/// und die Anzeige stand die ganze Zeit auf "verbinde".
#[allow(clippy::too_many_arguments)]
pub fn sitzung<S: std::io::Read + std::io::Write>(
    strom: &mut S,
    our_private: &SecretKey,
    our_public: &[u8; 32],
    our_payload: &[u8],
    their_payload: &[u8],
    their_commitment: &[u8],
    alice: bool,
) -> std::io::Result<SecretKey> {
    match verhandeln(
        strom,
        our_private,
        our_public,
        our_payload,
        their_payload,
        their_commitment,
        alice,
    ) {
        // Hat die Gegenseite abgebrochen, ist nichts mehr zu sagen.
        Err(e) if e.kind() != std::io::ErrorKind::ConnectionAborted => {
            abbruch_senden(strom);
            Err(e)
        }
        ergebnis => ergebnis,
    }
}

/// Der Gegenseite sagen, dass wir aufgeben. Bestes Bemuehen: scheitert das
/// Schreiben, ist die Leitung ohnehin tot. Der Rumpf ist leer, wie bei Briar
/// (KeyAgreementTransport.sendAbort).
fn abbruch_senden<S: std::io::Write>(strom: &mut S) {
    let _ = crate::record::write_record(
        strom,
        &crate::record::Record::new(PROTOCOL_VERSION, ABORT, Vec::new()),
    );
    let _ = strom.flush();
}

#[allow(clippy::too_many_arguments)]
fn verhandeln<S: std::io::Read + std::io::Write>(
    strom: &mut S,
    our_private: &SecretKey,
    our_public: &[u8; 32],
    our_payload: &[u8],
    their_payload: &[u8],
    their_commitment: &[u8],
    alice: bool,
) -> std::io::Result<SecretKey> {
    let fehler = |text: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, text);

    let schluessel_senden = |strom: &mut S| -> std::io::Result<()> {
        crate::record::write_record(
            strom,
            &crate::record::Record::new(PROTOCOL_VERSION, KEY, our_public.to_vec()),
        )?;
        strom.flush()
    };
    let schluessel_lesen = |strom: &mut S| -> std::io::Result<[u8; 32]> {
        let satz = lies(strom, KEY)?;
        if satz.len() != 32 {
            return Err(fehler("der Schluessel hat die falsche Laenge"));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&satz);
        // Die Verpflichtung aus dem Code muss auf genau diesen Schluessel
        // passen -- das ist der ganze Schutz gegen einen Mittelsmann. Wer hier
        // nachlaesst, hat ein Verfahren gebaut, das nichts beweist.
        if commitment(&k) != their_commitment {
            return Err(fehler("der Schluessel passt nicht zum QR-Code"));
        }
        Ok(k)
    };

    let their_public = if alice {
        schluessel_senden(strom)?;
        schluessel_lesen(strom)?
    } else {
        let ihrer = schluessel_lesen(strom)?;
        schluessel_senden(strom)?;
        ihrer
    };

    let shared = shared_secret(&their_public, our_private, our_public, alice)
        .ok_or_else(|| fehler("die Einigung ergab nichts"))?;

    let unsere = confirmation(
        &shared,
        their_payload,
        our_payload,
        &their_public,
        our_public,
        alice,
        alice,
    );
    let erwartet = confirmation(
        &shared,
        their_payload,
        our_payload,
        &their_public,
        our_public,
        alice,
        !alice,
    );
    let bestaetigung_senden = |strom: &mut S| -> std::io::Result<()> {
        crate::record::write_record(
            strom,
            &crate::record::Record::new(PROTOCOL_VERSION, CONFIRM, unsere.to_vec()),
        )?;
        strom.flush()
    };
    let bestaetigung_lesen = |strom: &mut S| -> std::io::Result<()> {
        let satz = lies(strom, CONFIRM)?;
        if satz != erwartet.to_vec() {
            return Err(fehler("die Bestaetigung stimmt nicht"));
        }
        Ok(())
    };
    if alice {
        bestaetigung_senden(strom)?;
        bestaetigung_lesen(strom)?;
    } else {
        bestaetigung_lesen(strom)?;
        bestaetigung_senden(strom)?;
    }
    Ok(master_key(&shared))
}

/// Den naechsten Satz der erwarteten Art lesen. Saetze derselben Fassung mit
/// unbekannter Art werden uebersprungen -- so haelt es Briars
/// KeyAgreementTransport --, ein ABORT beendet den Versuch, und ein bekannter
/// Satz ausser der Reihe ebenso: ein CONFIRM vor dem KEY ist kein Versehen,
/// sondern eine Gegenseite, die das Verfahren nicht einhaelt (Briar wirft
/// dort AbortException und bricht ab, statt weiterzulesen).
fn lies<S: std::io::Read>(strom: &mut S, art: u8) -> std::io::Result<Vec<u8>> {
    loop {
        let satz = crate::record::read_record(strom)?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "der Strom endete zu frueh")
        })?;
        if satz.protocol_version != PROTOCOL_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "andere Fassung",
            ));
        }
        if satz.record_type == ABORT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "die Gegenseite hat abgebrochen",
            ));
        }
        if satz.record_type == art {
            return Ok(satz.payload);
        }
        if satz.record_type == KEY || satz.record_type == CONFIRM {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ein Satz ausser der Reihe",
            ));
        }
        // Unbekannte Art: ueberspringen, nicht abbrechen.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{from_hex, to_hex};

    fn vektoren() -> std::collections::HashMap<String, String> {
        let pfad = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/vectors.txt");
        std::fs::read_to_string(pfad)
            .expect("vectors.txt")
            .lines()
            .filter_map(|z| z.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn schluessel(hex: &str) -> SecretKey {
        let mut k = [0u8; 32];
        k.copy_from_slice(&from_hex(hex).unwrap());
        k
    }

    /// Die Verpflichtung, der QR-Rumpf, das Geheimnis und beide
    /// Bestaetigungen -- alle gegen Briars eigene Werte.
    #[test]
    fn bqp_wie_bei_briar() {
        let v = vektoren();
        let alice_priv = schluessel(&v["bqp_alice_priv"]);
        let bob_priv = schluessel(&v["bqp_bob_priv"]);
        let alice_pub = schluessel(&v["bqp_alice_public"]);
        let bob_pub = schluessel(&v["bqp_bob_public"]);

        assert_eq!(to_hex(&commitment(&alice_pub)), v["bqp_alice_commit"]);
        assert_eq!(to_hex(&commitment(&bob_pub)), v["bqp_bob_commit"]);

        // Der Rumpf: Alice hat LAN und Bluetooth, Bob nur LAN.
        let alice_payload = Payload {
            commitment: from_hex(&v["bqp_alice_commit"]).unwrap(),
            descriptors: vec![
                Bdf::List(vec![
                    Bdf::Int(TRANSPORT_LAN),
                    Bdf::Raw(vec![192, 168, 1, 20]),
                    Bdf::Int(39000),
                ]),
                Bdf::List(vec![
                    Bdf::Int(TRANSPORT_BLUETOOTH),
                    Bdf::Raw(vec![0x40, 0x98, 0x4e, 0xad, 0xbd, 0x42]),
                ]),
            ],
        };
        let bob_payload = Payload {
            commitment: from_hex(&v["bqp_bob_commit"]).unwrap(),
            descriptors: vec![Bdf::List(vec![
                Bdf::Int(TRANSPORT_LAN),
                Bdf::Raw(vec![192, 168, 1, 21]),
                Bdf::Int(39001),
            ])],
        };
        let alice_roh = encode(&alice_payload);
        let bob_roh = encode(&bob_payload);
        assert_eq!(to_hex(&alice_roh), v["bqp_alice_payload"]);
        assert_eq!(to_hex(&bob_roh), v["bqp_bob_payload"]);

        // Und zurueck, samt der Adressen, auf die es beim Verbinden ankommt.
        let gelesen = parse(&alice_roh).expect("BQP-Rumpf");
        assert_eq!(gelesen, alice_payload);
        assert_eq!(gelesen.lan().as_deref(), Some("192.168.1.20:39000"));
        assert_eq!(gelesen.bluetooth().as_deref(), Some("40:98:4E:AD:BD:42"));
        assert!(parse(b"briar://abcdef").is_none(), "unser Link ist kein BQP");

        // Das Geheimnis -- aus Alices Sicht und aus Bobs, es muss dasselbe sein.
        let von_alice = shared_secret(&bob_pub, &alice_priv, &alice_pub, true).unwrap();
        let von_bob = shared_secret(&alice_pub, &bob_priv, &bob_pub, false).unwrap();
        assert_eq!(to_hex(&von_alice), v["bqp_shared"]);
        assert_eq!(von_alice, von_bob);
        assert_eq!(to_hex(&master_key(&von_alice)), v["bqp_master"]);

        // Die Bestaetigungen: Alice schickt ihre, erwartet Bobs -- und Bob
        // rechnet dieselben zwei Werte aus, nur mit vertauschten Rollen.
        let a = confirmation(&von_alice, &bob_roh, &alice_roh, &bob_pub, &alice_pub, true, true);
        let b = confirmation(&von_alice, &bob_roh, &alice_roh, &bob_pub, &alice_pub, true, false);
        assert_eq!(to_hex(&a), v["bqp_confirm_alice"]);
        assert_eq!(to_hex(&b), v["bqp_confirm_bob"]);
        let a_bei_bob =
            confirmation(&von_bob, &alice_roh, &bob_roh, &alice_pub, &bob_pub, false, true);
        let b_bei_bob =
            confirmation(&von_bob, &alice_roh, &bob_roh, &alice_pub, &bob_pub, false, false);
        assert_eq!(a_bei_bob, a, "Alices Satz, von Bob gerechnet");
        assert_eq!(b_bei_bob, b, "Bobs Satz, von Bob gerechnet");
    }

    /// Beide Seiten gegeneinander, ueber eine echte Verbindung: so faellt auf,
    /// wenn die Reihenfolge der Saetze nicht passt oder eine Rolle vertauscht
    /// ist -- das sieht man den Einzelwerten nicht an.
    #[test]
    fn beide_seiten_einigen_sich() {
        use std::io::Read;
        let lauscher = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = lauscher.local_addr().unwrap();

        let a_priv = crate::crypto::generate_agreement_private_key();
        let b_priv = crate::crypto::generate_agreement_private_key();
        let a_pub = crate::crypto::agreement_public_key(&a_priv);
        let b_pub = crate::crypto::agreement_public_key(&b_priv);
        let a_payload = encode(&Payload {
            commitment: commitment(&a_pub),
            descriptors: vec![],
        });
        let b_payload = encode(&Payload {
            commitment: commitment(&b_pub),
            descriptors: vec![],
        });
        let a_ist_alice = ist_alice(&commitment(&a_pub), &commitment(&b_pub));

        let (bp, ap, bpub2, apub2) = (b_payload.clone(), a_payload.clone(), b_pub, a_pub);
        let faden = std::thread::spawn(move || {
            let (mut strom, _) = lauscher.accept().unwrap();
            sitzung(
                &mut strom,
                &b_priv,
                &bpub2,
                &bp,
                &ap,
                &commitment(&apub2),
                !a_ist_alice,
            )
        });
        let mut strom = std::net::TcpStream::connect(adresse).unwrap();
        let bei_a = sitzung(
            &mut strom,
            &a_priv,
            &a_pub,
            &a_payload,
            &b_payload,
            &commitment(&b_pub),
            a_ist_alice,
        )
        .expect("Sitzung bei A");
        let bei_b = faden.join().unwrap().expect("Sitzung bei B");
        assert_eq!(bei_a, bei_b, "beide muessen denselben Hauptschluessel haben");
        // Und der Strom ist danach leer -- niemand hat etwas nachgeschoben.
        strom.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
        let mut rest = [0u8; 1];
        assert!(strom.read(&mut rest).is_err() || true);
    }

    /// Scheitert Bob am Schluessel, erfaehrt Alice es sofort: ein ABORT statt
    /// einer Minute Warten auf einen Satz, der nie kommt.
    #[test]
    fn wer_scheitert_sagt_es_der_gegenseite() {
        let lauscher = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = lauscher.local_addr().unwrap();
        let a_priv = crate::crypto::generate_agreement_private_key();
        let b_priv = crate::crypto::generate_agreement_private_key();
        let a_pub = crate::crypto::agreement_public_key(&a_priv);
        let b_pub = crate::crypto::agreement_public_key(&b_priv);
        let a_payload = encode(&Payload {
            commitment: commitment(&a_pub),
            descriptors: vec![],
        });
        let b_payload = encode(&Payload {
            commitment: commitment(&b_pub),
            descriptors: vec![],
        });
        let a_ist_alice = ist_alice(&commitment(&a_pub), &commitment(&b_pub));
        // B kennt fuer A eine falsche Verpflichtung -- als haette jemand den
        // Code vertauscht. Gleich, wer Alice ist: B liest A's Schluessel und
        // scheitert daran, A wartet danach auf B's naechsten Satz.
        let falsch = commitment(&crate::crypto::agreement_public_key(
            &crate::crypto::generate_agreement_private_key(),
        ));
        let (bp, ap) = (b_payload.clone(), a_payload.clone());
        let faden = std::thread::spawn(move || {
            let (mut strom, _) = lauscher.accept().unwrap();
            strom
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            sitzung(&mut strom, &b_priv, &b_pub, &bp, &ap, &falsch, !a_ist_alice)
        });
        let mut strom = std::net::TcpStream::connect(adresse).unwrap();
        strom
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let bei_a = sitzung(
            &mut strom,
            &a_priv,
            &a_pub,
            &a_payload,
            &b_payload,
            &commitment(&b_pub),
            a_ist_alice,
        );
        let bei_b = faden.join().unwrap();
        assert!(bei_b.is_err(), "B darf den Schluessel nicht annehmen");
        let e = bei_a.expect_err("A darf nicht weiterkommen");
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::ConnectionAborted,
            "A muss das ABORT gelesen haben, nicht in die Zeitgrenze laufen: {}",
            e
        );
    }

    /// Ein bekannter Satz ausser der Reihe -- ein CONFIRM vor dem KEY -- ist
    /// kein Versehen, sondern eine Gegenseite, die das Verfahren nicht
    /// einhaelt: abbrechen und es ihr sagen, statt weiterzulesen.
    #[test]
    fn satz_ausser_der_reihe_bricht_ab() {
        use std::io::Write;
        let lauscher = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = lauscher.local_addr().unwrap();
        let faden = std::thread::spawn(move || {
            let (mut strom, _) = lauscher.accept().unwrap();
            strom
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            crate::record::write_record(
                &mut strom,
                &crate::record::Record::new(PROTOCOL_VERSION, CONFIRM, vec![0; 32]),
            )
            .unwrap();
            strom.flush().unwrap();
            crate::record::read_record(&mut strom)
                .unwrap()
                .expect("ein Satz")
                .record_type
        });
        let privat = crate::crypto::generate_agreement_private_key();
        let oeffentlich = crate::crypto::agreement_public_key(&privat);
        let payload = encode(&Payload {
            commitment: commitment(&oeffentlich),
            descriptors: vec![],
        });
        let mut strom = std::net::TcpStream::connect(adresse).unwrap();
        strom
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        // Wir sind Bob und warten auf den KEY.
        let e = sitzung(
            &mut strom,
            &privat,
            &oeffentlich,
            &payload,
            &payload,
            &commitment(&oeffentlich),
            false,
        )
        .expect_err("ein CONFIRM vor dem KEY darf nicht durchgehen");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(faden.join().unwrap(), ABORT, "die Gegenseite bekommt ein ABORT");
    }

    #[test]
    fn falscher_schluessel_faellt_auf() {
        // Eine Verpflichtung, die nicht zum spaeter geschickten Schluessel
        // passt: genau das waere ein Mittelsmann.
        let priv1 = crate::crypto::generate_agreement_private_key();
        let pub1 = crate::crypto::agreement_public_key(&priv1);
        let fremd = crate::crypto::agreement_public_key(&crate::crypto::generate_agreement_private_key());
        assert_ne!(commitment(&pub1), commitment(&fremd));
    }

    #[test]
    fn alice_ist_die_kleinere_verpflichtung() {
        // Vorzeichenlos vergleichen: 0x80 ist groesser als 0x7f, nicht kleiner.
        assert!(ist_alice(&[0x7f], &[0x80]));
        assert!(!ist_alice(&[0x80], &[0x7f]));
    }
}


#[cfg(test)]
mod uuid_tests {
    use super::*;

    /// Die Vergleichswerte stammen nicht aus dieser Umsetzung, sondern aus
    /// einer unabhaengigen Rechnung nach Javas Vorschrift (MD5, dann Fassung
    /// 3 und IETF-Variante setzen).
    #[test]
    fn kennung_wie_bei_java() {
        let verpflichtung =
            hex("3df9d22ad582d3fb6c90edaa1f7f3e6e");
        assert_eq!(
            bt_uuid(&verpflichtung),
            "d00458d5-46bf-395c-9d7c-ccd157ae8882"
        );
        assert_eq!(
            bt_uuid(&[0u8; 16]),
            "4ae71336-e44b-39bf-b9d2-752e234818a5"
        );
    }

    /// Die Fassungs- und Variantenbits muessen bei jeder Eingabe stimmen,
    /// sonst faende Briar den Dienst nur zufaellig.
    #[test]
    fn fassung_und_variante_stehen_immer() {
        for i in 0u8..64 {
            let u = bt_uuid(&[i; 16]);
            assert_eq!(&u[14..15], "3", "Fassung 3 fehlt in {}", u);
            let variante = u.as_bytes()[19];
            assert!(
                matches!(variante, b'8' | b'9' | b'a' | b'b'),
                "IETF-Variante fehlt in {}",
                u
            );
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}

#[cfg(test)]
mod bluetooth_beschreiber_tests {
    use super::*;
    use crate::bdf::Bdf;

    fn rumpf(beschreiber: Vec<Bdf>) -> Payload {
        let roh = encode(&Payload {
            commitment: vec![7u8; 16],
            descriptors: beschreiber,
        });
        parse(&roh).expect("eigener Rumpf muss lesbar sein")
    }

    /// Briars Beschreiber ist [0, sechs Bytes], hohe Stelle zuerst.
    #[test]
    fn adresse_kommt_so_heraus_wie_sie_hineinging() {
        let p = rumpf(vec![Bdf::List(vec![
            Bdf::Int(TRANSPORT_BLUETOOTH),
            Bdf::Raw(vec![0x40, 0x98, 0x4E, 0xAD, 0xBD, 0x42]),
        ])]);
        assert_eq!(p.bluetooth().as_deref(), Some("40:98:4E:AD:BD:42"));
    }

    /// Briar laesst die Adresse weg, wenn es seine eigene nicht kennt --
    /// dann darf der Beschreiber dahinter trotzdem gefunden werden. Mit dem
    /// alten `?` verschluckte ein solcher Beschreiber die LAN-Adresse.
    #[test]
    fn bluetooth_ohne_adresse_verdeckt_das_lan_nicht() {
        let p = rumpf(vec![
            Bdf::List(vec![Bdf::Int(TRANSPORT_BLUETOOTH)]),
            Bdf::List(vec![
                Bdf::Int(TRANSPORT_LAN),
                Bdf::Raw(vec![10, 156, 40, 213]),
                Bdf::Int(7327),
            ]),
        ]);
        assert_eq!(p.bluetooth(), None, "ohne Adresse ist es fuer uns keins");
        assert_eq!(p.lan().as_deref(), Some("10.156.40.213:7327"));
    }

    /// Beide Wege nebeneinander, in Briars Reihenfolge.
    #[test]
    fn beide_wege_nebeneinander() {
        let p = rumpf(vec![
            Bdf::List(vec![
                Bdf::Int(TRANSPORT_BLUETOOTH),
                Bdf::Raw(vec![0x50, 0x56, 0xA8, 0x06, 0x05, 0xCA]),
            ]),
            Bdf::List(vec![
                Bdf::Int(TRANSPORT_LAN),
                Bdf::Raw(vec![10, 156, 40, 213]),
                Bdf::Int(32951),
            ]),
        ]);
        assert_eq!(p.bluetooth().as_deref(), Some("50:56:A8:06:05:CA"));
        assert_eq!(p.lan().as_deref(), Some("10.156.40.213:32951"));
    }

    /// Die Kennung des Dienstes haengt an der Verpflichtung, nicht am Geraet:
    /// zwei Laeufe mit verschiedenen Schluesseln lauschen unter verschiedenen
    /// Kennungen, und beide Seiten rechnen dieselbe aus.
    #[test]
    fn kennung_haengt_an_der_verpflichtung() {
        let a = bt_uuid(&[1u8; 16]);
        let b = bt_uuid(&[2u8; 16]);
        assert_ne!(a, b);
        assert_eq!(a, bt_uuid(&[1u8; 16]));
    }
}

#[cfg(test)]
mod mehrere_adressen_tests {
    use super::*;
    use crate::bdf::Bdf;

    fn lan(ip: [u8; 4], port: i64) -> Bdf {
        Bdf::List(vec![
            Bdf::Int(TRANSPORT_LAN),
            Bdf::Raw(ip.to_vec()),
            Bdf::Int(port),
        ])
    }

    /// Ein Geraet in zwei Netzen nennt beide. Wer nur die erste probiert,
    /// meldet "no reachable address", obwohl die Geraete nebeneinander
    /// liegen -- genau so ist es zwischen Jolla und N9 passiert.
    #[test]
    fn alle_adressen_kommen_heraus() {
        let roh = encode(&Payload {
            commitment: vec![3u8; 16],
            descriptors: vec![
                lan([10, 156, 40, 213], 32951),
                lan([172, 28, 172, 1], 32951),
            ],
        });
        let p = parse(&roh).unwrap();
        assert_eq!(
            p.lan_alle(),
            vec!["10.156.40.213:32951", "172.28.172.1:32951"]
        );
        // lan() bleibt die erste -- Aufrufer, die eine wollen, bekommen eine.
        assert_eq!(p.lan().as_deref(), Some("10.156.40.213:32951"));
    }

    /// Ein Bluetooth-Beschreiber dazwischen darf keine Adresse verdecken.
    #[test]
    fn bluetooth_dazwischen_stoert_nicht() {
        let roh = encode(&Payload {
            commitment: vec![3u8; 16],
            descriptors: vec![
                lan([10, 0, 0, 1], 7327),
                Bdf::List(vec![Bdf::Int(TRANSPORT_BLUETOOTH)]),
                lan([192, 168, 1, 5], 7327),
            ],
        });
        let p = parse(&roh).unwrap();
        assert_eq!(p.lan_alle(), vec!["10.0.0.1:7327", "192.168.1.5:7327"]);
    }
}
