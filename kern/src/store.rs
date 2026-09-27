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
    /// Nur noch fuer alte Dateien da: bis 0.24.0 stand hier EIN Zaehler,
    /// der ewig wuchs. Beim Laden wandert er in `out_streams` unter den
    /// gerade laufenden Zeitabschnitt, damit in diesem Abschnitt keine
    /// Stromnummer zweimal vergeben wird.
    #[serde(default)]
    pub out_stream: u64,
    /// Die ausgehende Stromnummer **je Zeitabschnitt**, wie bei Briar: dort
    /// erzeugt jede Schluesseldrehung neue OutgoingKeys ueber den
    /// Vierargumenten-Erbauer, und der setzt streamCounter auf 0
    /// (OutgoingKeys.java:20-23). Ein ewig wachsender Zaehler laeuft nach
    /// dem ersten Abschnittswechsel aus dem Fenster der Gegenseite heraus --
    /// und zwar dauerhaft, weil er nur steigt.
    #[serde(default)]
    pub out_streams: BTreeMap<String, u64>,
    /// Next expected incoming stream number, per time period
    pub in_stream: BTreeMap<String, u64>,
    /// Der Lauschport, den die Gegenseite gemeldet hat. Briar wuerfelt ihn
    /// beim ersten Start aus 32768..65535 und behaelt ihn -- eine feste
    /// Nummer gibt es dort nicht. Ohne diesen Wert laesst sich weder eine
    /// gelernte Absenderadresse vervollstaendigen noch eine Hotspot-Adresse
    /// raten.
    #[serde(default)]
    pub port: Option<u16>,
    /// Fassung der zuletzt uebernommenen Eigenschaftsmeldung. Briar laesst
    /// strikt die hoehere gewinnen; ohne das kann eine verspaetet
    /// eintreffende alte Meldung eine neuere ueberschreiben.
    #[serde(default)]
    pub props_version: u64,
    /// Die link-lokalen IPv6-Adressen der Gegenseite, wie Briar sie meldet:
    /// je 32 Hexzeichen der 16 Adressbytes, durch Komma getrennt, **ohne**
    /// Port -- der kommt aus `port`. Der Zonenindex fehlt darin absichtlich;
    /// ihn bestimmt die waehlende Seite aus ihren eigenen Schnittstellen.
    #[serde(default)]
    pub ipv6: Option<String>,
    /// Die Bluetooth-UUID der Gegenseite. Briar meldet sie als Eigenschaft
    /// `uuid`; ohne sie findet man seinen RFCOMM-Kanal nicht, denn er ist
    /// nicht fest.
    #[serde(default)]
    pub bt_uuid: Option<String>,
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
    /// Zustand je Transport. Gebraucht wird davon nur das Stromwerk:
    /// `out_streams` (die naechste ausgehende Nummer je Zeitabschnitt) und
    /// `in_stream` (der Fusspunkt unseres Fensters je Zeitabschnitt). Briar
    /// fuehrt fuer einen schwebenden Kontakt denselben Schluesselsatz wie
    /// fuer einen Kontakt, nur im Handschlagmodus, und zaehlt ueber denselben
    /// Pfad hoch -- TransportKeyManagerImpl.java:366-385 nimmt ContactId
    /// oder PendingContactId, einen Sonderweg fuer den Handschlag gibt es
    /// dort nicht. Je Transport ein Eintrag, denn LAN, Bluetooth und Tor
    /// haben eigene Schluessel und darum eigene Marken. Die uebrigen Felder
    /// bleiben hier leer: die Adressen eines Wartenden stehen oben, einzeln.
    #[serde(default)]
    pub transports: BTreeMap<String, TransportState>,
}

impl PendingContact {
    pub fn transport(&self, id: &str) -> Option<&TransportState> {
        self.transports.get(id)
    }

    pub fn transport_mut(&mut self, id: &str) -> &mut TransportState {
        self.transports.entry(id.to_string()).or_default()
    }
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
    /// Haushaltskram: Adressmeldung und Versionsansage. Sie liegen im selben
    /// Korb wie eine Privatnachricht, sind aber nichts, was der Benutzer
    /// geschrieben hat -- der Zaehler in der Kontaktliste darf sie nicht als
    /// "noch nicht gesendet" ausweisen.
    #[serde(default)]
    pub intern: bool,
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
    /// Kennungen, die die Gegenseite angeboten hat und die wir noch nicht
    /// haben. Sie gehen zu Beginn der naechsten Runde als REQUEST hinaus.
    #[serde(default)]
    pub to_request: Vec<String>,
    pub last_seen: u64,
    /// Fingerabdruck der zuletzt IN DEN KORB GELEGTEN Klientenliste -- nicht
    /// der zuletzt angekommenen. Was angekommen ist, sagt allein der Korb:
    /// solange die Ansage dort unquittiert liegt, geht sie jede Runde wieder
    /// hinaus. Aendert sich die Liste, wird die alte Ansage verworfen und eine
    /// neue mit hoeherer Nummer eingereiht.
    #[serde(default)]
    pub versioning_sent: String,
    /// Die Nummer der Ansage. Briar laesst die hoehere gewinnen und verwirft
    /// eine mit kleinerer (ClientVersioningManagerImpl), also muss sie
    /// steigen.
    #[serde(default)]
    pub versioning_version: u64,
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

/// Der Zustand der Einladungssitzung mit EINEM Kontakt, eingekocht auf die
/// Zustaende, die hier wirklich gelesen werden. Briars CreatorState und
/// InviteeState unterscheiden mehr, weil dort die Sichtbarkeit der Gruppe am
/// Zustand haengt; wir teilen die Gruppe schon beim Einladen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum Sitzungszustand {
    /// Nichts offen. Briars CreatorState.START -- auch der Zustand nach einer
    /// Ablehnung, danach ist neu einladen erlaubt. Ebenso der Zustand einer
    /// noch unbeantworteten Einladung an uns: dass sie offen ist, sagt schon
    /// `joined == false` mit `invited_by`.
    #[default]
    Start,
    /// Wir haben eingeladen und warten (CreatorState.INVITED). Gelesen von
    /// /group/invite: ein zweites Mal einladen ist ein Zustandsfehler.
    Eingeladen,
    /// Beide sind drin (CreatorState.JOINED).
    Beigetreten,
    /// Der Kontakt ist gegangen, wir sind noch drin (CreatorState.LEFT). Neu
    /// einladen waere falsch: seine Beitrittsnachricht steht noch in der
    /// Gruppe, eine zweite wuerde seine Kette gabeln.
    Gegangen,
    /// Ein ABORT ist geflogen. Wir antworten genau einmal darauf -- ohne
    /// diesen Zustand schicken sich zwei Geraete endlos ABORTs zu.
    Fehler,
}

/// Was zuletzt in der Einladungsgruppe geschah. Nur die Art und der Name --
/// die Worte macht die Oberflaeche, sonst stuende deutsche Schrift im Dienst
/// und die Sprachumschaltung griffe hier nicht.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ereignis {
    pub art: Ereignisart,
    pub wer: String,
    pub wann: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum Ereignisart {
    Angenommen,
    Abgelehnt,
    Gegangen,
    Aufgeloest,
    Abgebrochen,
}

/// Eine Einladungssitzung, so wie Briar sie fuehrt: eine je KONTAKT und
/// Gruppe. GroupInvitationManagerImpl sucht sie mit
/// getSession(Kontaktgruppe, sessionId = Gruppenkennung) -- deshalb reicht ein
/// Feld an der Gruppe nicht: die Kette zu Kontakt A und die zu Kontakt B sind
/// zwei Ketten, und wer sie vermischt, nennt eine vorige Nachricht, die es in
/// der anderen Kontaktgruppe nie gab.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Einladungssitzung {
    /// Unsere letzte Nachricht in DIESER Sitzung -- Briars
    /// lastLocalMessageId. JOIN und LEAVE tragen sie als drittes Listenglied.
    #[serde(default)]
    pub letzte_eigene: Option<String>,
    /// Die letzte Nachricht, die von der Gegenseite kam --
    /// lastRemoteMessageId. Briar prueft damit deren Kette
    /// (AbstractProtocolEngine.isValidDependency); wir merken sie, um eine
    /// doppelt gelieferte Nachricht zu erkennen und um sie melden zu koennen.
    #[serde(default)]
    pub letzte_fremde: Option<String>,
    /// Zeitstempel unserer letzten eigenen Nachricht und der Einladung. Briar
    /// setzt jeden neuen auf max(jetzt, groesserer + 1); eine Nachricht mit
    /// kleinerem Stempel bricht die Sitzung der Gegenseite ab.
    #[serde(default)]
    pub eigener_zeitstempel: u64,
    #[serde(default)]
    pub einladungs_zeitstempel: u64,
    /// Wie weit die Sitzung ist. Dasselbe JOIN heisst "hat angenommen" oder
    /// "kommt zurueck", je nachdem, was vorher war.
    #[serde(default)]
    pub zustand: Sitzungszustand,
}

impl Einladungssitzung {
    /// Briars getTimestampForInvisibleMessage: nie kleiner oder gleich dem,
    /// was in dieser Sitzung schon gesendet oder als Einladung empfangen
    /// wurde. Auf N9 und N950 laeuft die Uhr ohne Zeitdienst, da traegt
    /// now_ms() allein nicht.
    pub fn naechster_zeitstempel(&self) -> u64 {
        let untergrenze = self.eigener_zeitstempel.max(self.einladungs_zeitstempel);
        crate::util::now_ms().max(untergrenze.saturating_add(1))
    }
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
    /// Je Kontakt eine Einladungssitzung, Schluessel ist die Kontaktnummer.
    /// Bis Fassung 0.26 stand hier ein einziges `einladung_previous` fuer die
    /// ganze Gruppe. Damit trugen die LEAVE an zwei Kontakte dieselbe vorige
    /// Nachricht, und eines von beiden nennt eine Nachricht, die in jener
    /// Kontaktgruppe nie vorkam -- Briar haelt es dann fuer immer zurueck.
    #[serde(default)]
    pub einladungen: BTreeMap<u32, Einladungssitzung>,
    /// Nur noch zum Lesen alter Dateien. Beim Oeffnen wandert der Inhalt in
    /// `einladungen` (Speicherfassung 3) und wird nicht mehr geschrieben.
    #[serde(default, skip_serializing)]
    pub einladung_previous: Option<String>,
    /// Der Ersteller ist gegangen -- Briars markGroupDissolved. Die Gruppe
    /// bleibt lesbar und entfernbar, aber es geht nichts mehr hinaus, und eine
    /// offene Einladung ist nicht mehr annehmbar.
    #[serde(default)]
    pub aufgeloest: bool,
    /// Die letzte Antwort der Gegenseite, fuer die Oberflaeche. Briar zeigt so
    /// etwas als Zeile im Gespraech; wir haben dort keine Zeile und sagen es an
    /// der Gruppe. Wird beim Oeffnen der Gruppe geleert (/read).
    #[serde(default)]
    pub letztes_ereignis: Option<Ereignis>,
    /// Contacts this group is synced with
    #[serde(default)]
    pub contacts: Vec<u32>,
}

impl PrivateGroup {
    /// Der Zeitstempel unserer letzten eigenen Nachricht -- der, auf den
    /// `our_previous` zeigt. Der naechste Beitrag muss echt darueber liegen,
    /// sonst wirft Briar ihn beim Zustellen weg.
    ///
    /// Fehlt der Eintrag, nehmen wir den spaetesten Zeitstempel der Gruppe:
    /// zu weit vorgeruecken schadet nichts, zu wenig kostet die Nachricht.
    pub fn vorgaenger_zeit(&self) -> u64 {
        if let Some(id) = &self.our_previous {
            if let Some(m) = self.messages.iter().find(|m| &m.id == id) {
                return m.timestamp;
            }
        }
        self.messages.iter().map(|m| m.timestamp).max().unwrap_or(0)
    }
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
    /// Die zuletzt benutzten eigenen LAN-Adressen, neueste zuerst -- Briars
    /// PREF_LAN_IP_PORTS. Sie ueberlebt Neustart und Netzwechsel: kommt man
    /// heim, steht die Heimadresse noch drin und passt wieder.
    #[serde(default)]
    pub lan_recent: Vec<String>,
    /// Was davon zuletzt an die Kontakte ging -- Briars PROP_IP_PORTS. Getrennt
    /// gefuehrt, damit ein blosses Umsortieren zwischen zwei bekannten Netzen
    /// keine Eigenschaftsmeldung an alle Kontakte ausloest.
    #[serde(default)]
    pub lan_published: String,
    /// Dasselbe Gedaechtnis fuer die eigenen link-lokalen IPv6-Adressen.
    #[serde(default)]
    pub lan6_recent: Vec<String>,
    /// Unsere Bluetooth-UUID. Einmal gewuerfelt und dann behalten: die
    /// Kontakte merken sie sich, und eine neue waere fuer sie ein neues
    /// Geraet.
    #[serde(default)]
    pub bt_uuid: Option<String>,
    #[serde(default)]
    pub pending: Vec<PendingContact>,
    #[serde(default)]
    pub contacts: Vec<Contact>,
    #[serde(default)]
    pub groups: Vec<PrivateGroup>,
    /// Die Einladungssitzungen entfernter Gruppen, nach Gruppenkennung. Briar
    /// behaelt eine Sitzung, wenn eine Einladung abgelehnt wird -- der Zustand
    /// geht auf START, und die Kette laeuft weiter (CreatorProtocolEngine
    /// onRemoteDecline). Bei uns lebt die Sitzung an der Gruppe, und die Gruppe
    /// zu entfernen IST die Ablehnung: ohne dieses Gedaechtnis nennt unser
    /// spaeteres JOIN nach einer neuen Einladung keine vorige Nachricht, und
    /// Briar bricht die Sitzung ab, statt die Gruppe zu teilen.
    #[serde(default)]
    pub verlassene_einladungen: BTreeMap<String, BTreeMap<u32, Einladungssitzung>>,
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
const STATE_VERSION: u32 = 3;

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
    /// Das Siegel: der ausgepackte Speicherschluessel und seine Verpackung.
    /// Ist es None, liegt der Speicher wie frueher im Klartext.
    ///
    /// Hier lag frueher das Passwort, und `save()` leitete daraus bei jedem
    /// Aufruf mit scrypt neu ab -- 16 MB und ein bis drei Sekunden, je
    /// Abgleichsrunde und je Nachricht, und das alles unter dem Schloss des
    /// Speichers. Briar leitet zweimal ab (Konto oeffnen, Passwort wechseln)
    /// und haelt danach den Schluessel. Genau das tut das Siegel; das
    /// Passwort selbst wird gar nicht mehr aufbewahrt.
    siegel: Option<crate::tresor::Siegel>,
}

impl Store {
    /// Ein Passwort setzen, aendern oder -- mit leerer Zeichenkette --
    /// aufheben.
    ///
    /// Ist schon eines gesetzt, muss das alte stimmen. Das ist keine
    /// Foermlichkeit: sonst koennte jeder, der kurz an das entsperrte Geraet
    /// kommt, das Passwort aendern und den Besitzer aussperren. Briar prueft
    /// es an derselben Stelle, indem es den Speicherschluessel mit dem alten
    /// Passwort auspackt.
    pub fn passwort_setzen(&mut self, alt: Option<&str>, neu: &str) -> std::io::Result<()> {
        // Geprueft wird jetzt am Paket und nicht an einer gemerkten
        // Zeichenkette: das Passwort steht nirgends mehr, und der Vergleich
        // kostet einen scrypt-Lauf -- hier ist er richtig aufgehoben.
        if let Some(siegel) = &self.siegel {
            let stimmt = alt.map(|a| siegel.stimmt(a)).unwrap_or(false);
            if !stimmt {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "das alte Passwort stimmt nicht",
                ));
            }
        }
        let fehler = |e: String| std::io::Error::new(std::io::ErrorKind::Other, e);
        self.siegel = if neu.is_empty() {
            None
        } else {
            // Beim Wechsel wandert der Speicherschluessel mit, sonst waere
            // jede alte Sicherung unlesbar; ohne Siegel wird einer geboren.
            Some(match &self.siegel {
                Some(altes) => altes.neu_verpacken(neu).map_err(fehler)?,
                None => crate::tresor::Siegel::frisch(neu).map_err(fehler)?,
            })
        };
        self.save()
    }

    /// Liegt der Speicher gerade verschluesselt vor?
    pub fn verschluesselt(&self) -> bool {
        self.siegel.is_some()
    }
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
    /// Oeffnet den Speicher. Ist er verschluesselt, braucht es das Passwort --
    /// dann `open_mit_passwort`.
    pub fn open(path: &Path, default_port: u16) -> std::io::Result<Store> {
        Self::open_intern(path, default_port, None)
    }

    /// Wie `open`, mit Passwort fuer einen verschluesselten Speicher. Ist die
    /// Datei noch Klartext, wird sie beim naechsten Speichern umgestellt.
    pub fn open_mit_passwort(
        path: &Path,
        default_port: u16,
        passwort: &str,
    ) -> std::io::Result<Store> {
        Self::open_intern(path, default_port, Some(passwort.to_string()))
    }

    /// Ist die Datei an diesem Ort verschluesselt? Der Dienst fragt das beim
    /// Start, um zu wissen, ob er auf ein Passwort warten muss.
    pub fn ist_verschluesselt(path: &Path) -> bool {
        match std::fs::read(path) {
            Ok(rohdaten) => crate::tresor::ist_verschluesselt(&rohdaten),
            Err(_) => false,
        }
    }

    fn open_intern(
        path: &Path,
        default_port: u16,
        passwort: Option<String>,
    ) -> std::io::Result<Store> {
        // Das Siegel aus der Datei, falls sie verschluesselt war: hier laeuft
        // der eine scrypt-Lauf, den es braucht.
        let mut gefundenes_siegel: Option<crate::tresor::Siegel> = None;
        let state = if path.exists() {
            let rohdaten = std::fs::read(path)?;
            let text = if crate::tresor::ist_verschluesselt(&rohdaten) {
                let pw = passwort.as_deref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "der Speicher ist verschluesselt, es fehlt das Passwort",
                    )
                })?;
                let (klartext, siegel) = crate::tresor::Siegel::oeffnen(&rohdaten, pw)
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied, e))?;
                gefundenes_siegel = Some(siegel);
                String::from_utf8(klartext).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "entschluesselter Speicher ist kein Text",
                    )
                })?
            } else {
                String::from_utf8(rohdaten).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Speicher ist weder Text noch verschluesselt",
                    )
                })?
            };
            // Nicht mehr unwrap_or_default(): eine beschaedigte Datei fiel
            // damit still auf einen leeren Zustand zurueck, und der naechste
            // save() schrieb ihn darueber. Ein Lesefehler kostete alles --
            // Kontakte, Schluessel, Nachrichten. Jetzt bricht das Oeffnen ab
            // und die Datei bleibt, wie sie ist.
            serde_json::from_str(&text).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Speicher nicht lesbar ({}) -- Datei bleibt unangetastet", e),
                )
            })?
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
            // Ein Passwort ohne verschluesselte Datei heisst: der Speicher
            // wird beim naechsten Schreiben umgestellt -- dafuer ein frisches
            // Siegel, das ist der eine erlaubte zweite scrypt-Lauf.
            siegel: match (gefundenes_siegel, passwort.as_deref()) {
                (Some(siegel), _) => Some(siegel),
                (None, Some(pw)) if !pw.is_empty() => Some(
                    crate::tresor::Siegel::frisch(pw).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })?,
                ),
                _ => None,
            },
        };
        // Einmal wuerfeln und behalten -- eine neue UUID waere fuer die
        // Kontakte ein neues Geraet.
        if store.state.bt_uuid.is_none() {
            store.state.bt_uuid = Some(crate::bt::random_uuid());
        }
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
        // Fassung 2 fuehrte die Kette der Einladungsgruppe je Gruppe statt je
        // (Kontakt, Gruppe). Was dort steht, kann nur aus der Sitzung mit dem
        // Einladenden stammen: geschrieben wurde das Feld ausschliesslich auf
        // dem Weg /group/join. Alles andere faengt bei Null an -- eine falsche
        // vorige Nachricht ist schlimmer als keine, denn Briar wartet auf sie.
        if store.state.state_version < 3 {
            // Haushaltspost, die schon im Korb liegt, als solche kennzeichnen:
            // Adressmeldung und Versionsansage sollen nicht als "noch nicht
            // gesendet" am Kontakt stehen. Ohne diesen Schritt bliebe bei jedem
            // bestehenden Kontakt eine Zahl neben dem Namen, die niemand
            // wegbekommt, bis die Meldung quittiert ist.
            let eigene = store
                .state
                .identity
                .as_ref()
                .map(|i| key_from_hex(&i.author_id));
            if let Some(eigene) = eigene {
                for contact in store.state.contacts.iter_mut() {
                    let ihre = key_from_hex(&contact.author_id);
                    let haushalt = [
                        to_hex(&crate::sync::properties_group_id(&eigene, &ihre)),
                        to_hex(&crate::sync::versioning_group_id(&eigene, &ihre)),
                    ];
                    for post in contact.outbox.iter_mut() {
                        if haushalt.contains(&post.group) {
                            post.intern = true;
                        }
                    }
                }
            }
            for group in store.state.groups.iter_mut() {
                let vorige = group.einladung_previous.take();
                if let (Some(kontakt), Some(vorige)) = (group.invited_by, vorige) {
                    let stempel = group.invite_timestamp.unwrap_or(0);
                    let beigetreten = group.joined;
                    let sitzung = group.einladungen.entry(kontakt).or_default();
                    sitzung.letzte_eigene = Some(vorige);
                    sitzung.einladungs_zeitstempel = stempel;
                    sitzung.eigener_zeitstempel = stempel;
                    sitzung.zustand = if beigetreten {
                        Sitzungszustand::Beigetreten
                    } else {
                        Sitzungszustand::Start
                    };
                }
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
            set_mode(dir, 0o700);
        }
        let text = serde_json::to_string_pretty(&self.state)?;
        // Mit Passwort verschluesselt, ohne wie bisher als Klartext. Die
        // Umstellung passiert damit beim ersten Speichern nach dem Setzen
        // eines Passworts, ohne eigenen Wanderungsschritt.
        let inhalt: Vec<u8> = match &self.siegel {
            Some(siegel) => siegel.verschluesseln(text.as_bytes()),
            None => text.into_bytes(),
        };
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, inhalt)?;
        // Nur der Eigentuemer. In dieser Datei stehen der private
        // Handschlagschluessel, der Signatursamen, je Kontakt der
        // gemeinsame Hauptschluessel, der Onion-Schluessel und alle
        // Nachrichten -- sie stand bisher auf 0644, also fuer jeden lesbar.
        // Gesetzt wird es an der temporaeren Datei, bevor sie an ihren Platz
        // rueckt: sonst gibt es einen Augenblick, in dem sie offen liegt.
        set_mode(&tmp, 0o600);
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

    pub fn sitzung(&self, group: &str, contact_id: u32) -> Option<&Einladungssitzung> {
        self.group(group).and_then(|g| g.einladungen.get(&contact_id))
    }

    /// Legt die Sitzung bei Bedarf an -- aber nur fuer eine Gruppe, die es
    /// wirklich gibt. Fuer eine unbekannte Gruppe darf nichts entstehen.
    pub fn sitzung_mut(
        &mut self,
        group: &str,
        contact_id: u32,
    ) -> Option<&mut Einladungssitzung> {
        self.group_mut(group)
            .map(|g| g.einladungen.entry(contact_id).or_default())
    }

    /// Nimmt einem Kontakt alles wieder aus der Warteschlange, was zu DIESER
    /// Gruppe gehoert. Briar macht die Gruppe fuer ihn unsichtbar, dann geht
    /// nichts mehr hinaus; bei uns ist die Warteschlange der einzige Ort, an
    /// dem Ausstehendes liegt. `group_hex` ist die Kennung der Gruppe selbst,
    /// nicht die der Einladungsgruppe -- sonst flogen unser eigenes LEAVE und
    /// ABORT mit hinaus, bevor sie abgeschickt sind.
    pub fn verwerfe_gruppenpost(&mut self, contact_id: u32, group_hex: &str) {
        if let Some(contact) = self.contact_mut(contact_id) {
            contact.outbox.retain(|m| m.group != group_hex);
        }
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

/// Rechte setzen, ohne dass ein Fehlschlag das Speichern verhindert -- auf
/// einem Dateisystem ohne Unix-Rechte ist es eben nicht zu haben.
fn set_mode(pfad: &std::path::Path, modus: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(pfad, std::fs::Permissions::from_mode(modus));
}

#[cfg(test)]
mod gruppen_tests {
    use super::*;

    fn beitrag(id: &str, zeit: u64) -> GroupPost {
        GroupPost {
            id: id.to_string(),
            author_id: "aa".to_string(),
            author_name: "ich".to_string(),
            timestamp: zeit,
            text: "hallo".to_string(),
            body: String::new(),
            join: false,
        }
    }

    fn gruppe(vorher: Option<&str>, posts: Vec<GroupPost>) -> PrivateGroup {
        PrivateGroup {
            id: "11".to_string(),
            name: "Testgruppe".to_string(),
            salt: "22".to_string(),
            creator_name: "wer".to_string(),
            creator_public: "33".to_string(),
            creator_author_id: "44".to_string(),
            joined: true,
            invited_by: None,
            invite_timestamp: None,
            invite_signature: None,
            member_names: BTreeMap::new(),
            last_read: 0,
            messages: posts,
            our_previous: vorher.map(|v| v.to_string()),
            einladungen: BTreeMap::new(),
            einladung_previous: None,
            aufgeloest: false,
            letztes_ereignis: None,
            contacts: Vec::new(),
        }
    }

    #[test]
    fn vorgaenger_zeit_nimmt_die_eigene_letzte() {
        let g = gruppe(Some("b"), vec![beitrag("a", 500), beitrag("b", 900)]);
        assert_eq!(g.vorgaenger_zeit(), 900);
    }

    #[test]
    fn fehlt_der_eintrag_gilt_der_spaeteste() {
        // Kann nicht vorkommen, solange beides zusammen gesetzt wird -- aber
        // zu weit vorruecken schadet nichts, zu wenig kostet die Nachricht.
        let g = gruppe(Some("weg"), vec![beitrag("a", 500), beitrag("b", 900)]);
        assert_eq!(g.vorgaenger_zeit(), 900);
    }

    #[test]
    fn ohne_nachrichten_null() {
        let g = gruppe(None, Vec::new());
        assert_eq!(g.vorgaenger_zeit(), 0);
    }
}

#[cfg(test)]
mod wanderung_tests {
    use super::*;

    /// Eine Gruppe von Hand, ohne Datei und ohne Netz.
    fn leere_gruppe() -> PrivateGroup {
        PrivateGroup {
            id: to_hex(&[1u8; 32]),
            name: "Testgruppe".to_string(),
            salt: "22".to_string(),
            creator_name: "wer".to_string(),
            creator_public: "33".to_string(),
            creator_author_id: "44".to_string(),
            joined: true,
            invited_by: None,
            invite_timestamp: None,
            invite_signature: None,
            member_names: BTreeMap::new(),
            last_read: 0,
            messages: Vec::new(),
            our_previous: None,
            einladungen: BTreeMap::new(),
            einladung_previous: None,
            aufgeloest: false,
            letztes_ereignis: None,
            contacts: Vec::new(),
        }
    }

    fn pfad(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-wanderung-test-{}.json", name));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Eine Datei der Fassung 2 kennt nur `einladung_previous` an der Gruppe.
    /// Beim Oeffnen muss daraus die Sitzung mit dem Einladenden werden, sonst
    /// nennt das naechste LEAVE keine vorige Nachricht mehr -- und Briar
    /// wartet dann auf eine, die nie kommt.
    #[test]
    fn alte_kette_wandert_in_die_sitzung() {
        let p = pfad("kette");
        let alt = r#"{
            "identity": null,
            "listen_port": 7327,
            "state_version": 2,
            "groups": [{
                "id": "aa11",
                "name": "Alte Gruppe",
                "salt": "bb22",
                "creator_name": "wer",
                "creator_public": "cc33",
                "creator_author_id": "dd44",
                "joined": true,
                "invited_by": 3,
                "invite_timestamp": 1000,
                "invite_signature": null,
                "our_previous": null,
                "einladung_previous": "ab12"
            }]
        }"#;
        std::fs::write(&p, alt).unwrap();
        let store = Store::open(&p, 7327).unwrap();
        let sitzung = store.sitzung("aa11", 3).expect("Sitzung mit dem Einladenden");
        assert_eq!(sitzung.letzte_eigene.as_deref(), Some("ab12"));
        assert_eq!(sitzung.einladungs_zeitstempel, 1000);
        assert_eq!(sitzung.eigener_zeitstempel, 1000);
        // Das alte Feld wird nicht mehr geschrieben.
        let roh = std::fs::read_to_string(&p).unwrap();
        assert!(!roh.contains("einladung_previous"), "{}", roh);
        assert!(
            roh.replace(' ', "").contains("\"state_version\":3"),
            "{}",
            roh
        );
        let _ = std::fs::remove_file(&p);
    }

    /// Zwei Kontakte, zwei Ketten: die beiden LEAVE duerfen nicht dieselbe
    /// vorige Nachricht nennen. Genau das tat die Fassung bis 0.26 -- sie
    /// fuehrte ein Feld fuer alle, und fuer einen der beiden nannte es eine
    /// Nachricht, die in seiner Kontaktgruppe nie vorkam.
    ///
    /// Geprueft wird der Weg, den /group/remove geht: Kette aus DER Sitzung
    /// holen, Rumpf daraus bauen.
    #[test]
    fn zwei_sitzungen_zwei_ketten() {
        let aa = to_hex(&[0xaau8; 32]);
        let bb = to_hex(&[0xbbu8; 32]);
        let mut g = leere_gruppe();
        g.einladungen.insert(
            7,
            Einladungssitzung {
                letzte_eigene: Some(aa.clone()),
                letzte_fremde: None,
                eigener_zeitstempel: 100,
                einladungs_zeitstempel: 100,
                zustand: Sitzungszustand::Beigetreten,
            },
        );
        g.einladungen.insert(
            9,
            Einladungssitzung {
                letzte_eigene: Some(bb.clone()),
                letzte_fremde: None,
                eigener_zeitstempel: 200,
                einladungs_zeitstempel: 100,
                zustand: Sitzungszustand::Beigetreten,
            },
        );

        // Was /group/remove je Kontakt nachschlaegt und in den Rumpf legt.
        let kette = |kontakt: u32| -> Vec<u8> {
            let vorige = g
                .einladungen
                .get(&kontakt)
                .and_then(|s| s.letzte_eigene.clone());
            crate::groups::einladung_leave_body(
                &key_from_hex(&g.id),
                vorige.as_deref().and_then(from_hex).as_deref(),
            )
        };
        let rumpf_7 = kette(7);
        let rumpf_9 = kette(9);
        assert_ne!(rumpf_7, rumpf_9, "zwei Sitzungen, zwei vorige Nachrichten");

        // Und jeder Rumpf nennt genau die Nachricht SEINER Sitzung.
        let genannt = |rumpf: &[u8]| match crate::groups::parse_einladung(rumpf) {
            Some(crate::groups::Einladungsnachricht::Leave { vorige, .. }) => {
                vorige.map(|v| to_hex(&v))
            }
            other => panic!("kein LEAVE: {:?}", other),
        };
        assert_eq!(genannt(&rumpf_7), Some(aa));
        assert_eq!(genannt(&rumpf_9), Some(bb));
    }

    /// Steht die Uhr hinter der Einladung, muss der naechste Zeitstempel
    /// trotzdem darueber liegen -- N9 und N950 laufen ohne Zeitdienst.
    #[test]
    fn zeitstempel_steigt_auch_bei_stehender_uhr() {
        let s = Einladungssitzung {
            letzte_eigene: None,
            letzte_fremde: None,
            eigener_zeitstempel: 0,
            einladungs_zeitstempel: u64::MAX / 2,
            zustand: Sitzungszustand::Start,
        };
        assert!(s.naechster_zeitstempel() > s.einladungs_zeitstempel);
        // Und ohne alles gilt die Uhr.
        let leer = Einladungssitzung::default();
        assert!(leer.naechster_zeitstempel() > 1);
    }
}

#[cfg(test)]
mod tresor_tests {
    use super::*;

    fn pfad(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-tresor-test-{}.json", name));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn klartext_wird_beim_passwortsetzen_umgestellt() {
        let p = pfad("umstellen");
        {
            let mut s = Store::open(&p, 7327).unwrap();
            s.state.listen_port = 4242;
            s.save().unwrap();
        }
        // Vorher lesbar.
        let roh = std::fs::read(&p).unwrap();
        assert!(!crate::tresor::ist_verschluesselt(&roh));
        assert!(String::from_utf8_lossy(&roh).contains("4242"));

        {
            let mut s = Store::open(&p, 7327).unwrap();
            s.passwort_setzen(None, "geheim").unwrap();
        }
        // Nachher nicht mehr -- und die Portnummer steht nirgends im Klartext.
        let roh = std::fs::read(&p).unwrap();
        assert!(crate::tresor::ist_verschluesselt(&roh));
        assert!(!String::from_utf8_lossy(&roh).contains("4242"));

        // Ohne Passwort kein Zutritt, mit Passwort alles wieder da.
        assert!(Store::open(&p, 7327).is_err());
        let s = Store::open_mit_passwort(&p, 7327, "geheim").unwrap();
        assert_eq!(s.state.listen_port, 4242);
        assert!(s.verschluesselt());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn falsches_passwort_oeffnet_nicht() {
        let p = pfad("falsch");
        {
            let mut s = Store::open(&p, 7327).unwrap();
            s.passwort_setzen(None, "richtig").unwrap();
        }
        assert!(Store::open_mit_passwort(&p, 7327, "falsch").is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn beschaedigte_datei_wird_nicht_stillschweigend_geleert() {
        // Das war der gefaehrlichste Fehler: unwrap_or_default() lieferte bei
        // einem Lesefehler einen leeren Zustand, und der naechste save()
        // schrieb ihn ueber Kontakte, Schluessel und Nachrichten.
        let p = pfad("beschaedigt");
        std::fs::write(&p, b"{ das ist kein JSON").unwrap();
        let ergebnis = Store::open(&p, 7327);
        assert!(ergebnis.is_err(), "beschaedigte Datei muss auffallen");
        // Und die Datei liegt unangetastet da.
        assert_eq!(std::fs::read(&p).unwrap(), b"{ das ist kein JSON");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rechte_sind_eng() {
        use std::os::unix::fs::PermissionsExt;
        let p = pfad("rechte");
        {
            let mut s = Store::open(&p, 7327).unwrap();
            s.save().unwrap();
        }
        let modus = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(modus, 0o600, "Speicher stand auf {:o}", modus);
        let _ = std::fs::remove_file(&p);
    }
}

#[cfg(test)]
mod wechsel_tests {
    use super::*;

    fn pfad(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-wechsel-{}.json", name));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn aendern_verlangt_das_alte_passwort() {
        let p = pfad("aendern");
        {
            let mut s = Store::open(&p, 7327).unwrap();
            s.state.listen_port = 4242;
            s.passwort_setzen(None, "alt").unwrap();
        }
        {
            let mut s = Store::open_mit_passwort(&p, 7327, "alt").unwrap();
            // Ohne das alte geht es nicht -- sonst koennte jeder, der kurz
            // an das entsperrte Geraet kommt, den Besitzer aussperren.
            assert!(s.passwort_setzen(None, "neu").is_err());
            assert!(s.passwort_setzen(Some("falsch"), "neu").is_err());
            s.passwort_setzen(Some("alt"), "neu").unwrap();
        }
        assert!(Store::open_mit_passwort(&p, 7327, "alt").is_err());
        let s = Store::open_mit_passwort(&p, 7327, "neu").unwrap();
        assert_eq!(s.state.listen_port, 4242);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn aufheben_verlangt_das_alte_ebenfalls() {
        let p = pfad("aufheben");
        {
            let mut s = Store::open(&p, 7327).unwrap();
            s.passwort_setzen(None, "geheim").unwrap();
        }
        {
            let mut s = Store::open_mit_passwort(&p, 7327, "geheim").unwrap();
            assert!(s.passwort_setzen(None, "").is_err());
            s.passwort_setzen(Some("geheim"), "").unwrap();
            assert!(!s.verschluesselt());
        }
        let roh = std::fs::read(&p).unwrap();
        assert!(!crate::tresor::ist_verschluesselt(&roh));
        let _ = std::fs::remove_file(&p);
    }
}
