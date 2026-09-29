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
    /// Der Fusspunkt (base) unseres Empfangsfensters je Zeitabschnitt: die
    /// kleinste Nummer, die noch erkannt werden kann. Das Fenster reicht von
    /// hier 32 Nummern weit (ReorderingWindow.java).
    pub in_stream: BTreeMap<String, u64>,
    /// Welche Nummern im Fenster schon gesehen sind, je Zeitabschnitt: Bit i
    /// gesetzt heisst `in_stream + i` ist verbraucht. Briar fuehrt dasselbe
    /// als Bitfeld von 32 (ReorderingWindow.java:17-18); ohne es liesse sich
    /// ein mitgeschnittener Strom erneut einspielen, solange seine Nummer
    /// ueber dem Fusspunkt liegt. Nur bei Kontakten gefuehrt -- bei Wartenden
    /// bleibt es leer (siehe `net::fenster_nachziehen`). Fehlt es in einer
    /// alten Datei, gilt alles als ungesehen: das ist der alte Stand.
    #[serde(default)]
    pub in_gesehen: BTreeMap<String, u32>,
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
    /// Die Adresse, unter der die Gegenseite bei UNS angekommen ist -- bei
    /// Bluetooth ihre MAC aus dem angenommenen Sockel.
    ///
    /// Briar meldet sie dem Kontakt als `u:address` zurueck, weil ein Android
    /// ab 8.0 seine eigene MAC nicht mehr lesen darf: es uebernimmt sie erst,
    /// wenn die Mehrheit seiner Kontakte dieselbe zurueckmeldet
    /// (AbstractBluetoothPlugin). Ohne diese Meldung hat ein solches Briar
    /// keine Bluetooth-Adresse, und niemand kann es anwaehlen.
    #[serde(default)]
    pub gesehene_adresse: Option<String>,
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
    /// Der erste Anhang -- bleibt fuer alles stehen, was nur einen kennt.
    #[serde(default)]
    pub attachment: Option<String>,
    #[serde(default)]
    pub attachment_type: Option<String>,
    /// Alle Anhaenge dieser Nachricht, in der Reihenfolge, in der sie
    /// genannt wurden.
    ///
    /// Briar laesst bis zu zehn Bilder an einer Nachricht zu
    /// (MAX_ATTACHMENTS_PER_MESSAGE). Bis 0.29.2 wurde nur der erste behalten:
    /// die weiteren kamen an, wurden quittiert -- und verschwanden, weil
    /// niemand mehr auf sie zeigte. Fuer den Absender sah es aus, als seien
    /// alle angekommen.
    #[serde(default)]
    pub anhaenge: Vec<Anhangskopf>,
    /// Verschwindende Nachricht: wie lange sie nach dem Ankommen noch da
    /// bleibt, in Millisekunden. Nichts heisst: sie bleibt.
    #[serde(default)]
    pub loesch_dauer: Option<u64>,
    /// Der Zeitpunkt, an dem sie geht. Er steht erst fest, wenn die Uhr
    /// laeuft: bei einer eigenen Nachricht mit der Bestaetigung der
    /// Gegenseite, bei einer fremden mit dem Lesen. So haelt es Briar auch --
    /// eine ungelesene Nachricht verschwindet nicht unter der Hand.
    #[serde(default)]
    pub loesch_frist: Option<u64>,
}

/// Ein Anhang, wie die Nachricht ihn nennt: seine Kennung und sein Typ. Die
/// Bytes liegen daneben in einer Datei (siehe `Attachment`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Anhangskopf {
    pub id: String,
    #[serde(default)]
    pub content_type: Option<String>,
}

/// An attachment that has arrived or been sent: its bytes live in a file
/// beside the state, not in it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attachment {
    pub content_type: String,
    /// Die Datei unter `attachments/`. Bei einem versiegelten Anhang ist das
    /// die `.siegel`-Datei -- die Oberflaeche bekommt stattdessen die Kopie
    /// aus `Store::anhang_pfad`.
    pub path: String,
    /// Groesse des Klartexts.
    pub size: u64,
    /// Liegt die Datei mit dem Siegel verschluesselt? Ein eigenes Feld statt
    /// eines Blicks auf die Endung; alte Staende kennen es nicht und sind
    /// damit richtig als Klartext eingetragen.
    #[serde(default)]
    pub versiegelt: bool,
}

/// Was die Magic-Bytes ueber einen Inhalt sagen. Ein Typ je Signatur; Ogg,
/// MP4 und Matroska/WebM tragen Ton wie Bild und stehen hier unter einem
/// Vertreter -- die Familienpruefung beim Empfang (`empfangener_typ`) zaehlt
/// sie fuer audio/* und video/*.
///
/// Nur noch in den Tests: sie belegen damit, dass jede Signatur, die
/// `empfangener_typ` je Familie prueft, auch erkannt wird.
#[cfg(test)]
fn typ_aus_inhalt(daten: &[u8]) -> Option<&'static str> {
    let d = daten;
    if d.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if d.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if d.starts_with(b"GIF87a") || d.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if d.len() >= 12 && d.starts_with(b"RIFF") {
        match &d[8..12] {
            b"WEBP" => return Some("image/webp"),
            b"WAVE" => return Some("audio/wav"),
            _ => {}
        }
    }
    if d.starts_with(b"fLaC") {
        return Some("audio/flac");
    }
    if d.starts_with(b"OggS") {
        return Some("audio/ogg");
    }
    if d.len() >= 8 && &d[4..8] == b"ftyp" {
        return Some("video/mp4");
    }
    if d.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return Some("video/webm");
    }
    if ist_mpeg_ton(d) {
        return Some("audio/mpeg");
    }
    // Zwei Bytes sind eine schwache Signatur; deshalb erst nach allen
    // laengeren.
    if d.starts_with(b"BM") {
        return Some("image/bmp");
    }
    if ist_text(d) {
        return Some("text/plain");
    }
    None
}

/// ID3-Kopf oder ein MPEG-Rahmen (11 gesetzte Sync-Bits: FF Ex / FF Fx).
fn ist_mpeg_ton(d: &[u8]) -> bool {
    d.starts_with(b"ID3") || (d.len() >= 2 && d[0] == 0xFF && d[1] & 0xE0 == 0xE0)
}

fn ist_text(d: &[u8]) -> bool {
    !d.contains(&0) && std::str::from_utf8(d).is_ok()
}

const OCTET_STREAM: &str = "application/octet-stream";

/// Einen gemeldeten Typ in die Form `[a-z0-9.+-]+/[a-z0-9.+-]+` bringen
/// (kleingeschrieben, ohne Leerraum und ohne Parameter wie "; charset=...",
/// hoechstens 100 Zeichen); was sich so nicht schreiben laesst, wird
/// application/octet-stream. Der Typ steht spaeter in der Oberflaeche, in der
/// Bruecke und -- als Familie -- im Protokoll: frei gewaehlter Text der
/// Gegenseite (Zeilenumbrueche!) gehoert an keine dieser Stellen (7b, C7).
pub fn typ_normalisieren(gemeldet: &str) -> String {
    let grund = gemeldet.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let teil_gut = |t: &str| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+-.".contains(&b))
    };
    let gut = grund.len() <= 100
        && grund
            .split_once('/')
            .is_some_and(|(art, unterart)| teil_gut(art) && teil_gut(unterart));
    if gut {
        grund
    } else {
        OCTET_STREAM.to_string()
    }
}

/// Die Familie eines (normalisierten) Typs -- mehr kommt nicht ins Protokoll.
pub fn typ_familie(typ: &str) -> &'static str {
    match typ.split('/').next().unwrap_or("") {
        "image" => "image",
        "audio" => "audio",
        "video" => "video",
        "text" => "text",
        _ => "other",
    }
}

/// Der Typ, der von einem empfangenen Anhang gespeichert wird (Befund M7).
///
/// Der gemeldete Typ kommt von der Gegenseite und verteilt in der
/// Oberflaeche auf die Anzeige: image/* an Qts Bildlader, audio/* und
/// video/* an den Abspieler (erst nach Antippen), sonst "Datei". Passt der
/// Inhalt nicht zur gemeldeten Familie, wird daraus
/// application/octet-stream. Das verhindert nur, dass ein falsch
/// deklarierter Anhang in einer anderen Anzeige landet; einen Decoder mit
/// passender Signatur, aber boesem Inhalt haelt es nicht auf -- Qt und
/// gstreamer waehlen ihren Leser selbst am Inhalt (7b, C2). Andere Typen
/// (application/pdf ...) gehen an keinen Decoder.
///
/// Geprueft wird je Familie und nicht gegen den einen Treffer von
/// `typ_aus_inhalt`: ein Text, der mit "BM" anfaengt, ist trotzdem Text.
/// Gespeichert wird der normalisierte Typ (`typ_normalisieren`).
pub fn empfangener_typ(gemeldet: &str, daten: &[u8]) -> String {
    let klein = typ_normalisieren(gemeldet);
    let d = daten;
    let riff = |art: &[u8]| d.len() >= 12 && d.starts_with(b"RIFF") && &d[8..12] == art;
    let ogg = d.starts_with(b"OggS");
    let mp4 = d.len() >= 8 && &d[4..8] == b"ftyp";
    let ebml = d.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]);
    let passt = if klein.starts_with("image/") {
        d.starts_with(&[0xFF, 0xD8, 0xFF])
            || d.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
            || d.starts_with(b"GIF87a")
            || d.starts_with(b"GIF89a")
            || riff(b"WEBP")
            || d.starts_with(b"BM")
    } else if klein.starts_with("audio/") {
        // audio/webm (Opus in WebM) gibt es wirklich, deshalb zaehlt EBML
        // auch hier.
        ist_mpeg_ton(d) || riff(b"WAVE") || d.starts_with(b"fLaC") || ogg || mp4 || ebml
    } else if klein.starts_with("video/") {
        ogg || mp4 || ebml
    } else if klein.starts_with("text/") {
        ist_text(d)
    } else {
        return klein;
    };
    if passt {
        klein
    } else {
        crate::net::log(&format!(
            "attachment type did not match its content ({})",
            typ_familie(&klein)
        ));
        OCTET_STREAM.to_string()
    }
}

/// Die Dateiendung zum gespeicherten Typ. Gstreamer und Qt schauen zwar in
/// den Inhalt, eine passende Endung schadet aber keinem Programm, das die
/// Datei spaeter oeffnet.
fn endung(content_type: &str) -> &'static str {
    let klein = content_type.trim().to_ascii_lowercase();
    let grund = klein.split(';').next().unwrap_or("").trim();
    match grund {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/bmp" => "bmp",
        "audio/ogg" => "oga",
        "video/ogg" => "ogv",
        "audio/mpeg" => "mp3",
        "audio/wav" | "audio/x-wav" | "audio/wave" => "wav",
        "audio/flac" => "flac",
        "audio/mp4" => "m4a",
        "video/mp4" => "mp4",
        "audio/webm" | "video/webm" => "webm",
        "video/x-matroska" => "mkv",
        "text/plain" => "txt",
        "application/pdf" => "pdf",
        _ => "bin",
    }
}

/// Der Name der entschluesselten Kopie: Kennung und Endung, ohne `.siegel`.
fn kopie_name(id: &str, anhang: &Attachment) -> String {
    format!("{}.{}", id, endung(&anhang.content_type))
}

/// Wo die entschluesselten Kopien der Anhaenge liegen: im Laufzeitordner, der
/// mit der Sitzung verschwindet. Auf Sailfish ist `XDG_RUNTIME_DIR`
/// /run/user/<uid> (tmpfs, 0700). Harmattan setzt die Variable nicht; dort
/// bleibt /tmp/harbour-briar-<uid> -- ob /tmp auf dem N9 ein tmpfs ist, ist
/// ungeprueft, die Kopien koennen dort also auf dem Flash landen. Sie werden
/// beim Start, beim Zusperren und beim Loeschen weggeraeumt.
pub fn anhang_laufzeit_ordner() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d).join("harbour-briar").join("anhaenge"),
        _ => {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/tmp/harbour-briar-{}", uid)).join("anhaenge")
        }
    }
}

/// Der Laufzeitordner, mit dem ein Speicher oeffnet. In Tests nie der echte:
/// auch Tests, die ihn nicht umlenken, raeumen beim Passwortsetzen auf.
#[cfg(not(test))]
fn laufzeit_vorgabe() -> PathBuf {
    anhang_laufzeit_ordner()
}

#[cfg(test)]
fn laufzeit_vorgabe() -> PathBuf {
    std::env::temp_dir().join(format!("briar-lauf-{}", std::process::id()))
}

/// Alle entschluesselten Kopien wegraeumen.
pub fn anhang_kopien_leeren(ordner: &Path) {
    let _ = std::fs::remove_dir_all(ordner);
}

/// Den Laufzeitordner anlegen und pruefen, dass er uns gehoert. Unter /tmp
/// kann ein anderer Benutzer den Namen vorher belegen -- als Verweis auf
/// seinen eigenen Ordner, oder als offenen Ordner. Dann keine Kopie.
fn laufzeit_ordner_bereit(ordner: &Path) -> bool {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(ordner)
        .is_err()
    {
        return false;
    }
    let uid = unsafe { libc::getuid() };
    // Der Ordner selbst und der eigene darueber (harbour-briar bzw.
    // harbour-briar-<uid>); was darueber liegt, ist Sache des Systems.
    for pfad in [Some(ordner), ordner.parent()].into_iter().flatten() {
        let meta = match std::fs::symlink_metadata(pfad) {
            Ok(m) => m,
            Err(_) => return false,
        };
        if !meta.file_type().is_dir() || meta.uid() != uid {
            return false;
        }
        if meta.mode() & 0o077 != 0 {
            set_mode(pfad, 0o700);
            match std::fs::symlink_metadata(pfad) {
                Ok(m) if m.mode() & 0o077 == 0 => {}
                _ => return false,
            }
        }
    }
    true
}

/// Schreibt erst daneben und rueckt dann an den Platz, mit 0600 von Anfang
/// an -- es gibt keinen Augenblick mit halber Datei oder offenen Rechten.
fn datei_schreiben(ziel: &Path, inhalt: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut tmp = ziel.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut datei = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    datei.write_all(inhalt)?;
    drop(datei);
    set_mode(&tmp, 0o600);
    std::fs::rename(&tmp, ziel)
}

/// Eine vorbereitete Umlegung: die neue Fassung liegt unter `neu` und kommt
/// nach `ziel`; `alt` ist die Datei, auf die der Eintrag bisher zeigt.
struct Umlegung {
    id: String,
    neu: PathBuf,
    ziel: PathBuf,
    alt: PathBuf,
}

/// Einen Anhang fuer ein anderes Siegel vorbereiten: Klartext -> versiegelt,
/// versiegelt -> Klartext oder versiegelt -> neu versiegelt. Die neue
/// Fassung wird nur daneben gelegt (`<ziel>.neu`); an den Platz kommt sie
/// erst, wenn alle Anhaenge vorbereitet sind (`passwort_setzen`).
fn anhang_vorbereiten(
    id: &str,
    anhang: &Attachment,
    ordner: &Path,
    alt: Option<&crate::tresor::Siegel>,
    neu: Option<&crate::tresor::Siegel>,
) -> Result<Option<Umlegung>, String> {
    let roh = match std::fs::read(&anhang.path) {
        Ok(r) => r,
        // Keine Datei, nichts umzulegen -- der Eintrag bleibt, wie er ist.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let klar = if anhang.versiegelt {
        alt.ok_or_else(|| "kein Siegel fuer einen versiegelten Anhang".to_string())?
            .entschluesseln(&roh)?
    } else {
        roh
    };
    let (ziel, inhalt) = match neu {
        Some(siegel) => (
            ordner.join(format!("{}.{}.siegel", id, endung(&anhang.content_type))),
            siegel.verschluesseln(&klar),
        ),
        None => (ordner.join(format!("{}.{}", id, endung(&anhang.content_type))), klar),
    };
    let mut daneben = ziel.clone().into_os_string();
    daneben.push(".neu");
    let daneben = PathBuf::from(daneben);
    datei_schreiben(&daneben, &inhalt).map_err(|e| e.to_string())?;
    Ok(Some(Umlegung {
        id: id.to_string(),
        neu: daneben,
        ziel,
        alt: PathBuf::from(&anhang.path),
    }))
}

/// Einen einzelnen Anhang gleich umlegen -- fuer das Nachholen beim Oeffnen,
/// wo jeder Anhang fuer sich gelingt oder nicht. Die alte Datei (falls sie
/// anders heisst) kommt zurueck und wird erst geloescht, wenn der Zustand
/// gespeichert ist.
fn anhang_umlegen(
    id: &str,
    anhang: &mut Attachment,
    ordner: &Path,
    alt: Option<&crate::tresor::Siegel>,
    neu: Option<&crate::tresor::Siegel>,
) -> Result<Option<PathBuf>, String> {
    let Some(u) = anhang_vorbereiten(id, anhang, ordner, alt, neu)? else {
        return Ok(None);
    };
    if let Err(e) = std::fs::rename(&u.neu, &u.ziel) {
        let _ = std::fs::remove_file(&u.neu);
        return Err(e.to_string());
    }
    anhang.path = u.ziel.to_string_lossy().to_string();
    anhang.versiegelt = neu.is_some();
    Ok(if u.alt != u.ziel { Some(u.alt) } else { None })
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
    /// Die Zuenddauer, die in dieser Nachricht steht -- gebraucht, um beim
    /// Eintreffen der Bestaetigung die Uhr zu starten.
    #[serde(default)]
    pub loesch_dauer: Option<u64>,
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
    /// Die Fassungsnummer der letzten Adressmeldung an diesen Kontakt. Briar
    /// laesst strikt die hoehere gewinnen und loescht eine Meldung mit
    /// kleinerer Nummer (TransportPropertyManagerImpl) -- quittiert sie aber.
    ///
    /// Vorher stand hier die Uhrzeit. Wird die Uhr zurueckgestellt, und auf N9
    /// und N950 laeuft sie ohne Zeitdienst, traegt jede weitere Meldung eine
    /// kleinere Nummer: Briar behaelt die alte Adressliste, wir halten die neue
    /// fuer zugestellt. Jetzt ist es ein Zaehler, der nie zurueckgeht -- und
    /// weil er von der Uhr ausgeht, ist er auch groesser als alles, was frueher
    /// schon hinausging.
    #[serde(default)]
    pub props_sent_version: u64,
    /// When the user last looked at this chat -- what came later counts as
    /// unread, and that is what a notification is raised for.
    #[serde(default)]
    pub last_read: u64,
    /// Verschwindende Nachrichten: die Dauer in Millisekunden, die jede neue
    /// Nachricht an diesen Kontakt mitbekommt. -1 heisst aus.
    ///
    /// Die Dauer wird nicht ausgehandelt, sondern gespiegelt: sie faehrt in
    /// jeder Nachricht mit, und wer eine mit anderer Dauer bekommt,
    /// uebernimmt sie. So haben beide Seiten dieselbe Einstellung, ohne dass
    /// es dafuer eigene Nachrichten braeuchte (AutoDeleteManagerImpl).
    #[serde(default = "kein_timer")]
    pub loesch_timer: i64,
    /// Die vorige Dauer, solange die Aenderung noch in keiner Nachricht
    /// draussen war. -2 heisst: keine offene Aenderung. Briar entscheidet
    /// daran, wessen Aenderung gilt, wenn beide gleichzeitig umstellen.
    #[serde(default = "keine_vorige")]
    pub loesch_vorher: i64,
    /// Der Zeitstempel der letzten Nachricht, die eine Dauer gemeldet hat.
    /// Aeltere Meldungen zaehlen nicht mehr.
    #[serde(default)]
    pub loesch_stempel: u64,
    /// Was die Gegenseite angesagt hat: Klientenkennung -> Nebenfassung.
    /// Danach richtet sich, was ihr geschickt werden darf.
    #[serde(default)]
    pub fremde_fassungen: BTreeMap<String, u32>,
    /// Die Nummer ihrer letzten Ansage -- eine aeltere zaehlt nicht mehr.
    #[serde(default)]
    pub fremde_ansage_nummer: u64,
    /// Wie oft jede Kennung in `to_request` schon angefordert wurde -- nach
    /// ein paar Runden ohne Antwort faellt sie heraus (net.rs,
    /// anforderungen_fortschreiben).
    #[serde(default)]
    pub anforderungs_runden: BTreeMap<String, u8>,
}

/// -1: keine Zuenddauer -- dieselbe Zahl wie Briars NO_AUTO_DELETE_TIMER.
pub fn kein_timer() -> i64 {
    -1
}

/// -2: keine offene Aenderung (NO_PREVIOUS_TIMER).
pub fn keine_vorige() -> i64 {
    -2
}

/// Die Grenzen, die Briar an eine Zuenddauer legt: eine Minute bis ein Jahr.
pub const MIN_LOESCHDAUER_MS: i64 = 60 * 1000;
pub const MAX_LOESCHDAUER_MS: i64 = 365 * 24 * 60 * 60 * 1000;

impl Contact {
    /// Darf diese Gegenseite eine Zuenddauer bekommen?
    ///
    /// Ja -- ausser sie hat ausdruecklich weniger als Nebenfassung 3 angesagt.
    /// Das ist der entscheidende Unterschied zu "hat 3 angesagt": wir selbst
    /// sagen 3 an, also erwartet Briar die Dauer von uns. Bekommt es
    /// stattdessen eine dreigliedrige Nachricht, liest es das als "keine
    /// Dauer" und spiegelt sie zurueck -- dem Benutzer drueben werden seine
    /// verschwindenden Nachrichten abgeschaltet, und zwar mit dem Hinweis,
    /// wir haetten das getan.
    ///
    /// Eine leere Karte heisst nicht "kann es nicht", sondern "wir haben ihre
    /// Ansage nie gesehen". Das ist der Normalfall fuer jeden Kontakt von vor
    /// 0.29.0: Briar erneuert seine Ansage nur, wenn sich seine eigenen
    /// Klienten aendern, nicht wegen unserer neuen Nebenfassung
    /// (ClientVersioningManagerImpl.updateStatesFromRemoteStates sieht nur die
    /// Hauptfassung). Die Karte bliebe also fuer immer leer.
    ///
    /// Gefaehrlich ist das nicht: Briars Pruefer nimmt drei ODER vier Glieder
    /// an, gleich welche Fassung angesagt wurde (checkSize(body, 3, 4)), und
    /// unsere eigenen aelteren Fassungen lesen das vierte Glied einfach nicht.
    pub fn darf_zuenddauer_bekommen(&self) -> bool {
        self.fremde_fassungen
            .get(crate::sync::MESSAGING_CLIENT_ID)
            .map(|neben| *neben >= 3)
            .unwrap_or(true)
    }

    /// Hat die Gegenseite die Zuenddauer nachweislich angesagt oder benutzt?
    /// Nur fuer die Anzeige -- daran haengt keine Entscheidung auf der
    /// Leitung.
    pub fn zuenddauer_bestaetigt(&self) -> bool {
        self.fremde_fassungen
            .get(crate::sync::MESSAGING_CLIENT_ID)
            .map(|neben| *neben >= 3)
            .unwrap_or(false)
    }

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
/// Zustand haengt; bei uns entscheidet `PrivateGroup::empfaenger()` allein an
/// "Eingeladen", wer Beitraege bekommt.
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
    /// Beitraege, deren Kette bei uns noch nicht steht: die vorige Nachricht
    /// bzw. der Elternbeitrag fehlt. Briar fuehrt sie als Abhaengigkeiten
    /// (GroupMessageValidator.validatePost) und stellt sie erst zu, wenn alles
    /// da ist; bis dahin sieht sie niemand und sie werden nicht weitergereicht.
    #[serde(default)]
    pub wartend: Vec<WartenderBeitrag>,
    /// Kennungen verworfener Beitraege, neueste zuletzt. Briar setzt eine
    /// ungueltige Nachricht INVALID und mit ihr alles, was von ihr abhaengt
    /// (ValidationManagerImpl.invalidateMessage, Z. 424-440). Ohne dieses
    /// Gedaechtnis wartete ein Beitrag auf einen verworfenen Vorgaenger fuer
    /// immer und belegte einen Platz auf der Warteliste.
    #[serde(default)]
    pub verworfen: Vec<String>,
}

/// Ein Beitrag auf der Warteliste einer Gruppe. `contact_id` ist der Kontakt,
/// von dem er kam: an ihn geht er nicht zurueck, wenn er spaeter aufgeht.
///
/// Autor, Elternbeitrag und vorige Nachricht werden beim Einlegen einmal aus
/// dem Rumpf gelesen und hier mitgefuehrt: die Nachlese sucht ueber sie, statt
/// jeden Rumpf erneut zu dekodieren. Eintraege aus 0.42.0 haben sie nicht
/// (`previous` leer); die traegt die Nachlese beim ersten Mal nach.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WartenderBeitrag {
    pub id: String,
    pub contact_id: u32,
    pub timestamp: u64,
    pub body: String,
    #[serde(default)]
    pub author_id: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub previous: String,
}

impl WartenderBeitrag {
    /// Die Groesse des Rumpfs in Byte -- gespeichert ist er als Hexzahl.
    pub fn rumpf_laenge(&self) -> usize {
        self.body.len() / 2
    }
}

/// So viele Beitraege wartet eine Gruppe hoechstens, und so viel Rumpf (in
/// Byte, nicht Hexzeichen).
pub const MAX_WARTEND: usize = 200;
pub const MAX_WARTEND_BYTES: usize = 4 * 1024 * 1024;
/// ... und je Ueberbringer. Ein Kontakt kann so nur die eigenen Plaetze
/// fuellen, nicht die Beitraege verdraengen, die andere gebracht haben.
pub const MAX_WARTEND_JE_KONTAKT: usize = 50;
pub const MAX_WARTEND_BYTES_JE_KONTAKT: usize = 1024 * 1024;
/// So viele verworfene Kennungen merkt sich eine Gruppe; die aelteste faellt.
pub const MAX_VERWORFEN: usize = 500;

impl PrivateGroup {
    /// Legt einen Beitrag auf die Warteliste -- wenn Platz ist. Ist eine der
    /// Grenzen erreicht (je Gruppe oder je Ueberbringer), bleibt die Liste,
    /// wie sie ist, und die Antwort ist `false`: dann wird der NEUE Beitrag
    /// zurueckgestellt, also nicht quittiert, und die Gegenseite schickt ihn
    /// spaeter wieder. Frueher fiel stattdessen der aelteste Wartende -- der
    /// war aber schon quittiert und damit fuer immer verloren, samt der
    /// ganzen spaeteren Kette seines Autors (Gegenpruefung 7a, G1).
    pub fn warten_lassen(&mut self, beitrag: WartenderBeitrag) -> bool {
        let groesse = beitrag.rumpf_laenge();
        let (mut anzahl, mut bytes) = (0usize, 0usize);
        let (mut anzahl_kontakt, mut bytes_kontakt) = (0usize, 0usize);
        for w in &self.wartend {
            anzahl += 1;
            bytes += w.rumpf_laenge();
            if w.contact_id == beitrag.contact_id {
                anzahl_kontakt += 1;
                bytes_kontakt += w.rumpf_laenge();
            }
        }
        if anzahl >= MAX_WARTEND
            || bytes + groesse > MAX_WARTEND_BYTES
            || anzahl_kontakt >= MAX_WARTEND_JE_KONTAKT
            || bytes_kontakt + groesse > MAX_WARTEND_BYTES_JE_KONTAKT
        {
            return false;
        }
        self.wartend.push(beitrag);
        true
    }

    /// Eine Kennung als verworfen merken, hoechstens MAX_VERWORFEN.
    pub fn verworfen_merken(&mut self, id: &str) {
        if self.verworfen.iter().any(|v| v == id) {
            return;
        }
        self.verworfen.push(id.to_string());
        if self.verworfen.len() > MAX_VERWORFEN {
            let zuviel = self.verworfen.len() - MAX_VERWORFEN;
            self.verworfen.drain(..zuviel);
        }
    }

    /// Verwirft `id` und mit ihr jeden Wartenden, der darauf aufbaut, und so
    /// fort -- Briars addDependentsToInvalidate. Gibt die Zahl der
    /// mitverworfenen Wartenden zurueck.
    pub fn verwerfen_mit_abhaengigen(&mut self, id: &str) -> usize {
        let mut offen = vec![id.to_string()];
        let mut mit = 0;
        while let Some(id) = offen.pop() {
            self.verworfen_merken(&id);
            let (weg, bleibt): (Vec<WartenderBeitrag>, Vec<WartenderBeitrag>) =
                std::mem::take(&mut self.wartend)
                    .into_iter()
                    .partition(|w| w.previous == id || w.parent.as_deref() == Some(id.as_str()));
            self.wartend = bleibt;
            mit += weg.len();
            offen.extend(weg.into_iter().map(|w| w.id));
        }
        mit
    }

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

    /// An wen ein Beitrag geht: die Mitglieder, deren Einladung nicht mehr
    /// offen ist. Fuer ein echtes Briar gibt es die Gruppe vor der Zusage
    /// nicht -- sie ist unsichtbar, und in einer unsichtbaren Gruppe wird jede
    /// Nachricht verworfen UND nicht quittiert (DatabaseComponentImpl
    /// .receiveMessage). Der Korb schickte den Verlauf also in jeder Runde
    /// erneut, bis sie zusagt, und fuer immer, wenn sie nie antwortet. Mit
    /// der Zusage (receive_einladung_join) geht der Verlauf dann geschlossen
    /// hinaus, samt allem, was in der Zwischenzeit geschrieben wurde.
    ///
    /// Das LEAVE beim Verlassen geht dagegen an ALLE in `contacts`: eine
    /// offene Einladung muss davon erfahren, sonst laesst sie sich drueben
    /// noch annehmen (Briars Ersteller schickt es auch in INVITED).
    pub fn empfaenger(&self) -> Vec<u32> {
        self.contacts
            .iter()
            .copied()
            .filter(|c| {
                !matches!(
                    self.einladungen.get(c).map(|s| s.zustand),
                    Some(Sitzungszustand::Eingeladen)
                )
            })
            .collect()
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
    /// Nach wie vielen Minuten ohne Regung die Oberflaeche von selbst zusperrt.
    /// 0 heisst nie -- wie bei Briar, wo die Sperre erst eingeschaltet werden
    /// muss.
    #[serde(default)]
    pub sperre_nach_minuten: u64,
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
    /// Ob Benachrichtigungen Absender und Text zeigen. Aus, wie bei Briar auf
    /// Android: sonst liegt der Text im Benachrichtigungsspeicher des
    /// Telefons, ausserhalb des verschluesselten Zustands.
    #[serde(default)]
    pub notification_preview: bool,
}

/// The newest layout this build knows.
const STATE_VERSION: u32 = 6;

/// Transports are on unless switched off -- a state file written before a
/// transport existed should not leave it disabled for ever.
fn enabled() -> bool {
    true
}

/// Whether Tor starts by itself. A Tor process costs some 66 MB (measured on
/// the Jolla), which is a lot on Harmattan (armv7) and bearable on the Jolla,
/// so on Harmattan the user switches it on when they want it. The switch
/// works live: the supervisor in main.rs picks it up within five seconds,
/// no restart. The help page says so.
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
    /// Wohin die entschluesselten Kopien der Anhaenge kommen
    /// (`anhang_laufzeit_ordner`); in Tests ein Wegwerfordner.
    laufzeit: PathBuf,
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
        let neues = if neu.is_empty() {
            None
        } else {
            // Beim Wechsel wandert der Speicherschluessel mit, sonst waere
            // jede alte Sicherung unlesbar; ohne Siegel wird einer geboren.
            Some(match &self.siegel {
                Some(altes) => altes.neu_verpacken(neu).map_err(fehler)?,
                None => crate::tresor::Siegel::frisch(neu).map_err(fehler)?,
            })
        };
        // Die Anhaenge mitnehmen: mit Passwort versiegelt, ohne im Klartext.
        //
        // Der Speicherschluessel bleibt beim Wechsel derselbe -- wie Briars
        // DB-Schluessel, den ein neues Passwort nur neu verpackt
        // (`neu_verpacken`). Wer eine alte Kopie der state.json oder einer
        // Anhangsdatei UND das alte Passwort hat, entschluesselt damit also
        // auch alles Neue; das ist gewollt, sonst waere jede Sicherung nach
        // einem Wechsel unlesbar. Neu geschrieben wird trotzdem jede Datei:
        // in ihrem Kopf steht das Paket des Passworts, unter dem sie
        // geschrieben wurde, und mit dem alten Passwort liesse sich aus einer
        // liegengebliebenen der Speicherschluessel holen.
        //
        // Darum alles oder nichts (7b, C6): erst jede neue Fassung neben die
        // alte legen; scheitert eine, bleibt die alte Lage ganz stehen und
        // der Fehler geht an die Oberflaeche. Frueher zaehlte ein Fehlschlag
        // nur mit, und der Wechsel lief trotzdem durch -- die eine Datei trug
        // dann weiter das alte Paket.
        let ordner = self.attachment_dir();
        let mut vorbereitet: Vec<Umlegung> = Vec::new();
        let mut fehler_beim_umlegen = None;
        for (id, anhang) in self.state.attachments.iter() {
            if !anhang.versiegelt && neues.is_none() {
                continue;
            }
            match anhang_vorbereiten(id, anhang, &ordner, self.siegel.as_ref(), neues.as_ref()) {
                Ok(Some(u)) => vorbereitet.push(u),
                Ok(None) => {}
                Err(e) => {
                    fehler_beim_umlegen = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = fehler_beim_umlegen {
            for u in &vorbereitet {
                let _ = std::fs::remove_file(&u.neu);
            }
            crate::net::log("an attachment could not be re-encrypted -- the password stays as it was");
            return Err(fehler(format!("ein Anhang liess sich nicht umschluesseln: {}", e)));
        }
        // Jetzt an den Platz. Ein rename im selben Ordner scheitert kaum; tut
        // er es doch, bleibt es beim alten Passwort, und die schon
        // umgelegten Dateien sind mit demselben Schluessel lesbar.
        let mut alte_dateien = Vec::new();
        for (n, u) in vorbereitet.iter().enumerate() {
            if let Err(e) = std::fs::rename(&u.neu, &u.ziel) {
                for rest in &vorbereitet[n..] {
                    let _ = std::fs::remove_file(&rest.neu);
                }
                // Was schon umgelegt ist und anders heisst, liegt neben
                // der alten Datei, auf die der Eintrag noch zeigt.
                for fertig in &vorbereitet[..n] {
                    if fertig.ziel != fertig.alt {
                        let _ = std::fs::remove_file(&fertig.ziel);
                    }
                }
                crate::net::log("an attachment could not be moved into place -- the password stays as it was");
                return Err(fehler(format!("ein Anhang liess sich nicht umlegen: {}", e)));
            }
        }
        for u in vorbereitet {
            if let Some(anhang) = self.state.attachments.get_mut(&u.id) {
                anhang.path = u.ziel.to_string_lossy().to_string();
                anhang.versiegelt = neues.is_some();
            }
            if u.alt != u.ziel {
                alte_dateien.push(u.alt);
            }
        }
        self.siegel = neues;
        // Kopien aus der Zeit davor gelten nicht mehr.
        self.anhang_kopien_leeren();
        self.save()?;
        // Erst jetzt: vorher zeigte der gespeicherte Zustand noch auf sie.
        for datei in alte_dateien {
            let _ = std::fs::remove_file(datei);
        }
        Ok(())
    }

    /// Die entschluesselten Kopien dieses Speichers wegraeumen -- beim
    /// Zusperren und nach einem Passwortwechsel.
    pub fn anhang_kopien_leeren(&self) {
        anhang_kopien_leeren(&self.laufzeit);
    }

    /// Den Laufzeitordner umlenken, damit Tests nicht in den echten
    /// schreiben (Umgebungsvariablen gelten fuer alle Tests zugleich).
    #[cfg(test)]
    pub fn laufzeit_setzen(&mut self, ordner: PathBuf) {
        self.laufzeit = ordner;
    }

    /// Liegt der Speicher gerade verschluesselt vor?
    pub fn verschluesselt(&self) -> bool {
        self.siegel.is_some()
    }

    /// Stimmt dieses Passwort? Gebraucht beim Aufsperren der Oberflaeche --
    /// dort ist der Speicher schon offen, es geht nur um die Frage, ob der
    /// davorsteht, der es darf. Ohne Passwort gibt es keine Sperre und damit
    /// auch nichts zu pruefen.
    pub fn passwort_stimmt(&self, passwort: &str) -> bool {
        match &self.siegel {
            Some(siegel) => siegel.stimmt(passwort),
            None => false,
        }
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
            //
            // Der Fehlertext von serde zitiert Werte aus dem schon
            // entschluesselten Zustand ("invalid type: string \"...\"") und
            // landet im Protokoll und auf stderr. Darum nur Zeile und Spalte;
            // den vollen Text gibt es mit BRIAR_LOG_VOLL=1 (7b, D4).
            serde_json::from_str(&text).map_err(|e| {
                let grund = if crate::net::log_voll() {
                    e.to_string()
                } else {
                    format!("state does not parse, line {} column {}", e.line(), e.column())
                };
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Speicher nicht lesbar ({}) -- Datei bleibt unangetastet", grund),
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
            laufzeit: laufzeit_vorgabe(),
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
        // Fassung 4 kannte je Nachricht nur einen Anhang. Den einen in die
        // Liste heben, damit von hier an alles ueber sie laeuft.
        if store.state.state_version < 5 {
            for contact in store.state.contacts.iter_mut() {
                for m in contact.messages.iter_mut() {
                    if m.anhaenge.is_empty() {
                        if let Some(id) = m.attachment.clone() {
                            m.anhaenge.push(Anhangskopf {
                                id,
                                content_type: m.attachment_type.clone(),
                            });
                        }
                    }
                }
            }
        }
        // Fassung 5 legte Beitraege auch fuer Kontakte mit offener Einladung
        // in den Korb. Ein echtes Briar verwirft sie dort und quittiert sie
        // nicht -- der Korb schickte sie in jeder Runde erneut, bis zur Zusage
        // oder fuer immer. Einmal ausraeumen; mit der Zusage geht der Verlauf
        // ohnehin geschlossen hinaus (net.rs, receive_einladung_join).
        if store.state.state_version < 6 {
            let offen: Vec<(u32, String)> = store
                .state
                .groups
                .iter()
                .flat_map(|g| {
                    g.einladungen
                        .iter()
                        .filter(|(_, s)| s.zustand == Sitzungszustand::Eingeladen)
                        .map(|(c, _)| (*c, g.id.clone()))
                        .collect::<Vec<_>>()
                })
                .collect();
            for (contact_id, group_hex) in offen {
                store.verwerfe_gruppenpost(contact_id, &group_hex);
            }
        }
        // Mit Passwort, aber noch Klartext-Anhaenge auf der Platte: aus einer
        // Fassung, die sie nie versiegelt hat, oder ein Umlegen ist beim
        // Passwortsetzen fehlgeschlagen. Jetzt nachholen. Kein eigener
        // Fassungsschritt -- das Feld `versiegelt` sagt genug.
        let mut alte_dateien = Vec::new();
        if store.siegel.is_some() {
            let ordner = store.attachment_dir();
            let siegel = store.siegel.as_ref();
            for (id, anhang) in store.state.attachments.iter_mut() {
                if anhang.versiegelt {
                    continue;
                }
                match anhang_umlegen(id, anhang, &ordner, siegel, siegel) {
                    Ok(Some(alt)) => alte_dateien.push(alt),
                    Ok(None) => {}
                    Err(_) => crate::net::log("an attachment could not be encrypted"),
                }
            }
        }
        if store.state.state_version != STATE_VERSION || !alte_dateien.is_empty() {
            store.state.state_version = STATE_VERSION;
            if store.save().is_ok() {
                for datei in alte_dateien {
                    let _ = std::fs::remove_file(datei);
                }
            }
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

    /// Writes an attachment's bytes to disk and remembers where. With a
    /// password the file is sealed (`<id>.<ext>.siegel`) like the state
    /// itself; the returned path is the stored file, not a readable copy.
    /// The type is taken as given -- this is the path for our own sends;
    /// received attachments go through `anhang_empfangen`.
    pub fn store_attachment(
        &mut self,
        id: &str,
        content_type: &str,
        data: &[u8],
    ) -> std::io::Result<String> {
        let dir = self.attachment_dir();
        std::fs::create_dir_all(&dir)?;
        set_mode(&dir, 0o700);
        let extension = endung(content_type);
        let (file, inhalt) = match &self.siegel {
            Some(siegel) => (
                dir.join(format!("{}.{}.siegel", id, extension)),
                siegel.verschluesseln(data),
            ),
            None => (dir.join(format!("{}.{}", id, extension)), data.to_vec()),
        };
        datei_schreiben(&file, &inhalt)?;
        let path = file.to_string_lossy().to_string();
        let vorher = self.state.attachments.insert(
            id.to_string(),
            Attachment {
                content_type: content_type.to_string(),
                path: path.clone(),
                size: data.len() as u64,
                versiegelt: self.siegel.is_some(),
            },
        );
        // Kam derselbe Anhang schon einmal, unter anderem Namen: die alte
        // Datei und eine alte Kopie nicht verwaist liegen lassen.
        if let Some(vorher) = vorher {
            if vorher.path != path {
                let _ = std::fs::remove_file(&vorher.path);
            }
            let _ = std::fs::remove_file(self.laufzeit.join(kopie_name(id, &vorher)));
        }
        Ok(path)
    }

    /// Ein empfangener Anhang: der gemeldete Typ wird am Inhalt geprueft
    /// (`empfangener_typ`), dann wie `store_attachment`. Zurueck kommt der
    /// Typ, der gespeichert wurde -- er gehoert auch in die Nachricht.
    pub fn anhang_empfangen(
        &mut self,
        id: &str,
        gemeldeter_typ: &str,
        data: &[u8],
    ) -> std::io::Result<String> {
        let typ = empfangener_typ(gemeldeter_typ, data);
        self.store_attachment(id, &typ, data)?;
        Ok(typ)
    }

    pub fn attachment(&self, id: &str) -> Option<&Attachment> {
        self.state.attachments.get(id)
    }

    /// Der Pfad, den die Oberflaeche laden kann. Ohne Passwort die Datei
    /// selbst; versiegelt eine entschluesselte Kopie im Laufzeitordner, die
    /// hier bei Bedarf entsteht. None, wenn es den Anhang nicht gibt, die
    /// Kopie nicht sicher abzulegen ist -- oder die Oberflaeche zugesperrt
    /// ist: hinter der Sperre entsteht keine Kopie mehr (7b, C3).
    pub fn anhang_pfad(&self, id: &str) -> Option<String> {
        self.anhang_pfad_wenn(id, crate::api::ist_gesperrt())
    }

    /// `anhang_pfad` mit der Sperre als Argument -- die echte ist ein
    /// Prozessglobal, und ein Test, der sie umlegt, stoerte alle anderen.
    fn anhang_pfad_wenn(&self, id: &str, gesperrt: bool) -> Option<String> {
        if gesperrt {
            return None;
        }
        let anhang = self.state.attachments.get(id)?;
        if !anhang.versiegelt {
            return Some(anhang.path.clone());
        }
        let siegel = self.siegel.as_ref()?;
        if !laufzeit_ordner_bereit(&self.laufzeit) {
            // Einmal je Lauf: die Oberflaeche fragt laufend, das waere sonst
            // eine Zeile je Anhang und Abruf.
            static GEMELDET: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !GEMELDET.swap(true, std::sync::atomic::Ordering::Relaxed) {
                crate::net::log("the runtime directory for attachments is not safe to use");
            }
            return None;
        }
        let kopie = self.laufzeit.join(kopie_name(id, anhang));
        if !kopie.is_file() {
            let roh = std::fs::read(&anhang.path).ok()?;
            let klar = siegel.entschluesseln(&roh).ok()?;
            datei_schreiben(&kopie, &klar).ok()?;
        }
        Some(kopie.to_string_lossy().to_string())
    }

    /// Einen Anhang samt Datei wegraeumen. Gebraucht beim Loeschen einer
    /// Nachricht: bliebe die Datei liegen, waere das Bild noch da, das man
    /// gerade weghaben wollte. Alle drei Orte: die gespeicherte Datei, ein
    /// Klartext-Rest daneben (aus einem abgebrochenen Umlegen) und die Kopie
    /// im Laufzeitordner.
    pub fn anhang_loeschen(&mut self, id: &str) {
        if let Some(anhang) = self.state.attachments.remove(id) {
            let _ = std::fs::remove_file(&anhang.path);
            let ordner = self.attachment_dir();
            let klar = ordner.join(format!("{}.{}", id, endung(&anhang.content_type)));
            let _ = std::fs::remove_file(&klar);
            let mut versiegelt = klar.into_os_string();
            versiegelt.push(".siegel");
            let _ = std::fs::remove_file(versiegelt);
            let _ = std::fs::remove_file(self.laufzeit.join(kopie_name(id, &anhang)));
        }
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
            wartend: Vec::new(),
            verworfen: Vec::new(),
        }
    }

    fn wartender(n: usize) -> WartenderBeitrag {
        wartender_von(n, 1, 0)
    }

    /// Ein Wartender von Kontakt `von` mit `bytes` Byte Rumpf.
    fn wartender_von(n: usize, von: u32, bytes: usize) -> WartenderBeitrag {
        WartenderBeitrag {
            id: format!("w{}", n),
            contact_id: von,
            timestamp: n as u64,
            body: "00".repeat(bytes),
            ..Default::default()
        }
    }

    /// Frueher fiel hier der aelteste -- der war aber schon quittiert und
    /// damit verloren (7a, G1). Jetzt bleibt die Liste und der neue wird
    /// abgewiesen; der Aufrufer quittiert ihn dann nicht.
    #[test]
    fn volle_warteliste_weist_den_neuen_ab() {
        let mut g = gruppe(None, Vec::new());
        // Vier Ueberbringer, damit die Grenze je Kontakt nicht zuerst greift.
        for n in 0..MAX_WARTEND {
            assert!(g.warten_lassen(wartender_von(n, (n % 4) as u32 + 1, 0)));
        }
        assert!(!g.warten_lassen(wartender_von(MAX_WARTEND, 5, 0)));
        assert_eq!(g.wartend.len(), MAX_WARTEND);
        assert_eq!(g.wartend[0].id, "w0", "der erste ist geblieben");
    }

    #[test]
    fn grenze_je_ueberbringer_laesst_andere_herein() {
        let mut g = gruppe(None, Vec::new());
        for n in 0..MAX_WARTEND_JE_KONTAKT {
            assert!(g.warten_lassen(wartender_von(n, 1, 0)));
        }
        assert!(!g.warten_lassen(wartender_von(900, 1, 0)), "Kontakt 1 ist voll");
        assert!(g.warten_lassen(wartender_von(901, 2, 0)), "Kontakt 2 nicht");
        assert_eq!(g.wartend.len(), MAX_WARTEND_JE_KONTAKT + 1);
    }

    #[test]
    fn bytegrenze_je_ueberbringer_zaehlt_den_rumpf_nicht_die_hexzeichen() {
        let mut g = gruppe(None, Vec::new());
        let halb = MAX_WARTEND_BYTES_JE_KONTAKT / 2;
        assert!(g.warten_lassen(wartender_von(0, 1, halb)));
        // Genau bis an die Grenze geht noch -- als Hex waeren es doppelt so viele.
        assert!(g.warten_lassen(wartender_von(1, 1, halb)));
        assert!(!g.warten_lassen(wartender_von(2, 1, 1)), "ein Byte darueber nicht");
        assert!(g.warten_lassen(wartender_von(3, 2, 1)));
    }

    #[test]
    fn bytegrenze_je_gruppe_greift_ueber_alle_ueberbringer() {
        let mut g = gruppe(None, Vec::new());
        let je = MAX_WARTEND_BYTES_JE_KONTAKT;
        let kontakte = (MAX_WARTEND_BYTES / je) as u32;
        for k in 0..kontakte {
            assert!(g.warten_lassen(wartender_von(k as usize, k + 1, je)));
        }
        assert!(!g.warten_lassen(wartender_von(99, kontakte + 1, 1)));
    }

    #[test]
    fn verworfen_merkt_hoechstens_die_grenze() {
        let mut g = gruppe(None, Vec::new());
        for n in 0..=MAX_VERWORFEN {
            g.verworfen_merken(&format!("v{}", n));
        }
        g.verworfen_merken("v3");
        assert_eq!(g.verworfen.len(), MAX_VERWORFEN);
        assert_eq!(g.verworfen[0], "v1", "der aelteste faellt");
    }

    #[test]
    fn verwerfen_nimmt_die_ganze_abhaengige_kette_mit() {
        let mut g = gruppe(None, Vec::new());
        let mut a = wartender(1);
        a.previous = "wurzel".to_string();
        let mut b = wartender(2);
        b.previous = "w1".to_string();
        let mut c = wartender(3);
        c.previous = "anders".to_string();
        c.parent = Some("w2".to_string());
        let mut d = wartender(4);
        d.previous = "fremd".to_string();
        for w in [a, b, c, d] {
            assert!(g.warten_lassen(w));
        }
        assert_eq!(g.verwerfen_mit_abhaengigen("wurzel"), 3);
        assert_eq!(g.wartend.iter().map(|w| w.id.as_str()).collect::<Vec<_>>(), vec!["w4"]);
        for id in ["wurzel", "w1", "w2", "w3"] {
            assert!(g.verworfen.iter().any(|v| v == id), "{} fehlt", id);
        }
    }

    #[test]
    fn wartender_aus_0_42_ohne_verweise_laedt() {
        let alt = serde_json::json!({
            "id": "w1", "contact_id": 2, "timestamp": 5, "body": "0102"
        });
        let w: WartenderBeitrag = serde_json::from_value(alt).unwrap();
        assert!(w.previous.is_empty());
        assert_eq!(w.parent, None);
        assert_eq!(w.rumpf_laenge(), 2);
    }

    #[test]
    fn gruppe_ohne_warteliste_in_der_datei_laedt() {
        let g = gruppe(None, Vec::new());
        let mut wert = serde_json::to_value(&g).unwrap();
        wert.as_object_mut().unwrap().remove("wartend");
        wert.as_object_mut().unwrap().remove("verworfen");
        assert!(wert.get("wartend").is_none());
        let geladen: PrivateGroup = serde_json::from_value(wert).unwrap();
        assert!(geladen.wartend.is_empty());
        assert!(geladen.verworfen.is_empty());
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

    /// Wer nur eingeladen ist, bekommt noch keine Beitraege -- fuer ein
    /// echtes Briar gibt es die Gruppe vor der Zusage nicht. Das LEAVE geht
    /// trotzdem an alle, darum bleibt `contacts` selbst unveraendert.
    #[test]
    fn offene_einladungen_bekommen_keine_beitraege() {
        let mut g = gruppe(None, Vec::new());
        g.contacts = vec![1, 2, 3];
        let mut offen = Einladungssitzung::default();
        offen.zustand = Sitzungszustand::Eingeladen;
        g.einladungen.insert(2, offen);
        let mut drin = Einladungssitzung::default();
        drin.zustand = Sitzungszustand::Beigetreten;
        g.einladungen.insert(3, drin);
        assert_eq!(g.empfaenger(), vec![1, 3]);
        assert_eq!(g.contacts, vec![1, 2, 3]);
    }
}

#[cfg(test)]
mod korbwanderung_tests {
    use super::*;

    fn kontakt(id: u32) -> Contact {
        Contact {
            id,
            name: format!("k{}", id),
            author_id: format!("{:064x}", id),
            signature_public: format!("{:064x}", id),
            handshake_public: None,
            master_key: format!("{:064x}", id),
            alice: true,
            creation_period: 0,
            transports: BTreeMap::new(),
            messages: Vec::new(),
            outbox: Vec::new(),
            to_ack: Vec::new(),
            to_request: Vec::new(),
            last_seen: 0,
            versioning_sent: String::new(),
            versioning_version: 0,
            sent_properties: None,
            props_sent_version: 0,
            last_read: 0,
            loesch_timer: kein_timer(),
            loesch_vorher: keine_vorige(),
            loesch_stempel: 0,
            fremde_fassungen: Default::default(),
            fremde_ansage_nummer: 0,
            anforderungs_runden: Default::default(),
        }
    }

    fn eintrag(group: &str, id: &str) -> OutMessage {
        OutMessage {
            id: id.to_string(),
            group: group.to_string(),
            timestamp: 1,
            body: String::new(),
            acked: false,
            intern: false,
            loesch_dauer: None,
        }
    }

    /// Fassung 5 legte Gruppenbeitraege auch fuer offene Einladungen in den
    /// Korb; die Wanderung auf 6 raeumt genau die aus -- und nur die.
    #[test]
    fn alter_korbbestand_an_offene_einladungen_wird_ausgeraeumt() {
        let mut p = std::env::temp_dir();
        p.push("briar-korbwanderung.json");
        let _ = std::fs::remove_file(&p);
        let gruppe = "aa".repeat(32);
        let andere = "bb".repeat(32);
        {
            let mut store = Store::open(&p, 7327).unwrap();
            store.state.contacts.push(kontakt(1));
            store.state.contacts.push(kontakt(2));
            let mut einladungen = BTreeMap::new();
            let mut offen = Einladungssitzung::default();
            offen.zustand = Sitzungszustand::Eingeladen;
            einladungen.insert(1, offen);
            let mut drin = Einladungssitzung::default();
            drin.zustand = Sitzungszustand::Beigetreten;
            einladungen.insert(2, drin);
            store.state.groups.push(PrivateGroup {
                id: gruppe.clone(),
                name: "g".to_string(),
                salt: "00".to_string(),
                creator_name: "ich".to_string(),
                creator_public: "00".to_string(),
                creator_author_id: "00".to_string(),
                joined: true,
                invited_by: None,
                invite_timestamp: None,
                invite_signature: None,
                member_names: BTreeMap::new(),
                last_read: 0,
                messages: Vec::new(),
                our_previous: None,
                einladungen,
                einladung_previous: None,
                aufgeloest: false,
                letztes_ereignis: None,
                contacts: vec![1, 2],
                wartend: Vec::new(),
                verworfen: Vec::new(),
            });
            for (c, k) in [(1, "p1"), (1, "p2"), (2, "p3")] {
                store.contact_mut(c).unwrap().outbox.push(eintrag(&gruppe, k));
            }
            // Die Einladung selbst und Fremdes bleiben.
            store.contact_mut(1).unwrap().outbox.push(eintrag(&andere, "inv"));
            store.state.state_version = 5;
            store.save().unwrap();
        }
        let store = Store::open(&p, 7327).unwrap();
        assert_eq!(store.state.state_version, STATE_VERSION);
        let korb1: Vec<&str> = store.contact(1).unwrap().outbox.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(korb1, vec!["inv"], "nur die Gruppenbeitraege gehen");
        let korb2: Vec<&str> = store.contact(2).unwrap().outbox.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(korb2, vec!["p3"], "wer drin ist, behaelt alles");
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
            wartend: Vec::new(),
            verworfen: Vec::new(),
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
            roh.replace(' ', "")
                .contains(&format!("\"state_version\":{}", STATE_VERSION)),
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

#[cfg(test)]
mod aufmachen_tests {
    use super::*;

    /// Eine Datei, wie 0.28.0 sie geschrieben hat: verschluesselt, Fassung 3,
    /// und ohne jedes Feld, das 0.29.0 dazugelegt hat. Sie MUSS sich mit dem
    /// richtigen Passwort oeffnen lassen.
    ///
    /// Das ist keine Formalie: der Entsperrweg meldet jeden Fehler beim
    /// Oeffnen als "falsches Passwort" -- ein Lesefehler saehe fuer den
    /// Benutzer also aus wie ein vergessenes Passwort, und der naechste
    /// Schritt waere, das Konto zu loeschen.
    #[test]
    fn eine_datei_von_0_28_geht_auf() {
        let alt = r#"{
            "identity": {
                "name": "Ich",
                "signature_seed": "11",
                "signature_public": "22",
                "author_id": "33",
                "handshake_private": "44",
                "handshake_public": "55"
            },
            "listen_port": 7327,
            "bluetooth": true,
            "tor": true,
            "tor_key": null,
            "tor_onion": "abc",
            "lan_recent": ["192.168.1.5:7327"],
            "lan_published": "192.168.1.5:7327",
            "lan6_recent": [],
            "bt_uuid": "0000-1111",
            "pending": [],
            "contacts": [{
                "id": 1,
                "name": "Gegenueber",
                "author_id": "aa",
                "signature_public": "bb",
                "handshake_public": "cc",
                "master_key": "dd",
                "alice": true,
                "creation_period": 3,
                "transports": {},
                "messages": [{
                    "id": "m1",
                    "timestamp": 1000,
                    "text": "hallo",
                    "outgoing": true,
                    "acked": true,
                    "attachment": null,
                    "attachment_type": null
                }],
                "outbox": [{
                    "id": "m2",
                    "group": "gg",
                    "timestamp": 1001,
                    "body": "00",
                    "acked": false,
                    "intern": false
                }],
                "to_ack": [],
                "to_request": [],
                "last_seen": 900,
                "versioning_sent": "abcd",
                "versioning_version": 2,
                "sent_properties": "x",
                "props_sent_version": 1,
                "last_read": 500
            }],
            "groups": [],
            "verlassene_einladungen": {},
            "sperre_nach_minuten": 0,
            "attachments": {},
            "next_contact_id": 2,
            "revision": 42,
            "state_version": 3
        }"#;

        let mut p = std::env::temp_dir();
        p.push("briar-aufmachen-0-28.json");
        let _ = std::fs::remove_file(&p);
        let siegel = crate::tresor::Siegel::frisch("geheim").expect("Siegel");
        std::fs::write(&p, siegel.verschluesseln(alt.as_bytes())).unwrap();

        let store = Store::open_mit_passwort(&p, 7327, "geheim");
        let store = match store {
            Ok(s) => s,
            Err(e) => panic!("0.28-Datei laesst sich nicht oeffnen: {}", e),
        };
        assert_eq!(store.state.contacts.len(), 1);
        assert_eq!(store.state.contacts[0].messages.len(), 1);
        assert_eq!(store.state.contacts[0].loesch_timer, kein_timer());
        assert_eq!(store.state.contacts[0].loesch_vorher, keine_vorige());
        assert!(store.state.contacts[0].fremde_fassungen.is_empty());
        assert_eq!(store.state.state_version, STATE_VERSION);
        // Und ein falsches Passwort muss weiterhin scheitern.
        assert!(Store::open_mit_passwort(&p, 7327, "falsch").is_err());
        let _ = std::fs::remove_file(&p);
    }
}

#[cfg(test)]
mod anhangs_tests {
    use super::*;

    /// Eine Datei aus 0.29.2 kannte je Nachricht nur einen Anhang. Er muss
    /// beim Oeffnen in die Liste wandern, sonst zeigt die Oberflaeche nach
    /// dem Aufruesten gar keinen mehr.
    #[test]
    fn der_einzelne_anhang_wandert_in_die_liste() {
        let alt = r#"{
            "identity": null,
            "listen_port": 7327,
            "contacts": [{
                "id": 1,
                "name": "Gegenueber",
                "author_id": "aa",
                "signature_public": "bb",
                "handshake_public": null,
                "master_key": "dd",
                "alice": true,
                "creation_period": 0,
                "messages": [
                    {
                        "id": "m1", "timestamp": 1, "text": "Bild",
                        "outgoing": false, "acked": true,
                        "attachment": "a1", "attachment_type": "image/jpeg"
                    },
                    {
                        "id": "m2", "timestamp": 2, "text": "ohne",
                        "outgoing": false, "acked": true,
                        "attachment": null, "attachment_type": null
                    }
                ],
                "last_seen": 0
            }],
            "state_version": 4
        }"#;
        let mut p = std::env::temp_dir();
        p.push("briar-anhangswanderung.json");
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, alt).unwrap();

        let store = Store::open(&p, 7327).unwrap();
        let m = &store.state.contacts[0].messages;
        assert_eq!(
            m[0].anhaenge,
            vec![Anhangskopf {
                id: "a1".to_string(),
                content_type: Some("image/jpeg".to_string()),
            }]
        );
        assert!(m[1].anhaenge.is_empty(), "ohne Anhang bleibt leer");
        // Der alte Platz bleibt gefuellt -- alles, was nur einen kennt,
        // findet ihn weiterhin.
        assert_eq!(m[0].attachment.as_deref(), Some("a1"));
        assert_eq!(store.state.state_version, STATE_VERSION);
        let _ = std::fs::remove_file(&p);
    }
}

#[cfg(test)]
mod vorschau_tests {
    use super::*;

    /// Eine state.json von vor der Einstellung kennt das Feld nicht. Sie muss
    /// laden, und die Vorschau ist dann aus -- wie bei Briar.
    #[test]
    fn alte_datei_ohne_feld_laedt_mit_vorschau_aus() {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-vorschau-alt-{}.json", std::process::id()));
        std::fs::write(&p, r#"{"listen_port": 7327, "state_version": 6, "language": "de"}"#).unwrap();
        let store = Store::open(&p, 7327).unwrap();
        assert!(!store.state.notification_preview);
        let _ = std::fs::remove_file(&p);
    }

    /// Einmal eingeschaltet, uebersteht sie das Schreiben und Wiederlesen.
    #[test]
    fn eingeschaltete_vorschau_uebersteht_neuladen() {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-vorschau-an-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let mut store = Store::open(&p, 7327).unwrap();
        store.state.notification_preview = true;
        store.save().unwrap();
        let wieder = Store::open(&p, 7327).unwrap();
        assert!(wieder.state.notification_preview);
        let _ = std::fs::remove_file(&p);
    }
}

#[cfg(test)]
mod anhang_tests {
    use super::*;

    /// Ein eigener Wegwerfordner je Test: Speicher, Anhaenge und
    /// Laufzeitordner liegen darin, nichts im echten XDG_RUNTIME_DIR.
    fn ordner(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("briar-anhang-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn laufzeit(o: &Path) -> PathBuf {
        o.join("lauf").join("anhaenge")
    }

    fn speicher(o: &Path) -> Store {
        let mut s = Store::open(&o.join("state.json"), 7327).unwrap();
        s.laufzeit_setzen(laufzeit(o));
        s
    }

    fn mit_passwort(o: &Path, pw: &str) -> Store {
        let mut s = Store::open_mit_passwort(&o.join("state.json"), 7327, pw).unwrap();
        s.laufzeit_setzen(laufzeit(o));
        s
    }

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n-geheimes-bild-";
    const MUSTER: &[u8] = b"-geheimes-bild-";

    fn enthaelt(heu: &[u8], nadel: &[u8]) -> bool {
        heu.windows(nadel.len()).any(|f| f == nadel)
    }

    // ---- M7: Typ aus dem Inhalt ----

    #[test]
    fn typ_aus_inhalt_erkennt_jede_signatur() {
        let faelle: &[(&[u8], &str)] = &[
            (b"\xFF\xD8\xFF\xE0rest", "image/jpeg"),
            (b"\x89PNG\r\n\x1a\nrest", "image/png"),
            (b"GIF87a...", "image/gif"),
            (b"GIF89a...", "image/gif"),
            (b"RIFF\x10\0\0\0WEBPVP8 ", "image/webp"),
            (b"BM\x3a\0\0\0\0\0", "image/bmp"),
            (b"OggS\0\x02", "audio/ogg"),
            (b"ID3\x04\0", "audio/mpeg"),
            (b"\xFF\xFB\x90\x00", "audio/mpeg"),
            (b"\xFF\xF3\x90\x00", "audio/mpeg"),
            (b"RIFF\x10\0\0\0WAVEfmt ", "audio/wav"),
            (b"fLaC\0\0\0\x22", "audio/flac"),
            (b"\0\0\0\x20ftypisom", "video/mp4"),
            (b"\x1A\x45\xDF\xA3\x9f", "video/webm"),
            ("Grüße".as_bytes(), "text/plain"),
        ];
        for (daten, typ) in faelle {
            assert_eq!(typ_aus_inhalt(daten), Some(*typ), "{:?}", daten);
        }
    }

    #[test]
    fn typ_aus_inhalt_unerkannt() {
        assert_eq!(typ_aus_inhalt(b"\x00\x01\x02\x03"), None, "Binaer mit NUL");
        assert_eq!(typ_aus_inhalt(b"\xC3\x28"), None, "kaputtes UTF-8");
        assert_eq!(typ_aus_inhalt(b"RIFF\x10\0\0\0AVI "), None, "RIFF ohne Bild/Ton");
        assert_eq!(typ_aus_inhalt(b"\0\0ft"), None, "ftyp zu kurz");
    }

    #[test]
    fn falscher_bildtyp_wird_octet_stream() {
        assert_eq!(empfangener_typ("image/jpeg", b"OggS\0\x02"), "application/octet-stream");
        assert_eq!(empfangener_typ("image/png", b"\x00\x01\x02"), "application/octet-stream");
    }

    #[test]
    fn falscher_tontyp_wird_octet_stream() {
        assert_eq!(empfangener_typ("audio/ogg", PNG), "application/octet-stream");
    }

    #[test]
    fn falscher_videotyp_wird_octet_stream() {
        // MP3 ist Ton, kein Bild -- fuer video/* zaehlt es nicht.
        assert_eq!(empfangener_typ("video/mp4", b"ID3\x04\0"), "application/octet-stream");
    }

    #[test]
    fn falscher_texttyp_wird_octet_stream() {
        assert_eq!(empfangener_typ("text/plain", b"a\0b"), "application/octet-stream");
    }

    #[test]
    fn grossschreibung_umgeht_die_pruefung_nicht() {
        assert_eq!(empfangener_typ("IMAGE/JPEG", b"\0\0"), "application/octet-stream");
        assert_eq!(empfangener_typ(" image/png", b"\0\0"), "application/octet-stream");
    }

    #[test]
    fn passender_typ_bleibt() {
        assert_eq!(empfangener_typ("image/png", PNG), "image/png");
        assert_eq!(empfangener_typ("image/jpeg", b"\xFF\xD8\xFF\xE1"), "image/jpeg");
        // Parameter fallen seit 7b C7 weg: gespeichert wird nur noch, was
        // auf [a-z0-9.+-]+/[a-z0-9.+-]+ passt.
        assert_eq!(empfangener_typ("text/plain; charset=utf-8", b"Hallo"), "text/plain");
        assert_eq!(empfangener_typ("IMAGE/PNG", PNG), "image/png", "kleingeschrieben");
    }

    #[test]
    fn typ_wird_auf_das_muster_gebracht() {
        assert_eq!(typ_normalisieren(" Application/PDF "), "application/pdf");
        assert_eq!(typ_normalisieren("application/vnd.oasis+xml"), "application/vnd.oasis+xml");
        assert_eq!(typ_normalisieren("text/plain; charset=utf-8"), "text/plain");
    }

    #[test]
    fn typ_ausserhalb_des_musters_wird_octet_stream() {
        for schlecht in [
            "",
            "image",
            "/png",
            "image/",
            "image/png/x",
            "image/p ng",
            "application/x\n[1790] eingeschleust",
            "application/x\u{7f}",
            "anwendung/ä",
        ] {
            assert_eq!(typ_normalisieren(&schlecht), OCTET_STREAM, "{:?}", schlecht);
        }
        let lang = format!("application/{}", "x".repeat(100));
        assert_eq!(typ_normalisieren(&lang), OCTET_STREAM);
        let genau = format!("application/{}", "x".repeat(100 - 12));
        assert_eq!(typ_normalisieren(&genau), genau, "100 Zeichen gehen noch");
    }

    #[test]
    fn fremder_typ_ohne_familie_wird_normalisiert_gespeichert() {
        assert_eq!(empfangener_typ("application/x\nzeile", b"\0"), OCTET_STREAM);
        assert_eq!(typ_familie("application/pdf"), "other");
        assert_eq!(typ_familie("image/png"), "image");
    }

    #[test]
    fn ogg_mp4_und_webm_zaehlen_fuer_ton_und_bild() {
        for daten in [&b"OggS\0\x02"[..], b"\0\0\0\x18ftypmp42", b"\x1A\x45\xDF\xA3"] {
            assert_eq!(empfangener_typ("audio/x", daten), "audio/x");
            assert_eq!(empfangener_typ("video/x", daten), "video/x");
        }
    }

    #[test]
    fn text_der_wie_bmp_anfaengt_bleibt_text() {
        assert_eq!(empfangener_typ("text/plain", b"BMW faehrt"), "text/plain");
    }

    #[test]
    fn andere_typen_bleiben_unveraendert() {
        assert_eq!(empfangener_typ("application/pdf", b"\0\0"), "application/pdf");
        assert_eq!(empfangener_typ("application/octet-stream", PNG),
                   "application/octet-stream");
    }

    #[test]
    fn empfang_speichert_den_geprueften_typ() {
        let o = ordner("empfang");
        let mut s = speicher(&o);
        let typ = s.anhang_empfangen("a1", "image/jpeg", b"\0\0\0").unwrap();
        assert_eq!(typ, "application/octet-stream");
        let a = s.attachment("a1").unwrap();
        assert_eq!(a.content_type, "application/octet-stream");
        assert!(a.path.ends_with("a1.bin"), "{}", a.path);
        let typ = s.anhang_empfangen("a2", "image/png", PNG).unwrap();
        assert_eq!(typ, "image/png");
        assert!(s.attachment("a2").unwrap().path.ends_with("a2.png"));
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn endungen_zum_typ() {
        assert_eq!(endung("image/webp"), "webp");
        assert_eq!(endung("audio/ogg"), "oga");
        assert_eq!(endung("video/mp4"), "mp4");
        assert_eq!(endung("video/x-matroska"), "mkv");
        assert_eq!(endung("application/pdf"), "pdf");
        assert_eq!(endung("text/plain; charset=utf-8"), "txt");
        assert_eq!(endung("application/octet-stream"), "bin");
        assert_eq!(endung("../../x"), "bin");
    }

    // ---- M4: versiegelte Ablage ----

    #[test]
    fn ohne_passwort_klartext_wie_bisher() {
        let o = ordner("klartext");
        let mut s = speicher(&o);
        let pfad = s.store_attachment("a1", "image/png", PNG).unwrap();
        assert_eq!(std::fs::read(&pfad).unwrap(), PNG);
        assert!(!s.attachment("a1").unwrap().versiegelt);
        assert_eq!(s.anhang_pfad("a1").as_deref(), Some(pfad.as_str()));
        assert!(!laufzeit(&o).exists(), "keine Kopie ohne Passwort");
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn mit_passwort_liegt_kein_klartext_auf_der_platte() {
        let o = ordner("versiegelt");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "geheim").unwrap();
        let pfad = s.store_attachment("a1", "image/png", PNG).unwrap();
        assert!(pfad.ends_with("a1.png.siegel"), "{}", pfad);
        let roh = std::fs::read(&pfad).unwrap();
        assert!(!enthaelt(&roh, MUSTER));
        assert!(crate::tresor::ist_verschluesselt(&roh));
        assert!(!o.join("attachments").join("a1.png").exists());
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn anhang_pfad_liefert_eine_lesbare_kopie() {
        let o = ordner("kopie");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "geheim").unwrap();
        s.store_attachment("a1", "image/png", PNG).unwrap();
        let kopie = s.anhang_pfad("a1").unwrap();
        assert!(kopie.starts_with(&*laufzeit(&o).to_string_lossy()), "{}", kopie);
        assert!(kopie.ends_with("a1.png"));
        assert_eq!(std::fs::read(&kopie).unwrap(), PNG);
        use std::os::unix::fs::PermissionsExt;
        let modus = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(modus(Path::new(&kopie)), 0o600);
        assert_eq!(modus(&laufzeit(&o)), 0o700);
        assert_eq!(s.anhang_pfad("gibtsnicht"), None);
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn nach_dem_leeren_kommt_die_kopie_wieder() {
        let o = ordner("leeren");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "geheim").unwrap();
        s.store_attachment("a1", "image/png", PNG).unwrap();
        let kopie = s.anhang_pfad("a1").unwrap();
        s.anhang_kopien_leeren();
        assert!(!Path::new(&kopie).exists(), "Kopie muss weg sein");
        assert_eq!(s.anhang_pfad("a1").as_deref(), Some(kopie.as_str()));
        assert_eq!(std::fs::read(&kopie).unwrap(), PNG);
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn fremder_laufzeitordner_wird_nicht_benutzt() {
        let o = ordner("verweis");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "geheim").unwrap();
        s.store_attachment("a1", "image/png", PNG).unwrap();
        // Ein Verweis an der Stelle des Laufzeitordners, wie ihn ein anderer
        // unter /tmp legen koennte.
        let woanders = o.join("woanders");
        std::fs::create_dir_all(&woanders).unwrap();
        std::fs::create_dir_all(o.join("lauf")).unwrap();
        std::os::unix::fs::symlink(&woanders, laufzeit(&o)).unwrap();
        assert_eq!(s.anhang_pfad("a1"), None);
        assert!(std::fs::read_dir(&woanders).unwrap().next().is_none());
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn passwort_setzen_versiegelt_vorhandene_anhaenge() {
        let o = ordner("umwandeln");
        let mut s = speicher(&o);
        let klar = s.store_attachment("a1", "image/png", PNG).unwrap();
        s.passwort_setzen(None, "geheim").unwrap();
        assert!(!Path::new(&klar).exists(), "Klartext muss weg sein");
        let a = s.attachment("a1").unwrap().clone();
        assert!(a.versiegelt);
        assert!(a.path.ends_with(".siegel"));
        assert!(!enthaelt(&std::fs::read(&a.path).unwrap(), MUSTER));
        assert_eq!(std::fs::read(s.anhang_pfad("a1").unwrap()).unwrap(), PNG);
        // Der Pfad ist auch im gespeicherten Zustand fortgeschrieben.
        drop(s);
        let s = mit_passwort(&o, "geheim");
        assert_eq!(s.attachment("a1").unwrap().path, a.path);
        assert_eq!(std::fs::read(s.anhang_pfad("a1").unwrap()).unwrap(), PNG);
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn passwort_entfernen_wandelt_zurueck() {
        let o = ordner("zurueck");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "geheim").unwrap();
        let siegelpfad = s.store_attachment("a1", "image/png", PNG).unwrap();
        let kopie = s.anhang_pfad("a1").unwrap();
        s.passwort_setzen(Some("geheim"), "").unwrap();
        assert!(!Path::new(&siegelpfad).exists(), ".siegel muss weg sein");
        assert!(!Path::new(&kopie).exists(), "Kopie muss weg sein");
        let a = s.attachment("a1").unwrap();
        assert!(!a.versiegelt);
        assert!(a.path.ends_with("a1.png"));
        assert_eq!(std::fs::read(&a.path).unwrap(), PNG);
        assert_eq!(s.anhang_pfad("a1").as_deref(), Some(a.path.as_str()));
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn passwortwechsel_schreibt_den_kopf_der_anhaenge_neu() {
        // Sonst holte das alte Passwort den Speicherschluessel aus jeder
        // Anhangsdatei.
        let o = ordner("wechsel");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "alt").unwrap();
        let pfad = s.store_attachment("a1", "image/png", PNG).unwrap();
        s.passwort_setzen(Some("alt"), "neu").unwrap();
        let roh = std::fs::read(&pfad).unwrap();
        assert!(crate::tresor::Siegel::oeffnen(&roh, "alt").is_err());
        assert_eq!(crate::tresor::Siegel::oeffnen(&roh, "neu").unwrap().0, PNG);
        assert_eq!(std::fs::read(s.anhang_pfad("a1").unwrap()).unwrap(), PNG);
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn scheitert_eine_umlegung_bleibt_das_alte_passwort() {
        let o = ordner("wechsel-scheitert");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "alt").unwrap();
        let gut = s.store_attachment("a1", "image/png", PNG).unwrap();
        let kaputt = s.store_attachment("a2", "image/png", PNG).unwrap();
        std::fs::write(&kaputt, b"kein Siegel").unwrap();
        s.save().unwrap();
        assert!(s.passwort_setzen(Some("alt"), "neu").is_err());
        assert!(s.passwort_stimmt("alt"), "das alte gilt weiter");
        assert!(!s.passwort_stimmt("neu"));
        // Die gute Datei traegt weiter das alte Paket, keine halbe Lage.
        let roh = std::fs::read(&gut).unwrap();
        assert!(crate::tresor::Siegel::oeffnen(&roh, "alt").is_ok());
        assert!(crate::tresor::Siegel::oeffnen(&roh, "neu").is_err());
        let reste: Vec<_> = std::fs::read_dir(o.join("attachments"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".neu"))
            .collect();
        assert!(reste.is_empty(), "keine vorbereiteten Dateien bleiben liegen");
        // Und auch auf der Platte: der Zustand oeffnet mit dem alten.
        drop(s);
        let s = mit_passwort(&o, "alt");
        assert_eq!(s.attachment("a1").unwrap().path, gut);
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn gesperrt_gibt_anhang_pfad_nichts_her() {
        let o = ordner("gesperrt");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "geheim").unwrap();
        s.store_attachment("a1", "image/png", PNG).unwrap();
        assert_eq!(s.anhang_pfad_wenn("a1", true), None);
        assert!(!laufzeit(&o).join("a1.png").exists(), "und legt keine Kopie an");
        assert!(s.anhang_pfad_wenn("a1", false).is_some(), "entsperrt wieder");
        let _ = std::fs::remove_dir_all(&o);
    }

    /// Ohne Passwort gibt es keine Kopie, aber hinter der Sperre auch den
    /// Pfad der Datei selbst nicht.
    #[test]
    fn gesperrt_gilt_auch_ohne_siegel() {
        let o = ordner("gesperrt-klar");
        let mut s = speicher(&o);
        s.store_attachment("a1", "image/png", PNG).unwrap();
        assert_eq!(s.anhang_pfad_wenn("a1", true), None);
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn unlesbarer_zustand_zitiert_keine_werte() {
        let o = ordner("zitat");
        let p = o.join("state.json");
        std::fs::write(&p, r#"{"identity": "GEHEIMER-NAME"}"#).unwrap();
        let fehler = match Store::open(&p, 7327) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("darf nicht oeffnen"),
        };
        // Mit BRIAR_LOG_VOLL=1 in der Umgebung steht der volle Text da --
        // so gewollt; dann gibt es hier nichts zu pruefen.
        if !crate::net::log_voll() {
            assert!(fehler.contains("state does not parse"), "{}", fehler);
            assert!(!fehler.contains("GEHEIMER-NAME"), "{}", fehler);
        }
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn anhang_loeschen_raeumt_alle_drei_orte() {
        let o = ordner("loeschen");
        let mut s = speicher(&o);
        s.passwort_setzen(None, "geheim").unwrap();
        let siegelpfad = s.store_attachment("a1", "image/png", PNG).unwrap();
        let kopie = s.anhang_pfad("a1").unwrap();
        // Ein Klartext-Rest daneben, wie ihn ein abgebrochenes Umlegen
        // hinterlaesst.
        let rest = o.join("attachments").join("a1.png");
        std::fs::write(&rest, PNG).unwrap();
        s.anhang_loeschen("a1");
        assert!(!Path::new(&siegelpfad).exists());
        assert!(!Path::new(&kopie).exists());
        assert!(!rest.exists());
        assert!(s.attachment("a1").is_none());
        assert_eq!(s.anhang_pfad("a1"), None);
        let _ = std::fs::remove_dir_all(&o);
    }

    /// Ein Stand von vor dieser Fassung: ein Anhang ohne das Feld
    /// `versiegelt`, die Datei im Klartext daneben.
    fn alter_stand(o: &Path) -> PathBuf {
        let dir = o.join("attachments");
        std::fs::create_dir_all(&dir).unwrap();
        let datei = dir.join("a1.png");
        std::fs::write(&datei, PNG).unwrap();
        // Ein frischer Zustand, dem der Anhangseintrag in der alten Form
        // (ohne `versiegelt`) von Hand eingesetzt wird.
        let p = o.join("state.json");
        Store::open(&p, 7327).unwrap().save().unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        json["attachments"] = serde_json::json!({
            "a1": {"content_type": "image/png", "path": datei, "size": PNG.len()}
        });
        std::fs::write(&p, json.to_string()).unwrap();
        datei
    }

    #[test]
    fn alter_stand_mit_klartext_laedt() {
        let o = ordner("altbestand");
        let datei = alter_stand(&o);
        let s = speicher(&o);
        let a = s.attachment("a1").unwrap();
        assert!(!a.versiegelt);
        assert_eq!(s.anhang_pfad("a1").unwrap(), datei.to_string_lossy());
        assert_eq!(std::fs::read(&datei).unwrap(), PNG);
        let _ = std::fs::remove_dir_all(&o);
    }

    #[test]
    fn alter_klartext_wird_beim_oeffnen_mit_passwort_versiegelt() {
        let o = ordner("nachholen");
        let datei = alter_stand(&o);
        let s = mit_passwort(&o, "geheim");
        assert!(!datei.exists(), "Klartext muss weg sein");
        let a = s.attachment("a1").unwrap();
        assert!(a.versiegelt);
        assert!(!enthaelt(&std::fs::read(&a.path).unwrap(), MUSTER));
        assert_eq!(std::fs::read(s.anhang_pfad("a1").unwrap()).unwrap(), PNG);
        // Und der Zustand ist gespeichert -- verschluesselt, mit neuem Pfad.
        let pfad = a.path.clone();
        drop(s);
        assert!(Store::ist_verschluesselt(&o.join("state.json")));
        let s = mit_passwort(&o, "geheim");
        assert_eq!(s.attachment("a1").unwrap().path, pfad);
        let _ = std::fs::remove_dir_all(&o);
    }
}
