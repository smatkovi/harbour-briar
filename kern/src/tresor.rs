//! Den Speicher verschluesseln, wie Briar es tut.
//!
//! Briar leitet aus dem Passwort des Anwenders mit scrypt einen Schluessel ab
//! (`encryptWithPassword` in CryptoComponentImpl: zufaelliges 32-Byte-Salz,
//! kalibrierte Kosten, danach XSalsa20-Poly1305), haertet ihn auf Android mit
//! dem Hardware-Keystore nach -- `if (keyStrengthener != null)`, also
//! ausdruecklich optional -- und verschluesselt damit den
//! Datenbankschluessel. Wer das Geraet in die Hand bekommt, hat ohne Passwort
//! nichts.
//!
//! Unser Speicher lag bisher als Klartext-JSON da, mit dem privaten
//! Handschlagschluessel, dem Signatursamen, je Kontakt dem gemeinsamen
//! Hauptschluessel, dem Onion-Schluessel und allen Nachrichten darin.
//!
//! Das Dateiformat ist **nicht** Briars -- es muss es nicht sein, der Speicher
//! ist rein oertlich. Es hat nur dieselben Eigenschaften.

// Die Chiffre ist dieselbe, die Briar fuer seine Stroeme benutzt, und sie ist
// bei uns gegen Briars echte Klassen geprueft -- kein zweiter Nachbau.
use crate::crypto::{secretbox_decrypt, secretbox_encrypt};

/// Steht am Anfang jeder verschluesselten Datei. Fehlt es, ist die Datei ein
/// Klartext-JSON aus einer Fassung vor der Verschluesselung -- die wird
/// weiterhin gelesen und beim naechsten Speichern mit Passwort umgestellt.
pub const MAGIE: &[u8; 8] = b"BRIARTR2";

const SALZ_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const MAC_BYTES: usize = 16;
/// Der eingepackte Speicherschluessel: 32 Byte Schluessel plus Beglaubigung.
const PAKET_BYTES: usize = 32 + MAC_BYTES;

/// scrypt-Kosten fuer ein **neues** Siegel. Briar kalibriert sie am Geraet;
/// wir nehmen einen festen, fuer ein Telefon von 2011 noch tragbaren Wert und
/// schreiben ihn mit, damit eine spaetere Fassung ihn erhoehen kann, ohne alte
/// Dateien unlesbar zu machen.
///
/// Ein erhoehter Wert wirkt erst beim naechsten Passwortwechsel: beim
/// Speichern gelten die Kosten, die in der Datei stehen, denn abgeleitet wird
/// dabei nichts mehr. Genau darum bleiben aeltere Dateien lesbar.
const LOG_N: u8 = 14;
const R: u32 = 8;
const P: u32 = 1;

/// Ist diese Datei verschluesselt?
pub fn ist_verschluesselt(rohdaten: &[u8]) -> bool {
    rohdaten.len() > MAGIE.len() && &rohdaten[..MAGIE.len()] == MAGIE
}

/// Aus Passwort und Salz einen Schluessel ableiten. Der eine teure Schritt --
/// er gehoert an das Entsperren und an den Passwortwechsel, sonst nirgends.
fn aus_passwort(passwort: &str, salz: &[u8], log_n: u8, r: u32, p: u32)
    -> Result<[u8; 32], String>
{
    let parameter = scrypt::Params::new(log_n, r, p, 32)
        .map_err(|e| format!("scrypt-Parameter: {}", e))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(passwort.as_bytes(), salz, &parameter, &mut key)
        .map_err(|e| format!("scrypt: {}", e))?;
    Ok(key)
}

/// Ein frischer Speicherschluessel. Er aendert sich nie wieder -- ein
/// Passwortwechsel packt ihn nur neu ein.
fn neuer_speicherschluessel() -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&crate::util::random(32));
    k
}

/// Den Speicherschluessel aus seinem Paket holen. Das ist der Schritt, der ein
/// Passwort prueft -- die Beglaubigung schlaegt bei einem falschen fehl.
fn auspacken(paket: &[u8], passwort: &str, salz: &[u8], log_n: u8, r: u32, p: u32)
    -> Result<[u8; 32], String>
{
    let wickel = aus_passwort(passwort, salz, log_n, r, p)?;
    // Das Paket braucht seine eigene Nonce nicht, aber nur so lange diese
    // Regel gilt: ein Wickelschluessel verschluesselt genau einen Klartext,
    // genau einmal. Das Salz gehoert zu genau einem Passwort, und darunter
    // wird nie etwas anderes eingepackt als diese 32 Byte.
    let klar = secretbox_decrypt(&wickel, &[0u8; NONCE_BYTES], paket)
        .ok_or_else(|| "falsches Passwort oder beschaedigte Datei".to_string())?;
    if klar.len() != 32 {
        return Err("beschaedigter Speicherschluessel".to_string());
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&klar);
    Ok(k)
}

/// Was zum Schreiben der verschluesselten Datei noetig ist, beisammen und
/// schon abgeleitet: der ausgepackte Speicherschluessel und die Verpackung,
/// die unveraendert wieder in den Kopf der Datei kommt.
///
/// Der scrypt-Lauf gehoert zum Entsperren, nicht zum Speichern. Briar leitet
/// genau zweimal ab -- beim Oeffnen des Kontos und beim Passwortwechsel -- und
/// haelt danach den Datenbankschluessel im Speicher
/// (AccountManagerImpl.databaseKey). `store.save()` faellt dagegen bei jeder
/// Abgleichsrunde und jeder eingehenden Nachricht an; 16 MB scrypt je
/// Nachricht sind auf einem Telefon von 2011 nicht zu bezahlen.
///
/// Geheim ist hier nur der Speicherschluessel. Salz, Kosten und Paket stehen
/// so oder so in der Datei -- sie im Speicher zu halten gibt nichts preis. Der
/// Wickelschluessel aus dem Passwort wird ausdruecklich **nicht** behalten: er
/// wird zum Einpacken gebraucht, und das ist schon geschehen. Das Passwort
/// selbst wird gar nicht erst aufbewahrt.
///
/// Absichtlich ohne Clone und ohne Debug: der Schluessel soll sich nicht
/// vervielfaeltigen und nicht in einer Fehlerzeile landen.
pub struct Siegel {
    speicherschluessel: [u8; 32],
    log_n: u8,
    r: u32,
    p: u32,
    salz: [u8; SALZ_BYTES],
    /// Der mit dem Passwort eingepackte Speicherschluessel, fertig fuer den
    /// Kopf der Datei.
    paket: Vec<u8>,
}

impl Siegel {
    /// Ein Siegel fuer ein neu gesetztes Passwort: frischer
    /// Speicherschluessel, frisches Salz, ein scrypt-Lauf.
    pub fn frisch(passwort: &str) -> Result<Siegel, String> {
        Self::einpacken(neuer_speicherschluessel(), passwort)
    }

    /// Dasselbe Siegel unter einem neuen Passwort -- der Speicherschluessel
    /// bleibt, das Salz ist neu. Deshalb kostet ein Passwortwechsel 32 Byte
    /// und nicht den ganzen Speicher, wie bei Briar
    /// (AccountManagerImpl.changePassword).
    pub fn neu_verpacken(&self, passwort: &str) -> Result<Siegel, String> {
        Self::einpacken(self.speicherschluessel, passwort)
    }

    /// Stimmt dieses Passwort zu dieser Datei? Kostet einen scrypt-Lauf und
    /// hat deshalb nur beim Passwortwechsel etwas zu suchen.
    pub fn stimmt(&self, passwort: &str) -> bool {
        auspacken(&self.paket, passwort, &self.salz, self.log_n, self.r, self.p).is_ok()
    }

    fn einpacken(speicherschluessel: [u8; 32], passwort: &str) -> Result<Siegel, String> {
        let mut salz = [0u8; SALZ_BYTES];
        salz.copy_from_slice(&crate::util::random(SALZ_BYTES));
        let wickel = aus_passwort(passwort, &salz, LOG_N, R, P)?;
        // Zur Null-Nonce siehe auspacken(): dieses Salz gehoert zu diesem
        // Passwort, und darunter wird genau einmal genau dieser Klartext
        // eingepackt.
        let paket = secretbox_encrypt(&wickel, &[0u8; NONCE_BYTES], &speicherschluessel);
        Ok(Siegel { speicherschluessel, log_n: LOG_N, r: R, p: P, salz, paket })
    }

    /// Die Datei aufmachen: ein scrypt-Lauf, danach liegen Inhalt und Siegel
    /// da. Das ist der Schritt, der das Passwort prueft.
    pub fn oeffnen(rohdaten: &[u8], passwort: &str) -> Result<(Vec<u8>, Siegel), String> {
        let (log_n, r, p, salz, paket, nonce, geheim) = zerlegen(rohdaten)?;
        let speicherschluessel = auspacken(&paket, passwort, &salz, log_n, r, p)?;
        let klar = secretbox_decrypt(&speicherschluessel, &nonce, &geheim)
            .ok_or_else(|| "beschaedigte Datei".to_string())?;
        // Kosten und Salz kommen aus der Datei, nicht aus den Konstanten: eine
        // aeltere Datei bleibt so lesbar und wird beim Speichern nicht
        // stillschweigend auf neue Kosten umgeschrieben.
        Ok((klar, Siegel { speicherschluessel, log_n, r, p, salz, paket }))
    }

    /// Schreiben. Hier laeuft **kein** scrypt: Salz, Kosten und Paket haengen
    /// am Passwort und nicht am Schreibvorgang und werden unveraendert wieder
    /// mitgeschrieben. Das Format bleibt Byte fuer Byte dasselbe -- BRIARTR2
    /// bleibt BRIARTR2.
    pub fn verschluesseln(&self, klartext: &[u8]) -> Vec<u8> {
        // Die Nonce muss dagegen jedes Mal neu sein. Der Speicherschluessel
        // aendert sich nie; zwei Staende der Datei unter demselben Schluessel
        // und derselben Nonce geben beide Klartexte preis -- XSalsa20 ist ein
        // Schluesselstrom, gleiche Nonce heisst gleicher Strom -- und dazu den
        // Poly1305-Schluessel, mit dem sich dann Faelschungen beglaubigen
        // lassen. 24 Byte aus dem Zufall des Systems sind genau der Zweck der
        // langen XSalsa20-Nonce; ein Zaehler muesste jeden Neustart
        // ueberleben.
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&crate::util::random(NONCE_BYTES));
        let geheim = secretbox_encrypt(&self.speicherschluessel, &nonce, klartext);

        let mut aus = Vec::with_capacity(
            MAGIE.len() + 9 + SALZ_BYTES + PAKET_BYTES + NONCE_BYTES + geheim.len());
        aus.extend_from_slice(MAGIE);
        aus.push(self.log_n);
        aus.extend_from_slice(&self.r.to_be_bytes());
        aus.extend_from_slice(&self.p.to_be_bytes());
        aus.extend_from_slice(&self.salz);
        aus.extend_from_slice(&self.paket);
        aus.extend_from_slice(&nonce);
        aus.extend_from_slice(&geheim);
        aus
    }
}

impl Drop for Siegel {
    /// Gesperrt ist bei uns dasselbe wie beendet, und dann soll der Schluessel
    /// nicht im Speicher liegen bleiben -- auf der N950 steht swappiness auf
    /// 80. Ohne die zeroize-Kiste bleibt das ein Versuch, deshalb volatil
    /// geschrieben: so wirft der Uebersetzer ihn nicht als toten Code weg.
    fn drop(&mut self) {
        for b in self.speicherschluessel.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

type Zerlegt = (u8, u32, u32, [u8; SALZ_BYTES], Vec<u8>, [u8; NONCE_BYTES], Vec<u8>);

fn zerlegen(rohdaten: &[u8]) -> Result<Zerlegt, String> {
    let kopf = MAGIE.len() + 9 + SALZ_BYTES + PAKET_BYTES + NONCE_BYTES;
    if rohdaten.len() < kopf || !ist_verschluesselt(rohdaten) {
        return Err("keine verschluesselte Datei".to_string());
    }
    let mut p = MAGIE.len();
    let log_n = rohdaten[p];
    p += 1;
    let r = u32::from_be_bytes(rohdaten[p..p + 4].try_into().unwrap());
    p += 4;
    let par_p = u32::from_be_bytes(rohdaten[p..p + 4].try_into().unwrap());
    p += 4;
    let mut salz = [0u8; SALZ_BYTES];
    salz.copy_from_slice(&rohdaten[p..p + SALZ_BYTES]);
    p += SALZ_BYTES;
    let paket = rohdaten[p..p + PAKET_BYTES].to_vec();
    p += PAKET_BYTES;
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&rohdaten[p..p + NONCE_BYTES]);
    p += NONCE_BYTES;
    Ok((log_n, r, par_p, salz, paket, nonce, rohdaten[p..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hin_und_zurueck() {
        let siegel = Siegel::frisch("geheim").unwrap();
        let inhalt = b"{\"identity\":{\"name\":\"Jolla\"}}";
        let datei = siegel.verschluesseln(inhalt);
        assert!(ist_verschluesselt(&datei));
        assert!(datei.windows(5).all(|f| f != b"Jolla"));
        let (klar, _) = Siegel::oeffnen(&datei, "geheim").unwrap();
        assert_eq!(klar, inhalt);
    }

    #[test]
    fn falsches_passwort_faellt_auf() {
        let siegel = Siegel::frisch("richtig").unwrap();
        let datei = siegel.verschluesseln(b"geheimer Inhalt");
        assert!(Siegel::oeffnen(&datei, "falsch").is_err());
        assert!(!siegel.stimmt("falsch"));
        assert!(siegel.stimmt("richtig"));
    }

    #[test]
    fn verfaelschte_datei_faellt_auf() {
        let siegel = Siegel::frisch("geheim").unwrap();
        let mut datei = siegel.verschluesseln(b"geheimer Inhalt");
        let letzte = datei.len() - 1;
        datei[letzte] ^= 1;
        assert!(Siegel::oeffnen(&datei, "geheim").is_err());
    }

    #[test]
    fn passwortwechsel_behaelt_den_speicherschluessel() {
        // Das ist der Punkt an Briars Aufbau: der Speicherschluessel aendert
        // sich nie, nur seine Verpackung. Ein Wechsel packt 32 Byte neu ein
        // und nicht den ganzen Speicher.
        let alt = Siegel::frisch("alt").unwrap();
        let datei = alt.verschluesseln(b"Inhalt");
        let neu = alt.neu_verpacken("neu").unwrap();
        let datei_neu = neu.verschluesseln(b"Inhalt");
        let (klar, _) = Siegel::oeffnen(&datei_neu, "neu").unwrap();
        assert_eq!(klar, b"Inhalt");
        assert!(Siegel::oeffnen(&datei_neu, "alt").is_err(), "altes darf nicht mehr gehen");
        // Und der alte Stand bleibt mit dem alten Passwort lesbar, denn der
        // Speicherschluessel darunter ist derselbe geblieben.
        assert!(Siegel::oeffnen(&datei, "alt").is_ok());
    }

    #[test]
    fn beim_schreiben_laeuft_kein_scrypt() {
        // Der eigentliche Zweck des Siegels. Gemessen wird nicht die Zeit --
        // die haengt am Build-Rechner --, sondern dass zwei Staende dieselbe
        // Verpackung tragen: Salz und Paket stehen ab Byte 17 bzw. 49.
        let siegel = Siegel::frisch("geheim").unwrap();
        let a = siegel.verschluesseln(b"erster Stand");
        let b = siegel.verschluesseln(b"zweiter Stand");
        let kopf = MAGIE.len() + 9;
        let bis = kopf + SALZ_BYTES + PAKET_BYTES;
        assert_eq!(a[kopf..bis], b[kopf..bis], "Salz und Paket muessen bleiben");
        // Die Nonce dagegen MUSS sich aendern: gleicher Schluessel und gleiche
        // Nonce gaeben beide Klartexte preis.
        assert_ne!(a[bis..bis + NONCE_BYTES], b[bis..bis + NONCE_BYTES]);
    }

    #[test]
    fn klartext_wird_als_solcher_erkannt() {
        assert!(!ist_verschluesselt(b"{\"identity\":null}"));
    }
}
