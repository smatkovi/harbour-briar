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
pub const MAGIE: &[u8; 8] = b"BRIARTR1";

const SALZ_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;

/// scrypt-Kosten. Briar kalibriert sie am Geraet; wir nehmen einen festen,
/// fuer ein Telefon von 2011 noch tragbaren Wert und schreiben ihn mit, damit
/// eine spaetere Fassung ihn erhoehen kann, ohne alte Dateien unlesbar zu
/// machen. log_n = 14 heisst 16384 Runden, das sind auf dem N9 einige
/// Sekunden -- einmal beim Entsperren, nicht bei jedem Speichern.
const LOG_N: u8 = 14;
const R: u32 = 8;
const P: u32 = 1;

pub fn ist_verschluesselt(rohdaten: &[u8]) -> bool {
    rohdaten.len() > MAGIE.len() && &rohdaten[..MAGIE.len()] == MAGIE
}

/// Aus Passwort und Salz einen Schluessel ableiten.
fn schluessel(passwort: &str, salz: &[u8], log_n: u8, r: u32, p: u32)
    -> Result<[u8; 32], String>
{
    let parameter = scrypt::Params::new(log_n, r, p, 32)
        .map_err(|e| format!("scrypt-Parameter: {}", e))?;
    let mut key = [0u8; 32];
    scrypt::scrypt(passwort.as_bytes(), salz, &parameter, &mut key)
        .map_err(|e| format!("scrypt: {}", e))?;
    Ok(key)
}

/// Verschluesseln. Salz und Nonce sind je Aufruf frisch -- zweimal derselbe
/// Inhalt ergibt nie dieselbe Datei.
pub fn verschluesseln(klartext: &[u8], passwort: &str) -> Result<Vec<u8>, String> {
    let mut salz = [0u8; SALZ_BYTES];
    salz.copy_from_slice(&crate::util::random(SALZ_BYTES));
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    nonce_bytes.copy_from_slice(&crate::util::random(NONCE_BYTES));

    let key = schluessel(passwort, &salz, LOG_N, R, P)?;
    let geheim = secretbox_encrypt(&key, &nonce_bytes, klartext);

    let mut aus = Vec::with_capacity(8 + 1 + 8 + SALZ_BYTES + NONCE_BYTES + geheim.len());
    aus.extend_from_slice(MAGIE);
    aus.push(LOG_N);
    aus.extend_from_slice(&R.to_be_bytes());
    aus.extend_from_slice(&P.to_be_bytes());
    aus.extend_from_slice(&salz);
    aus.extend_from_slice(&nonce_bytes);
    aus.extend_from_slice(&geheim);
    Ok(aus)
}

/// Entschluesseln. Ein falsches Passwort und eine verfaelschte Datei sind
/// beide ein Fehler und nie ein stiller Ruecksturz auf einen leeren Zustand --
/// XSalsa20-Poly1305 ist beglaubigt, eine geaenderte Datei faellt auf.
pub fn entschluesseln(rohdaten: &[u8], passwort: &str) -> Result<Vec<u8>, String> {
    let kopf = MAGIE.len() + 1 + 8 + SALZ_BYTES + NONCE_BYTES;
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
    let salz = &rohdaten[p..p + SALZ_BYTES];
    p += SALZ_BYTES;
    let nonce = &rohdaten[p..p + NONCE_BYTES];
    p += NONCE_BYTES;
    let geheim = &rohdaten[p..];

    let key = schluessel(passwort, salz, log_n, r, par_p)?;
    secretbox_decrypt(&key, nonce, geheim)
        .ok_or_else(|| "falsches Passwort oder beschaedigte Datei".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hin_und_zurueck() {
        let inhalt = b"{\"identity\":{\"name\":\"Jolla\"}}";
        let datei = verschluesseln(inhalt, "geheim").unwrap();
        assert!(ist_verschluesselt(&datei));
        // Der Klartext darf nirgends mehr in der Datei stehen.
        assert!(datei.windows(5).all(|f| f != b"Jolla"));
        assert_eq!(entschluesseln(&datei, "geheim").unwrap(), inhalt);
    }

    #[test]
    fn falsches_passwort_faellt_auf() {
        let datei = verschluesseln(b"geheimer Inhalt", "richtig").unwrap();
        assert!(entschluesseln(&datei, "falsch").is_err());
    }

    #[test]
    fn verfaelschte_datei_faellt_auf() {
        let mut datei = verschluesseln(b"geheimer Inhalt", "geheim").unwrap();
        let letzte = datei.len() - 1;
        datei[letzte] ^= 1;
        assert!(entschluesseln(&datei, "geheim").is_err());
    }

    #[test]
    fn zweimal_dasselbe_ergibt_verschiedene_dateien() {
        let a = verschluesseln(b"gleich", "geheim").unwrap();
        let b = verschluesseln(b"gleich", "geheim").unwrap();
        assert_ne!(a, b, "Salz oder Nonce wiederholen sich");
        assert_eq!(entschluesseln(&a, "geheim").unwrap(),
                   entschluesseln(&b, "geheim").unwrap());
    }

    #[test]
    fn klartext_wird_als_solcher_erkannt() {
        assert!(!ist_verschluesselt(b"{\"identity\":null}"));
    }
}
