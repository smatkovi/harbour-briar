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

/// scrypt-Kosten. Briar kalibriert sie am Geraet; wir nehmen einen festen,
/// fuer ein Telefon von 2011 noch tragbaren Wert und schreiben ihn mit, damit
/// eine spaetere Fassung ihn erhoehen kann, ohne alte Dateien unlesbar zu
/// machen.
const LOG_N: u8 = 14;
const R: u32 = 8;
const P: u32 = 1;

/// Ist diese Datei verschluesselt?
pub fn ist_verschluesselt(rohdaten: &[u8]) -> bool {
    rohdaten.len() > MAGIE.len() && &rohdaten[..MAGIE.len()] == MAGIE
}

/// Aus Passwort und Salz einen Schluessel ableiten.
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
pub fn neuer_speicherschluessel() -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&crate::util::random(32));
    k
}

/// Den Speicherschluessel aus einer Datei holen. Das ist der Schritt, der ein
/// Passwort prueft -- die Beglaubigung schlaegt bei einem falschen fehl.
pub fn schluessel_holen(rohdaten: &[u8], passwort: &str) -> Result<[u8; 32], String> {
    let (log_n, r, p, salz, paket, _, _) = zerlegen(rohdaten)?;
    let wickel = aus_passwort(passwort, &salz, log_n, r, p)?;
    // Das Paket hat seine eigene Nonce nicht noetig: der Wickelschluessel
    // haengt schon an einem Salz, das nie wiederverwendet wird.
    let klar = secretbox_decrypt(&wickel, &[0u8; NONCE_BYTES], &paket)
        .ok_or_else(|| "falsches Passwort oder beschaedigte Datei".to_string())?;
    if klar.len() != 32 {
        return Err("beschaedigter Speicherschluessel".to_string());
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&klar);
    Ok(k)
}

/// Verschluesseln. Der Speicherschluessel wird mit dem Passwort eingepackt,
/// der Inhalt mit dem Speicherschluessel -- wie bei Briar. Ein
/// Passwortwechsel packt dann nur die 32 Byte neu ein und nicht den ganzen
/// Speicher.
pub fn verschluesseln(klartext: &[u8], passwort: &str, speicherschluessel: &[u8; 32])
    -> Result<Vec<u8>, String>
{
    let mut salz = [0u8; SALZ_BYTES];
    salz.copy_from_slice(&crate::util::random(SALZ_BYTES));
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&crate::util::random(NONCE_BYTES));

    let wickel = aus_passwort(passwort, &salz, LOG_N, R, P)?;
    let paket = secretbox_encrypt(&wickel, &[0u8; NONCE_BYTES], speicherschluessel);
    let geheim = secretbox_encrypt(speicherschluessel, &nonce, klartext);

    let mut aus = Vec::with_capacity(
        MAGIE.len() + 9 + SALZ_BYTES + PAKET_BYTES + NONCE_BYTES + geheim.len());
    aus.extend_from_slice(MAGIE);
    aus.push(LOG_N);
    aus.extend_from_slice(&R.to_be_bytes());
    aus.extend_from_slice(&P.to_be_bytes());
    aus.extend_from_slice(&salz);
    aus.extend_from_slice(&paket);
    aus.extend_from_slice(&nonce);
    aus.extend_from_slice(&geheim);
    Ok(aus)
}

/// Entschluesseln mit dem Passwort.
pub fn entschluesseln(rohdaten: &[u8], passwort: &str) -> Result<(Vec<u8>, [u8; 32]), String> {
    let schluessel = schluessel_holen(rohdaten, passwort)?;
    let (_, _, _, _, _, nonce, geheim) = zerlegen(rohdaten)?;
    let klar = secretbox_decrypt(&schluessel, &nonce, &geheim)
        .ok_or_else(|| "beschaedigte Datei".to_string())?;
    Ok((klar, schluessel))
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
        let k = neuer_speicherschluessel();
        let inhalt = b"{\"identity\":{\"name\":\"Jolla\"}}";
        let datei = verschluesseln(inhalt, "geheim", &k).unwrap();
        assert!(ist_verschluesselt(&datei));
        assert!(datei.windows(5).all(|f| f != b"Jolla"));
        let (klar, k2) = entschluesseln(&datei, "geheim").unwrap();
        assert_eq!(klar, inhalt);
        assert_eq!(k2, k);
    }

    #[test]
    fn falsches_passwort_faellt_auf() {
        let k = neuer_speicherschluessel();
        let datei = verschluesseln(b"geheimer Inhalt", "richtig", &k).unwrap();
        assert!(entschluesseln(&datei, "falsch").is_err());
        assert!(schluessel_holen(&datei, "falsch").is_err());
    }

    #[test]
    fn verfaelschte_datei_faellt_auf() {
        let k = neuer_speicherschluessel();
        let mut datei = verschluesseln(b"geheimer Inhalt", "geheim", &k).unwrap();
        let letzte = datei.len() - 1;
        datei[letzte] ^= 1;
        assert!(entschluesseln(&datei, "geheim").is_err());
    }

    #[test]
    fn passwortwechsel_behaelt_den_speicherschluessel() {
        // Das ist der Punkt an Briars Aufbau: der Speicherschluessel aendert
        // sich nie, nur seine Verpackung. Ein Wechsel packt 32 Byte neu ein
        // und nicht den ganzen Speicher.
        let k = neuer_speicherschluessel();
        let alt = verschluesseln(b"Inhalt", "alt", &k).unwrap();
        let geholt = schluessel_holen(&alt, "alt").unwrap();
        let neu = verschluesseln(b"Inhalt", "neu", &geholt).unwrap();
        let (klar, k2) = entschluesseln(&neu, "neu").unwrap();
        assert_eq!(klar, b"Inhalt");
        assert_eq!(k2, k, "der Speicherschluessel darf sich nicht aendern");
        assert!(entschluesseln(&neu, "alt").is_err(), "altes darf nicht mehr gehen");
    }

    #[test]
    fn klartext_wird_als_solcher_erkannt() {
        assert!(!ist_verschluesselt(b"{\"identity\":null}"));
    }
}
