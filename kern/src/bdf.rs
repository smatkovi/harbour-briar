//! BDF, the Briar Data Format (bramble-core/data).
//!
//! Type bytes and the canonical ordering of dictionary keys are taken from
//! BdfWriterImpl/BdfReaderImpl -- they are part of the wire format, because
//! message identifiers are hashes over these bytes.
//!
//! Der Leser ist so streng wie Briars kanonischer (BdfReaderImpl mit
//! canonical = true, so erzeugt ihn BdfReaderFactoryImpl): Ganzzahlen und
//! Laengen in der kleinsten Form, Woerterbuchschluessel streng aufsteigend,
//! hoechstens fuenf Ebenen, hoechstens 64 KiB je Zeichenkette oder Rohfolge,
//! UTF-8 streng, und `from_bytes` nimmt keine Bytes hinter dem Wert an. Was
//! Briar verwirft, verwerfen wir auch -- sonst naehmen wir Nachrichten an,
//! die Briar-Geraete nicht weitergeben, und zeigten sie womoeglich anders.
//! Gleitkommazahlen prueft Briar nicht (readDouble), wir auch nicht.

use std::collections::BTreeMap;
use std::io::{Read, Write};

const NULL: u8 = 0x00;
const FALSE: u8 = 0x10;
const TRUE: u8 = 0x11;
const INT_8: u8 = 0x21;
const INT_16: u8 = 0x22;
const INT_32: u8 = 0x24;
const INT_64: u8 = 0x28;
const FLOAT_64: u8 = 0x38;
const STRING_8: u8 = 0x41;
const STRING_16: u8 = 0x42;
const STRING_32: u8 = 0x44;
const RAW_8: u8 = 0x51;
const RAW_16: u8 = 0x52;
const RAW_32: u8 = 0x54;
const LIST: u8 = 0x60;
const DICTIONARY: u8 = 0x70;
const END: u8 = 0x80;

/// Die groesste Zeichenkette oder Rohfolge, die der Leser annimmt -- Briars
/// BdfReader.DEFAULT_MAX_BUFFER_SIZE. Sicherheitsbefund H1: die 8- und
/// 16-Bit-Laengen wurden vorzeichenbehaftet gelesen, 0xff wurde zu usize::MAX
/// und `vec![0; len]` zum Panic; mit panic = "abort" starb der ganze Dienst
/// an einem Byte von einem Kontakt oder aus einem QR-Code. Briar wirft hier
/// eine FormatException und verwirft nur die Nachricht -- wir jetzt auch.
const MAX_LAENGE: usize = 64 * 1024;
/// So tief duerfen Listen und Woerterbuecher verschachtelt sein -- Briars
/// BdfReader.DEFAULT_NESTED_LIMIT.
const MAX_TIEFE: usize = 5;

#[derive(Clone, Debug, PartialEq)]
pub enum Bdf {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Raw(Vec<u8>),
    List(Vec<Bdf>),
    /// Eine BTreeMap, weil der Schreiber die Schluessel geordnet ausgeben
    /// muss -- in UTF-16-Ordnung, siehe `write`.
    Dict(BTreeMap<String, Bdf>),
}

impl Bdf {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Bdf::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Bdf::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_raw(&self) -> Option<&[u8]> {
        match self {
            Bdf::Raw(r) => Some(r),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<Bdf>> {
        match self {
            Bdf::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<String, Bdf>> {
        match self {
            Bdf::Dict(d) => Some(d),
            _ => None,
        }
    }

    pub fn list(items: Vec<Bdf>) -> Bdf {
        Bdf::List(items)
    }

    pub fn dict(entries: Vec<(&str, Bdf)>) -> Bdf {
        let mut m = BTreeMap::new();
        for (k, v) in entries {
            m.insert(k.to_string(), v);
        }
        Bdf::Dict(m)
    }
}

pub fn write(out: &mut impl Write, value: &Bdf) -> std::io::Result<()> {
    match value {
        Bdf::Null => out.write_all(&[NULL]),
        Bdf::Bool(b) => out.write_all(&[if *b { TRUE } else { FALSE }]),
        Bdf::Int(i) => write_int(out, *i),
        Bdf::Float(f) => {
            out.write_all(&[FLOAT_64])?;
            let mut b = [0u8; 8];
            crate::util::write_u64(&mut b, f.to_bits());
            out.write_all(&b)
        }
        Bdf::Str(s) => {
            let b = s.as_bytes();
            write_length_prefixed(out, b, STRING_8, STRING_16, STRING_32)
        }
        Bdf::Raw(r) => write_length_prefixed(out, r, RAW_8, RAW_16, RAW_32),
        Bdf::List(items) => {
            out.write_all(&[LIST])?;
            for item in items {
                write(out, item)?;
            }
            out.write_all(&[END])
        }
        Bdf::Dict(entries) => {
            out.write_all(&[DICTIONARY])?;
            // Die BTreeMap ordnet nach Bytes, also nach Codepunkten; Briar
            // ordnet nach Java-Strings, also nach UTF-16-Einheiten
            // (BdfWriterImpl.writeDictionary ueber eine TreeMap). Die beiden
            // weichen nur ab, wenn ein Zeichen ausserhalb der BMP (Surrogat
            // 0xD800..) auf eines zwischen U+E000 und U+FFFF trifft -- dann
            // wuerde Briars kanonischer Leser unser Woerterbuch verwerfen.
            let mut sortiert: Vec<(&String, &Bdf)> = entries.iter().collect();
            sortiert.sort_by(|a, b| utf16_ordnung(a.0, b.0));
            for (k, v) in sortiert {
                write(out, &Bdf::Str(k.clone()))?;
                write(out, v)?;
            }
            out.write_all(&[END])
        }
    }
}

/// Die Reihenfolge von Java's `String.compareTo`: lexikographisch ueber die
/// UTF-16-Einheiten.
fn utf16_ordnung(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_int(out: &mut impl Write, i: i64) -> std::io::Result<()> {
    if i >= i8::MIN as i64 && i <= i8::MAX as i64 {
        out.write_all(&[INT_8, i as u8])
    } else if i >= i16::MIN as i64 && i <= i16::MAX as i64 {
        let mut b = [0u8; 2];
        crate::util::write_u16(&mut b, i as i16 as u16);
        out.write_all(&[INT_16])?;
        out.write_all(&b)
    } else if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
        let mut b = [0u8; 4];
        crate::util::write_u32(&mut b, i as i32 as u32);
        out.write_all(&[INT_32])?;
        out.write_all(&b)
    } else {
        let mut b = [0u8; 8];
        crate::util::write_u64(&mut b, i as u64);
        out.write_all(&[INT_64])?;
        out.write_all(&b)
    }
}

fn write_length_prefixed(
    out: &mut impl Write,
    b: &[u8],
    t8: u8,
    t16: u8,
    t32: u8,
) -> std::io::Result<()> {
    if b.len() <= i8::MAX as usize {
        out.write_all(&[t8, b.len() as u8])?;
    } else if b.len() <= i16::MAX as usize {
        let mut l = [0u8; 2];
        crate::util::write_u16(&mut l, b.len() as u16);
        out.write_all(&[t16])?;
        out.write_all(&l)?;
    } else {
        let mut l = [0u8; 4];
        crate::util::write_u32(&mut l, b.len() as u32);
        out.write_all(&[t32])?;
        out.write_all(&l)?;
    }
    out.write_all(b)
}

pub fn to_bytes(value: &Bdf) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out, value).expect("writing to a Vec cannot fail");
    out
}

pub struct Reader<R: Read> {
    inner: R,
    peeked: Option<u8>,
    /// Wie tief wir gerade in Listen und Woerterbuechern stecken.
    tiefe: usize,
}

impl<R: Read> Reader<R> {
    pub fn new(inner: R) -> Self {
        Reader {
            inner,
            peeked: None,
            tiefe: 0,
        }
    }

    /// Eine Ebene hinein -- Briars BdfReaderImpl: `if (++level > nestedLimit)
    /// throw new FormatException()`.
    fn hinein(&mut self) -> std::io::Result<()> {
        self.tiefe += 1;
        if self.tiefe > MAX_TIEFE {
            return Err(bad("BDF nested too deeply"));
        }
        Ok(())
    }

    fn read_byte(&mut self) -> std::io::Result<u8> {
        if let Some(b) = self.peeked.take() {
            return Ok(b);
        }
        let mut b = [0u8; 1];
        self.inner.read_exact(&mut b)?;
        Ok(b[0])
    }

    fn peek(&mut self) -> std::io::Result<u8> {
        if self.peeked.is_none() {
            self.peeked = Some(self.read_byte()?);
        }
        Ok(self.peeked.unwrap())
    }

    fn read_exact_vec(&mut self, len: usize) -> std::io::Result<Vec<u8>> {
        let mut v = vec![0u8; len];
        if len > 0 {
            if let Some(b) = self.peeked.take() {
                v[0] = b;
                self.inner.read_exact(&mut v[1..])?;
            } else {
                self.inner.read_exact(&mut v)?;
            }
        }
        Ok(v)
    }

    pub fn read(&mut self) -> std::io::Result<Bdf> {
        let t = self.read_byte()?;
        self.read_with_type(t)
    }

    fn read_with_type(&mut self, t: u8) -> std::io::Result<Bdf> {
        match t {
            NULL => Ok(Bdf::Null),
            FALSE => Ok(Bdf::Bool(false)),
            TRUE => Ok(Bdf::Bool(true)),
            INT_8 => Ok(Bdf::Int(self.read_byte()? as i8 as i64)),
            // Briar liest kanonisch (BdfReaderImpl.readInt16/32/64 mit
            // canonical = true): ein Wert, der in die naechstkleinere Form
            // gepasst haette, ist ein Formfehler. Sonst haette dieselbe Zahl
            // mehrere Kodierungen und dieselbe Nachricht mehrere Kennungen.
            INT_16 => {
                let b = self.read_exact_vec(2)?;
                let v = crate::util::read_u16(&b) as i16 as i64;
                if (i8::MIN as i64..=i8::MAX as i64).contains(&v) {
                    return Err(bad("BDF INT_16 is not canonical"));
                }
                Ok(Bdf::Int(v))
            }
            INT_32 => {
                let b = self.read_exact_vec(4)?;
                let v = ((b[0] as u32) << 24)
                    | ((b[1] as u32) << 16)
                    | ((b[2] as u32) << 8)
                    | b[3] as u32;
                let v = v as i32 as i64;
                if (i16::MIN as i64..=i16::MAX as i64).contains(&v) {
                    return Err(bad("BDF INT_32 is not canonical"));
                }
                Ok(Bdf::Int(v))
            }
            INT_64 => {
                let b = self.read_exact_vec(8)?;
                let v = crate::util::read_u64(&b) as i64;
                if (i32::MIN as i64..=i32::MAX as i64).contains(&v) {
                    return Err(bad("BDF INT_64 is not canonical"));
                }
                Ok(Bdf::Int(v))
            }
            FLOAT_64 => {
                let b = self.read_exact_vec(8)?;
                Ok(Bdf::Float(f64::from_bits(crate::util::read_u64(&b))))
            }
            STRING_8 | STRING_16 | STRING_32 => {
                let len = self.read_length(t, STRING_8, STRING_16)?;
                let b = self.read_exact_vec(len)?;
                String::from_utf8(b)
                    .map(Bdf::Str)
                    .map_err(|_| bad("string is not UTF-8"))
            }
            RAW_8 | RAW_16 | RAW_32 => {
                let len = self.read_length(t, RAW_8, RAW_16)?;
                Ok(Bdf::Raw(self.read_exact_vec(len)?))
            }
            LIST => {
                self.hinein()?;
                let mut items = Vec::new();
                loop {
                    let t = self.read_byte()?;
                    if t == END {
                        self.tiefe -= 1;
                        return Ok(Bdf::List(items));
                    }
                    items.push(self.read_with_type(t)?);
                }
            }
            DICTIONARY => {
                self.hinein()?;
                let mut m = std::collections::BTreeMap::new();
                // Briars readDictionary: Schluessel streng aufsteigend nach
                // String.compareTo, also auch keine doppelten. Frueher
                // ueberschrieb ein zweiter gleicher Schluessel still den
                // ersten -- Briar verwirft so etwas.
                let mut voriger: Option<String> = None;
                loop {
                    let t = self.read_byte()?;
                    if t == END {
                        self.tiefe -= 1;
                        return Ok(Bdf::Dict(m));
                    }
                    let key = match self.read_with_type(t)? {
                        Bdf::Str(s) => s,
                        _ => return Err(bad("dictionary key is not a string")),
                    };
                    if let Some(v) = &voriger {
                        if utf16_ordnung(&key, v) != std::cmp::Ordering::Greater {
                            return Err(bad("BDF dictionary keys not sorted and unique"));
                        }
                    }
                    let value = self.read()?;
                    voriger = Some(key.clone());
                    m.insert(key, value);
                }
            }
            _ => Err(bad("unknown BDF type")),
        }
    }

    /// Die Laenge einer Zeichenkette oder Rohfolge, geprueft BEVOR etwas
    /// zugeteilt wird -- und zwar mit genau Briars Bereichen: Briar liest sie
    /// vorzeichenbehaftet und kanonisch (BdfReaderImpl.readInt8/16/32 mit
    /// canonical = true), also 8 Bit nur 0..127, 16 Bit nur 128..32767,
    /// 32 Bit nur ab 32768, und alles ueber maxBufferSize ist ein
    /// Formfehler. Was Briar verwirft, verwerfen wir auch; unser Schreiber
    /// (write_length_prefixed) ist ohnehin kanonisch.
    fn read_length(&mut self, t: u8, t8: u8, t16: u8) -> std::io::Result<usize> {
        let len = if t == t8 {
            let v = self.read_byte()? as usize;
            if v > 127 {
                return Err(bad("BDF 8-bit length is negative"));
            }
            v
        } else if t == t16 {
            let b = self.read_exact_vec(2)?;
            let v = crate::util::read_u16(&b) as usize;
            if !(128..=32767).contains(&v) {
                return Err(bad("BDF 16-bit length is not canonical"));
            }
            v
        } else {
            let b = self.read_exact_vec(4)?;
            let v = ((b[0] as u32) << 24)
                | ((b[1] as u32) << 16)
                | ((b[2] as u32) << 8)
                | b[3] as u32;
            if v < 32768 {
                return Err(bad("BDF 32-bit length is not canonical"));
            }
            v as usize
        };
        if len > MAX_LAENGE {
            return Err(bad("BDF length exceeds 64 KiB"));
        }
        Ok(len)
    }

    /// True if the stream has no more bytes.
    pub fn at_eof(&mut self) -> bool {
        self.peek().is_err()
    }

    /// How many bytes the reader has taken from the stream but not used --
    /// needed when data follows the encoded value, as in an attachment.
    pub fn buffered(&self) -> usize {
        if self.peeked.is_some() {
            1
        } else {
            0
        }
    }
}

fn bad(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

/// Genau ein Wert und nichts dahinter. Briar prueft das ueberall, wo ein
/// Rumpf gelesen wird (ClientHelperImpl.toList: `if (!reader.eof()) throw
/// new FormatException()`, ebenso PayloadParserImpl.parse fuer den QR-Code):
/// angehaengte Bytes gingen sonst nicht in die Pruefung ein, lagen aber in
/// der Nachrichtenkennung.
pub fn from_bytes(b: &[u8]) -> std::io::Result<Bdf> {
    let mut r = Reader::new(b);
    let v = r.read()?;
    if !r.at_eof() {
        return Err(bad("bytes after the BDF value"));
    }
    Ok(v)
}

/// Ein Wert am Anfang, der Rest bleibt ungelesen -- nur fuer Anhaenge, deren
/// Daten hinter der Beschreibung stehen (sync::attachment_body).
pub fn from_bytes_prefix(b: &[u8]) -> std::io::Result<Bdf> {
    Reader::new(b).read()
}
