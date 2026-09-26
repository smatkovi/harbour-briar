//! BDF, the Briar Data Format (bramble-core/data).
//!
//! Type bytes and the canonical ordering of dictionary keys are taken from
//! BdfWriterImpl/BdfReaderImpl -- they are part of the wire format, because
//! message identifiers are hashes over these bytes.

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

#[derive(Clone, Debug, PartialEq)]
pub enum Bdf {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Raw(Vec<u8>),
    List(Vec<Bdf>),
    /// A BTreeMap, because the writer demands keys in sorted order.
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
            for (k, v) in entries {
                write(out, &Bdf::Str(k.clone()))?;
                write(out, v)?;
            }
            out.write_all(&[END])
        }
    }
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
}

impl<R: Read> Reader<R> {
    pub fn new(inner: R) -> Self {
        Reader { inner, peeked: None }
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
            INT_16 => {
                let b = self.read_exact_vec(2)?;
                Ok(Bdf::Int(crate::util::read_u16(&b) as i16 as i64))
            }
            INT_32 => {
                let b = self.read_exact_vec(4)?;
                let v = ((b[0] as u32) << 24)
                    | ((b[1] as u32) << 16)
                    | ((b[2] as u32) << 8)
                    | b[3] as u32;
                Ok(Bdf::Int(v as i32 as i64))
            }
            INT_64 => {
                let b = self.read_exact_vec(8)?;
                Ok(Bdf::Int(crate::util::read_u64(&b) as i64))
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
                let mut items = Vec::new();
                loop {
                    let t = self.read_byte()?;
                    if t == END {
                        return Ok(Bdf::List(items));
                    }
                    items.push(self.read_with_type(t)?);
                }
            }
            DICTIONARY => {
                let mut m = std::collections::BTreeMap::new();
                loop {
                    let t = self.read_byte()?;
                    if t == END {
                        return Ok(Bdf::Dict(m));
                    }
                    let key = match self.read_with_type(t)? {
                        Bdf::Str(s) => s,
                        _ => return Err(bad("dictionary key is not a string")),
                    };
                    let value = self.read()?;
                    m.insert(key, value);
                }
            }
            _ => Err(bad("unknown BDF type")),
        }
    }

    fn read_length(&mut self, t: u8, t8: u8, t16: u8) -> std::io::Result<usize> {
        if t == t8 {
            Ok(self.read_byte()? as i8 as usize)
        } else if t == t16 {
            let b = self.read_exact_vec(2)?;
            Ok(crate::util::read_u16(&b) as i16 as usize)
        } else {
            let b = self.read_exact_vec(4)?;
            let v = ((b[0] as u32) << 24)
                | ((b[1] as u32) << 16)
                | ((b[2] as u32) << 8)
                | b[3] as u32;
            Ok(v as usize)
        }
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

pub fn from_bytes(b: &[u8]) -> std::io::Result<Bdf> {
    let mut r = Reader::new(b);
    let v = r.read()?;
    Ok(v)
}
