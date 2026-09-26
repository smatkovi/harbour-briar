//! Hex and base32, in the spellings Briar uses.

pub fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding -- Briar's Base32.encode, which it then
/// lowercases for links.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in data {
        buffer = (buffer << 8) | *byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in s.chars() {
        let c = c.to_ascii_uppercase();
        let v = BASE32.iter().position(|x| *x as char == c)? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

pub fn write_u16(dest: &mut [u8], value: u16) {
    dest[0] = (value >> 8) as u8;
    dest[1] = (value & 0xff) as u8;
}

pub fn write_u32(dest: &mut [u8], value: u32) {
    for i in 0..4 {
        dest[i] = (value >> (24 - 8 * i)) as u8;
    }
}

pub fn write_u64(dest: &mut [u8], value: u64) {
    for i in 0..8 {
        dest[i] = (value >> (56 - 8 * i)) as u8;
    }
}

pub fn read_u16(src: &[u8]) -> u16 {
    ((src[0] as u16) << 8) | src[1] as u16
}

pub fn read_u64(src: &[u8]) -> u64 {
    let mut v = 0u64;
    for i in 0..8 {
        v = (v << 8) | src[i] as u64;
    }
    v
}

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn random(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    getrandom::getrandom(&mut v).expect("no randomness available");
    v
}
