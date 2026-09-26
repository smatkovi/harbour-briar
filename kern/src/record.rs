//! Records: a 4-byte header (protocol version, type, 16-bit payload length)
//! and the payload (bramble-core/record).

use std::io::{Read, Write};

pub const RECORD_HEADER_LEN: usize = 4;
pub const MAX_RECORD_PAYLOAD_LEN: usize = 48 * 1024;

#[derive(Clone, Debug)]
pub struct Record {
    pub protocol_version: u8,
    pub record_type: u8,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn new(protocol_version: u8, record_type: u8, payload: Vec<u8>) -> Self {
        Record {
            protocol_version,
            record_type,
            payload,
        }
    }
}

pub fn write_record(out: &mut impl Write, r: &Record) -> std::io::Result<()> {
    let mut header = [0u8; RECORD_HEADER_LEN];
    header[0] = r.protocol_version;
    header[1] = r.record_type;
    crate::util::write_u16(&mut header[2..], r.payload.len() as u16);
    out.write_all(&header)?;
    out.write_all(&r.payload)
}

/// Reads one record. Returns None at end of stream.
pub fn read_record(inner: &mut impl Read) -> std::io::Result<Option<Record>> {
    let mut header = [0u8; RECORD_HEADER_LEN];
    let mut got = 0;
    while got < RECORD_HEADER_LEN {
        let n = inner.read(&mut header[got..])?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "record header cut short",
            ));
        }
        got += n;
    }
    let length = crate::util::read_u16(&header[2..]) as usize;
    if length > MAX_RECORD_PAYLOAD_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "record payload too long",
        ));
    }
    let mut payload = vec![0u8; length];
    inner.read_exact(&mut payload)?;
    Ok(Some(Record {
        protocol_version: header[0],
        record_type: header[1],
        payload,
    }))
}
