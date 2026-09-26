//! The framed, encrypted stream (bramble-core StreamEncrypterImpl /
//! StreamDecrypterImpl and the StreamWriter/StreamReader on top of them).
//!
//! A stream is: an optional 16-byte tag, a stream header carrying the frame
//! key, then frames. Each frame has an encrypted 4-byte header (payload
//! length, padding length, final-frame bit) and an encrypted payload; the
//! nonce is the frame number, with the top bit set for the header.

use crate::crypto::{self, SecretKey};
use crate::transport::*;
use crate::util::{read_u16, write_u16, write_u64};
use std::io::{Read, Write};

fn frame_nonce(frame_number: u64, header: bool) -> [u8; FRAME_NONCE_LEN] {
    let mut nonce = [0u8; FRAME_NONCE_LEN];
    write_u64(&mut nonce[..8], frame_number);
    if header {
        nonce[0] |= 0x80;
    }
    nonce
}

pub struct StreamWriter<W: Write> {
    out: W,
    header_key: SecretKey,
    frame_key: SecretKey,
    stream_number: u64,
    tag: Option<[u8; TAG_LEN]>,
    stream_header_nonce: [u8; STREAM_HEADER_NONCE_LEN],
    frame_number: u64,
    wrote_preamble: bool,
    buffer: Vec<u8>,
}

impl<W: Write> StreamWriter<W> {
    /// A stream in handshake or rotation mode: tagged, with the stream number
    /// in the header.
    pub fn new(out: W, keys: &StreamKeys, stream_number: u64) -> Self {
        let tag = encode_tag(&keys.tag_key, PROTOCOL_VERSION, stream_number);
        Self::with_parts(out, keys.header_key, Some(tag), stream_number)
    }

    /// The contact exchange stream: no tag, stream number 0, and the header
    /// key comes from the handshake's master key.
    pub fn untagged(out: W, header_key: SecretKey) -> Self {
        Self::with_parts(out, header_key, None, 0)
    }

    fn with_parts(
        out: W,
        header_key: SecretKey,
        tag: Option<[u8; TAG_LEN]>,
        stream_number: u64,
    ) -> Self {
        let mut nonce = [0u8; STREAM_HEADER_NONCE_LEN];
        nonce.copy_from_slice(&crate::util::random(STREAM_HEADER_NONCE_LEN));
        StreamWriter {
            out,
            header_key,
            frame_key: crypto::generate_secret_key(),
            stream_number,
            tag,
            stream_header_nonce: nonce,
            frame_number: 0,
            wrote_preamble: false,
            buffer: Vec::with_capacity(MAX_PAYLOAD_LEN),
        }
    }

    /// Only for the reference tests: fixes the values the real code takes
    /// from the random number generator.
    pub fn with_fixed_randomness(
        out: W,
        keys: &StreamKeys,
        stream_number: u64,
        nonce: [u8; STREAM_HEADER_NONCE_LEN],
        frame_key: SecretKey,
    ) -> Self {
        let mut w = Self::new(out, keys, stream_number);
        w.stream_header_nonce = nonce;
        w.frame_key = frame_key;
        w
    }

    fn write_preamble(&mut self) -> std::io::Result<()> {
        if self.wrote_preamble {
            return Ok(());
        }
        if let Some(tag) = self.tag {
            self.out.write_all(&tag)?;
        }
        let mut plaintext = [0u8; STREAM_HEADER_PLAINTEXT_LEN];
        write_u16(&mut plaintext[..2], PROTOCOL_VERSION);
        write_u64(&mut plaintext[2..10], self.stream_number);
        plaintext[10..].copy_from_slice(&self.frame_key);
        let ciphertext =
            crypto::secretbox_encrypt(&self.header_key, &self.stream_header_nonce, &plaintext);
        self.out.write_all(&self.stream_header_nonce)?;
        self.out.write_all(&ciphertext)?;
        self.wrote_preamble = true;
        Ok(())
    }

    fn write_frame(&mut self, final_frame: bool) -> std::io::Result<()> {
        self.write_preamble()?;
        let payload_length = self.buffer.len();
        let mut header = [0u8; FRAME_HEADER_PLAINTEXT_LEN];
        write_u16(&mut header[..2], payload_length as u16);
        write_u16(&mut header[2..], 0);
        if final_frame {
            header[0] |= 0x80;
        }
        let encrypted_header = crypto::secretbox_encrypt(
            &self.frame_key,
            &frame_nonce(self.frame_number, true),
            &header,
        );
        let encrypted_payload = crypto::secretbox_encrypt(
            &self.frame_key,
            &frame_nonce(self.frame_number, false),
            &self.buffer,
        );
        self.out.write_all(&encrypted_header)?;
        self.out.write_all(&encrypted_payload)?;
        self.buffer.clear();
        self.frame_number += 1;
        Ok(())
    }

    /// Writes a frame with the given payload and padding -- the shape the
    /// reference vectors use.
    pub fn write_raw_frame(
        &mut self,
        payload: &[u8],
        padding: usize,
        final_frame: bool,
    ) -> std::io::Result<()> {
        self.write_preamble()?;
        let mut header = [0u8; FRAME_HEADER_PLAINTEXT_LEN];
        write_u16(&mut header[..2], payload.len() as u16);
        write_u16(&mut header[2..], padding as u16);
        if final_frame {
            header[0] |= 0x80;
        }
        let encrypted_header = crypto::secretbox_encrypt(
            &self.frame_key,
            &frame_nonce(self.frame_number, true),
            &header,
        );
        let mut plaintext = payload.to_vec();
        plaintext.extend(std::iter::repeat(0u8).take(padding));
        let encrypted_payload = crypto::secretbox_encrypt(
            &self.frame_key,
            &frame_nonce(self.frame_number, false),
            &plaintext,
        );
        self.out.write_all(&encrypted_header)?;
        self.out.write_all(&encrypted_payload)?;
        self.frame_number += 1;
        Ok(())
    }

    /// Sends everything buffered, then the empty final frame that means end
    /// of stream.
    pub fn send_end_of_stream(&mut self) -> std::io::Result<()> {
        self.write_frame(true)?;
        self.out.flush()
    }
}

impl<W: Write> Write for StreamWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let total = buf.len();
        while !buf.is_empty() {
            let space = MAX_PAYLOAD_LEN - self.buffer.len();
            let take = space.min(buf.len());
            self.buffer.extend_from_slice(&buf[..take]);
            buf = &buf[take..];
            if self.buffer.len() == MAX_PAYLOAD_LEN {
                self.write_frame(false)?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write_frame(false)?;
        self.out.flush()
    }
}

pub struct StreamReader<R: Read> {
    inner: R,
    header_key: SecretKey,
    expected_stream_number: u64,
    frame_key: Option<SecretKey>,
    frame_number: u64,
    final_frame: bool,
    payload: Vec<u8>,
    offset: usize,
}

impl<R: Read> StreamReader<R> {
    /// The tag must already have been read and recognised by the caller: it
    /// is what picks the keys in the first place.
    pub fn new(inner: R, header_key: SecretKey, expected_stream_number: u64) -> Self {
        StreamReader {
            inner,
            header_key,
            expected_stream_number,
            frame_key: None,
            frame_number: 0,
            final_frame: false,
            payload: Vec::new(),
            offset: 0,
        }
    }

    fn read_stream_header(&mut self) -> std::io::Result<()> {
        let mut raw = [0u8; STREAM_HEADER_LEN];
        self.inner.read_exact(&mut raw)?;
        let nonce = &raw[..STREAM_HEADER_NONCE_LEN];
        let plaintext = crypto::secretbox_decrypt(&self.header_key, nonce, &raw[STREAM_HEADER_NONCE_LEN..])
            .ok_or_else(|| bad("stream header does not authenticate"))?;
        if read_u16(&plaintext[..2]) != PROTOCOL_VERSION {
            return Err(bad("wrong transport protocol version"));
        }
        if crate::util::read_u64(&plaintext[2..10]) != self.expected_stream_number {
            return Err(bad("wrong stream number"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext[10..]);
        self.frame_key = Some(key);
        Ok(())
    }

    fn read_frame(&mut self) -> std::io::Result<bool> {
        if self.final_frame {
            return Ok(false);
        }
        if self.frame_key.is_none() {
            self.read_stream_header()?;
        }
        let frame_key = self.frame_key.unwrap();
        let mut header_ciphertext = [0u8; FRAME_HEADER_LEN];
        self.inner.read_exact(&mut header_ciphertext)?;
        let header = crypto::secretbox_decrypt(
            &frame_key,
            &frame_nonce(self.frame_number, true),
            &header_ciphertext,
        )
        .ok_or_else(|| bad("frame header does not authenticate"))?;
        self.final_frame = header[0] & 0x80 == 0x80;
        let payload_length = (read_u16(&header[..2]) & 0x7fff) as usize;
        let padding_length = read_u16(&header[2..]) as usize;
        if payload_length + padding_length > MAX_PAYLOAD_LEN {
            return Err(bad("frame is too long"));
        }
        let mut body = vec![0u8; payload_length + padding_length + crypto::MAC_LEN];
        self.inner.read_exact(&mut body)?;
        let plaintext = crypto::secretbox_decrypt(
            &frame_key,
            &frame_nonce(self.frame_number, false),
            &body,
        )
        .ok_or_else(|| bad("frame does not authenticate"))?;
        if plaintext[payload_length..].iter().any(|b| *b != 0) {
            return Err(bad("padding is not zero"));
        }
        self.payload = plaintext[..payload_length].to_vec();
        self.offset = 0;
        self.frame_number += 1;
        Ok(true)
    }
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.offset >= self.payload.len() {
            if !self.read_frame()? {
                return Ok(0);
            }
        }
        let available = self.payload.len() - self.offset;
        let take = available.min(buf.len());
        buf[..take].copy_from_slice(&self.payload[self.offset..self.offset + take]);
        self.offset += take;
        Ok(take)
    }
}

fn bad(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}
