//! `WebSocket` carrier over blocking `TCP`, both roles.
//!
//! Upgrade handshake plus binary framing; the `VLESS` bytes ride unchanged.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// `RFC 6455` upgrade fingerprint, shared by every implementation on the wire.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest handshake block read before the upgrade is refused, not buffered.
const HEAD_LIMIT: usize = 16 * 1024;
/// Largest single frame payload accepted; anything bigger closes fast.
const FRAME_LIMIT: usize = 16 * 1024 * 1024;
/// Largest relay chunk per direction, one frame each way.
const CHUNK: usize = 16 * 1024;
/// Binary data frame opcode.
const OP_DATA: u8 = 0x02;
/// Subsequent fragment opcode.
const OP_CONT: u8 = 0x00;
/// Close opcode.
const OP_CLOSE: u8 = 0x08;
/// Ping opcode, answered with a pong carrying the same payload.
const OP_PING: u8 = 0x09;
/// Pong opcode, never answered.
const OP_PONG: u8 = 0x0A;
/// Normal-closure body sent with each close frame.
const CLOSE_BODY: [u8; 2] = [0x03, 0xE8];

/// Standard base64 alphabet, the encoding both handshake keys arrive in.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 encode with padding, for handshake keys only.
fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | u32::from(byte);
        }
        word <<= 8 * (3 - chunk.len());
        out.push(ALPHABET[(word >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(word >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(word >> 6 & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(word & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// One base64 digit in either alphabet; the early-data channel is url-safe.
fn b64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Base64 decode without padding in either alphabet, for early data only.
fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().trim_end_matches('=');
    if text.is_empty() {
        return Some(Vec::new());
    }
    if text.len() % 4 == 1 {
        return None;
    }
    let bytes = text.as_bytes();
    let (full, rest) = bytes.split_at(bytes.len() / 4 * 4);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    for group in full.as_chunks::<4>().0 {
        let mut word = 0u32;
        for &byte in group {
            word = (word << 6) | u32::from(b64_value(byte)?);
        }
        out.extend_from_slice(&word.to_be_bytes()[1..]);
    }
    if !rest.is_empty() {
        let mut word = 0u32;
        for &byte in rest {
            word = (word << 6) | u32::from(b64_value(byte)?);
        }
        word <<= 6 * (4 - rest.len());
        let tail = word.to_be_bytes();
        out.extend_from_slice(&tail[1..rest.len()]);
    }
    Some(out)
}

/// Expected `Sec-WebSocket-Accept` for a client key, per `RFC 6455` section 1.3.
fn accept_key(key: &str) -> String {
    use sha1::Digest as _;
    let mut hash = sha1::Sha1::new();
    hash.update(key.trim().as_bytes());
    hash.update(GUID.as_bytes());
    b64_encode(&hash.finalize())
}

/// Sixteen fresh random bytes as standard base64, the client handshake key.
fn fresh_key() -> Option<String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).ok()?;
    Some(b64_encode(&raw))
}

/// Four fresh random bytes, the mask of one client frame.
fn fresh_mask() -> Option<[u8; 4]> {
    let mut mask = [0u8; 4];
    getrandom::getrandom(&mut mask).ok()?;
    Some(mask)
}

/// Read until `\r\n\r\n`, keeping pipelined bytes; `None` past the limit.
fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    loop {
        if head.len() >= HEAD_LIMIT {
            return None;
        }
        let mut byte = [0u8; 1];
        crate::proxy::read_exact(stream, &mut byte).ok()?;
        head.push(byte[0]);
        if head.len() >= 4 && head[head.len() - 4..] == *b"\r\n\r\n" {
            return Some(head);
        }
    }
}

/// Header value for `name`, case-insensitive, trimmed, `None` when absent.
fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    lines.next()?;
    for line in lines {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// Request path without its query string, `None` on a malformed request line.
fn request_path(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split(' ');
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    Some(
        target
            .split_once('?')
            .map_or(target, |(base, _)| base)
            .to_owned(),
    )
}

/// Write handle shared by the relay thread and the control replies.
#[derive(Debug)]
struct Shared {
    /// Socket half every frame is written through, one writer at a time.
    stream: Mutex<TcpStream>,
    /// Whether a close frame already went out, so it goes out once.
    closed: AtomicBool,
}

/// Byte stream over `WebSocket` messages; `Read` yields message payload bytes.
#[derive(Debug)]
pub(crate) struct WsReader {
    /// Socket half frames are read from.
    read: TcpStream,
    /// Shared writer for pong and close replies.
    shared: Arc<Shared>,
    /// Decoded payload bytes not yet consumed.
    backlog: Vec<u8>,
    /// Early-data bytes served before the first message.
    early: Vec<u8>,
    /// Whether the peer closed cleanly, after which reads report `EOF`.
    eof: bool,
}

/// Frame writer; cheap to clone for the relay thread.
#[derive(Debug, Clone)]
pub(crate) struct WsWriter {
    /// Shared socket half every frame is written through.
    shared: Arc<Shared>,
    /// Whether frames are masked, which only clients do.
    masked: bool,
}

impl WsReader {
    /// Decode one frame from the socket: `(fin, opcode, payload)`.
    fn frame(&mut self) -> Option<(bool, u8, Vec<u8>)> {
        let mut head = [0u8; 2];
        crate::proxy::read_exact(&mut self.read, &mut head).ok()?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let mut len = usize::from(head[1] & 0x7F);
        if len == 126 {
            let mut ext = [0u8; 2];
            crate::proxy::read_exact(&mut self.read, &mut ext).ok()?;
            len = usize::from(u16::from_be_bytes(ext));
        } else if len == 127 {
            let mut ext = [0u8; 8];
            crate::proxy::read_exact(&mut self.read, &mut ext).ok()?;
            len = usize::try_from(u64::from_be_bytes(ext)).ok()?;
        }
        if len > FRAME_LIMIT {
            return None;
        }
        if opcode & 0x08 != 0 && (len > 125 || !fin) {
            return None;
        }
        let mask = if masked {
            let mut mask = [0u8; 4];
            crate::proxy::read_exact(&mut self.read, &mut mask).ok()?;
            Some(mask)
        } else {
            None
        };
        let mut payload = vec![0u8; len];
        if len > 0 {
            crate::proxy::read_exact(&mut self.read, &mut payload).ok()?;
        }
        if let Some(mask) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i & 3];
            }
        }
        Some((fin, opcode, payload))
    }

    /// Decode one data message, answering ping and close inline.
    fn message(&mut self) -> Option<Vec<u8>> {
        let mut msg = Vec::new();
        let mut open = false;
        loop {
            let (fin, opcode, payload) = self.frame()?;
            match opcode {
                OP_CLOSE => {
                    self.reply(OP_CLOSE, &payload);
                    self.eof = true;
                    return None;
                }
                OP_PING => self.reply(OP_PONG, &payload),
                OP_PONG => {}
                OP_DATA | OP_CONT => {
                    let continues = opcode == OP_CONT;
                    if continues && !open || !continues && open {
                        return None;
                    }
                    open = true;
                    msg.extend_from_slice(&payload);
                    if fin {
                        return Some(msg);
                    }
                }
                _ => return None,
            }
        }
    }

    /// Answer a control frame through the shared writer, at most one close.
    fn reply(&self, opcode: u8, payload: &[u8]) {
        if opcode == OP_CLOSE && self.shared.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        let _ = write_frame(&mut stream, false, opcode, payload);
    }
}

impl Read for WsReader {
    /// Fill `buf` with message payload bytes; empty means clean `EOF`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.early.is_empty() {
                let n = self.early.len().min(buf.len());
                buf[..n].copy_from_slice(&self.early[..n]);
                self.early.drain(..n);
                return Ok(n);
            }
            if !self.backlog.is_empty() {
                let n = self.backlog.len().min(buf.len());
                buf[..n].copy_from_slice(&self.backlog[..n]);
                self.backlog.drain(..n);
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            match self.message() {
                None => return Ok(0),
                Some(msg) => {
                    if msg.is_empty() {
                        continue;
                    }
                    let n = msg.len().min(buf.len());
                    buf[..n].copy_from_slice(&msg[..n]);
                    self.backlog.extend_from_slice(&msg[n..]);
                    return Ok(n);
                }
            }
        }
    }
}

impl WsWriter {
    /// Send one binary message, returning `false` when the socket is gone.
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        write_frame(&mut stream, self.masked, OP_DATA, data)
    }

    /// Send the close frame once, however the relay is ending.
    ///
    /// `pub(crate)` because a carried protocol ends its carrier itself: a relay
    /// over this carrier has to close the carrier when it stops, and it is not
    /// this module's relay.
    pub(crate) fn close(&self) {
        if self.shared.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        let _ = write_frame(&mut stream, self.masked, OP_CLOSE, &CLOSE_BODY);
    }
}

/// Encode one frame onto the stream; clients mask, servers never do.
fn write_frame(stream: &mut TcpStream, masked: bool, opcode: u8, data: &[u8]) -> bool {
    let mut head = Vec::with_capacity(14);
    head.push(0x80 | (opcode & 0x0F));
    let flag: u8 = if masked { 0x80 } else { 0 };
    if data.len() < 126 {
        head.push(flag | data.len() as u8);
    } else if u16::try_from(data.len()).is_ok() {
        head.push(flag | 0x7E);
        head.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        head.push(flag | 0x7F);
        head.extend_from_slice(&(data.len() as u64).to_be_bytes());
    }
    if stream.write_all(&head).is_err() {
        return false;
    }
    if !masked {
        return stream.write_all(data).is_ok();
    }
    let Some(mask) = fresh_mask() else {
        return false;
    };
    if stream.write_all(&mask).is_err() {
        return false;
    }
    let mut data = data.to_vec();
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= mask[i & 3];
    }
    stream.write_all(&data).is_ok()
}

/// Accept the upgrade as a server, checking the configured path exactly.
pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(WsReader, WsWriter)> {
    use std::fmt::Write as _;
    let mut read = stream;
    let head = read_head(&mut read)?;
    if request_path(&head)? != path {
        return None;
    }
    let key = header_value(&head, "sec-websocket-key")?;
    if key.is_empty() {
        return None;
    }
    let early = header_value(&head, "sec-websocket-protocol")
        .and_then(|value| b64_decode(&value))
        .filter(|bytes| !bytes.is_empty())
        .unwrap_or_default();
    let offered = header_value(&head, "sec-websocket-protocol").unwrap_or_default();
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        accept_key(&key)
    );
    if !early.is_empty() {
        let _ = write!(response, "Sec-WebSocket-Protocol: {offered}\r\n");
    }
    response.push_str("\r\n");
    read.write_all(response.as_bytes()).ok()?;
    split(read, early, false)
}

/// Perform the upgrade as a client, verifying the accept key before use.
pub(crate) fn connect(stream: TcpStream, host: &str, path: &str) -> Option<(WsReader, WsWriter)> {
    let key = fresh_key()?;
    let mut read = stream;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    read.write_all(request.as_bytes()).ok()?;
    let head = read_head(&mut read)?;
    let text = std::str::from_utf8(&head).ok()?;
    if text.split("\r\n").next()?.split(' ').nth(1)? != "101" {
        return None;
    }
    if header_value(&head, "sec-websocket-accept")? != accept_key(&key) {
        return None;
    }
    let at = head.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let mut early = Vec::new();
    early.extend_from_slice(&head[at..]);
    split(read, early, true)
}

/// Split one socket into its reader and writer halves around early bytes.
fn split(read: TcpStream, early: Vec<u8>, masked: bool) -> Option<(WsReader, WsWriter)> {
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let shared = Arc::new(Shared {
        stream: Mutex::new(write),
        closed: AtomicBool::new(false),
    });
    let reader = WsReader {
        read,
        shared: Arc::clone(&shared),
        backlog: Vec::new(),
        early,
        eof: false,
    };
    Some((reader, WsWriter { shared, masked }))
}

/// Relay raw bytes against `WebSocket` messages until either side ends.
pub(crate) fn relay(mut reader: WsReader, writer: &WsWriter, peer: &TcpStream) {
    let Ok(peer_read) = peer.try_clone() else {
        return;
    };
    let Ok(peer_write) = peer.try_clone() else {
        return;
    };
    let mut peer_read = peer_read;
    let mut peer_write = peer_write;
    let uplink = writer.clone();
    let done = thread::spawn(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match peer_read.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if !uplink.send(&buf[..n]) {
                        break;
                    }
                }
                _ => break,
            }
        }
        uplink.close();
        let _ = peer_read.shutdown(Shutdown::Both);
    });
    let mut buf = vec![0u8; CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(n) if n > 0 => {
                if peer_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
    writer.close();
    let _ = peer_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn accept_matches_the_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn base64_round_trips_short_and_padded_lengths() {
        for bytes in [vec![], vec![0xFB], vec![0xFB, 0xEF], vec![0xFF, 0xFE, 0xFD]] {
            let encoded = b64_encode(&bytes);
            let decoded = b64_decode(&encoded).expect("decodes");
            assert_eq!(decoded, bytes);
        }
        assert_eq!(b64_decode("--8"), Some(vec![0xFB, 0xEF]));
        assert!(b64_decode("abcde").is_none());
    }

    #[test]
    fn frames_round_trip_masked_and_plain() {
        for len in [0, 1, 125, 126, 200, 65_535, 65_536] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for masked in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
                let port = listener.local_addr().expect("addr").port();
                let expected = payload.clone();
                let writer = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().expect("accepts");
                    assert!(write_frame(&mut stream, masked, OP_DATA, &expected));
                });
                let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
                let shared = Arc::new(Shared {
                    stream: Mutex::new(stream.try_clone().expect("clones")),
                    closed: AtomicBool::new(false),
                });
                let mut reader = WsReader {
                    read: stream,
                    shared,
                    backlog: Vec::new(),
                    early: Vec::new(),
                    eof: false,
                };
                assert_eq!(reader.message().expect("reads"), payload);
                writer.join().expect("joins");
            }
        }
    }

    #[test]
    fn handshake_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) = connect(stream, "127.0.0.1", "/tunnel").expect("upgrades");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    #[test]
    fn handshake_rejects_a_wrong_path_and_key() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/tunnel").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Key: k\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
