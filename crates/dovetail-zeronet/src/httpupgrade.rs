//! `HTTPUpgrade` carrier over blocking `TCP`, both roles.
//!
//! Upgrade handshake, then raw bytes both ways: no framing follows the `101`.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;

/// Largest handshake block read before the upgrade is refused, not buffered.
const HEAD_LIMIT: usize = 64 * 1024;
/// Largest relay chunk per direction once upgraded.
const CHUNK: usize = 16 * 1024;

/// Byte stream past the upgrade; `Read` serves pipelined bytes first.
#[derive(Debug)]
pub(crate) struct UpReader {
    /// Socket half response bytes are read from.
    read: TcpStream,
    /// Bytes that followed the `101` on the wire.
    prefix: Vec<u8>,
}

impl Read for UpReader {
    /// Fill `buf`; empty means the peer closed a clean `TCP` `EOF`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[..n]);
            self.prefix.drain(..n);
            return Ok(n);
        }
        self.read.read(buf)
    }
}

/// Read until `\r\n\r\n`, keeping pipelined bytes; `None` past the limit.
fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut head = Vec::with_capacity(512);
    loop {
        if head.len() >= HEAD_LIMIT {
            return None;
        }
        let mut byte = [0u8; 1];
        crate::proxy::read_exact(stream, &mut byte).ok()?;
        head.push(byte[0]);
        if head.len() >= 4 && head[head.len() - 4..] == *b"\r\n\r\n" {
            let at = head.len() - 4 + 4;
            return Some((head[..at].to_vec(), head[at..].to_vec()));
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
    let mut parts = line.split_whitespace();
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

/// Accept the upgrade as a server, checking path and upgrade headers exactly.
pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(UpReader, TcpStream)> {
    let mut read = stream;
    let (head, prefix) = read_head(&mut read)?;
    if request_path(&head)? != path {
        return None;
    }
    let upgrade = header_value(&head, "upgrade").unwrap_or_default();
    let connection = header_value(&head, "connection").unwrap_or_default();
    if !upgrade.eq_ignore_ascii_case("websocket") || !connection.eq_ignore_ascii_case("upgrade") {
        return None;
    }
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    write
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .ok()?;
    Some((UpReader { read, prefix }, write))
}

/// Perform the upgrade as a client, checking the `101` before use.
pub(crate) fn connect(stream: TcpStream, host: &str, path: &str) -> Option<(UpReader, TcpStream)> {
    let mut read = stream;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    );
    read.write_all(request.as_bytes()).ok()?;
    let (head, prefix) = read_head(&mut read)?;
    let text = std::str::from_utf8(&head).ok()?;
    if text.split("\r\n").next()? != "HTTP/1.1 101 Switching Protocols" {
        return None;
    }
    if !header_value(&head, "connection")?.eq_ignore_ascii_case("upgrade") {
        return None;
    }
    if !header_value(&head, "upgrade")?.eq_ignore_ascii_case("websocket") {
        return None;
    }
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some((UpReader { read, prefix }, write))
}

/// Relay raw bytes both ways until either side ends.
pub(crate) fn relay(mut reader: UpReader, write: &TcpStream, peer: &TcpStream) {
    let Ok(peer_read) = peer.try_clone() else {
        return;
    };
    let Ok(peer_write) = peer.try_clone() else {
        return;
    };
    let mut peer_read = peer_read;
    let mut peer_write = peer_write;
    let Ok(mut uplink) = write.try_clone() else {
        return;
    };
    let done = thread::spawn(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match peer_read.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if uplink.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = peer_read.shutdown(Shutdown::Both);
        let _ = uplink.shutdown(Shutdown::Both);
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
    let _ = peer_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn upgrade_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, write) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            let mut write = write;
            write.write_all(b"pong").expect("writes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut write) =
            connect(stream, "oracle.example", "/tunnel").expect("upgrades");
        write.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    #[test]
    fn upgrade_rejects_a_wrong_path_and_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/tunnel").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
