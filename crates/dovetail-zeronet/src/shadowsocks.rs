//! `shadowsocks` `aes-256-gcm` chunk transport over `TCP`, both roles.
//!
//! Salt first, then length-prefixed sealed chunks; the target address rides in
//! the first chunk. Only this cipher exists here: anything else closes fast.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha1::Sha1;

use crate::proxy::{push_addr, read_exact};

/// Salt bytes per session, and tag bytes per sealed chunk.
const SALT_LEN: usize = 32;
/// Tag bytes per sealed chunk.
const TAG_LEN: usize = 16;
/// Largest plaintext payload per chunk, matching the oracle's framing.
const MAX_CHUNK: usize = 0x3FFF;
/// Largest plaintext read per relay turn.
const READ_CHUNK: usize = 0x4000;

/// Serve one `shadowsocks` connection: salt, address chunk, dial, relay sealed.
pub(crate) fn serve(mut stream: TcpStream, password: &str, method: &str, freedom: bool) {
    trace("accept");
    if method != "aes-256-gcm" || !freedom {
        trace("refuse method-or-freedom");
        return;
    }
    let master = master_key(password);
    let mut salt = [0u8; SALT_LEN];
    if read_exact(&mut stream, &mut salt).is_err() {
        trace("no peer salt");
        return;
    }
    trace("peer salt read");
    let Some(mut recv) = Cipher::new(&master, &salt) else {
        return;
    };
    let Some(first) = open_chunk(&mut stream, &mut recv) else {
        trace("no first chunk");
        return;
    };
    trace(&format!("first chunk {} bytes", first.len()));
    let Some((target, used)) = parse_addr_header(&first) else {
        trace("no target header");
        return;
    };
    trace(&format!("dial {target}"));
    let Ok(mut uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        trace("dial failed");
        return;
    };
    if uplink.write_all(&first[used..]).is_err() {
        return;
    }
    let mut salt = [0u8; SALT_LEN];
    if getrandom::getrandom(&mut salt).is_err() {
        return;
    }
    let Some(send) = Cipher::new(&master, &salt) else {
        return;
    };
    if stream.write_all(&salt).is_err() {
        return;
    }
    trace("relay starts");
    pump_relay(&uplink, &stream, send, Recv::Ready(Box::new(recv)));
}

/// Stderr line when `DOVETAIL_TRACE` is set, silence otherwise.
fn trace(message: &str) {
    if std::env::var_os("DOVETAIL_TRACE").is_some() {
        eprintln!("dovetail-ss: {message}");
    }
}

/// Dial a `shadowsocks` server for a target: salt and sealed address, no waiting.
pub(crate) fn client_send_handshake(
    uplink: &mut TcpStream,
    password: &str,
    method: &str,
    target: &SocketAddr,
) -> Option<(Cipher, Recv)> {
    if method != "aes-256-gcm" {
        return None;
    }
    let master = master_key(password);
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).ok()?;
    uplink.write_all(&salt).ok()?;
    trace("client salt sent");
    let mut send = Cipher::new(&master, &salt)?;
    let mut addr = Vec::with_capacity(20);
    push_addr(&mut addr, target, 4);
    addr.extend_from_slice(&target.port().to_be_bytes());
    seal_all(&mut send, &addr, uplink).ok()?;
    trace("client addr sent");
    Some((send, Recv::Waiting(master)))
}

/// Receive cipher: ready, or still waiting on the peer's salt.
pub(crate) enum Recv {
    /// Salt read, cipher derived, boxed like the oracle boxes its schedules.
    Ready(Box<Cipher>),
    /// Salt unread; derived on the first opened chunk.
    Waiting([u8; 32]),
}

/// Relay plaintext one side against sealed chunks the other, both ways to close.
pub(crate) fn pump_relay(plain: &TcpStream, sealed: &TcpStream, send: Cipher, recv: Recv) {
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(sealed_write) = sealed.try_clone() else {
        return;
    };
    let Ok(sealed_read) = sealed.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut sealed_write = sealed_write;
    let mut sealed_read = sealed_read;
    let mut plain_write = plain_write;
    let mut send = send;
    let done = thread::spawn(move || {
        let mut buf = vec![0u8; READ_CHUNK];
        while let Ok(read) = plain_read.read(&mut buf) {
            trace(&format!("plain->sealed {read} bytes"));
            if read == 0 {
                break;
            }
            if seal_all(&mut send, &buf[..read], &mut sealed_write).is_err() {
                trace("seal failed");
                break;
            }
        }
        trace("plain->sealed ended");
        let _ = plain_read.shutdown(Shutdown::Both);
        let _ = sealed_write.shutdown(Shutdown::Both);
    });
    let mut recv = match recv {
        Recv::Ready(boxed) => *boxed,
        Recv::Waiting(master) => {
            let mut peer = [0u8; SALT_LEN];
            if read_exact(&mut sealed_read, &mut peer).is_err() {
                trace("no server salt");
                return;
            }
            trace("server salt read");
            let Some(cipher) = Cipher::new(&master, &peer) else {
                return;
            };
            cipher
        }
    };
    while let Some(chunk) = open_chunk(&mut sealed_read, &mut recv) {
        trace(&format!("sealed->plain {} bytes", chunk.len()));
        if plain_write.write_all(&chunk).is_err() {
            break;
        }
    }
    trace("sealed->plain ended");
    let _ = sealed_read.shutdown(Shutdown::Both);
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

/// One direction cipher: subkey from salt, little-endian counter nonces.
pub(crate) struct Cipher {
    /// Sealed-chunk cipher for this direction.
    cipher: Aes256Gcm,
    /// Chunks sealed or opened so far, the nonce.
    counter: u64,
}

impl Cipher {
    /// Derive the subkey; `None` only when the fixed length misbehaves.
    fn new(master: &[u8; SALT_LEN], salt: &[u8; SALT_LEN]) -> Option<Self> {
        let expander = Hkdf::<Sha1>::new(Some(salt), master);
        let mut key = [0u8; 32];
        expander.expand(b"ss-subkey", &mut key).ok()?;
        Some(Self {
            cipher: Aes256Gcm::new_from_slice(&key).ok()?,
            counter: 0,
        })
    }

    /// Current nonce: counter little-endian in the first eight bytes.
    fn nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        nonce
    }
}

/// Master key: `MD5` chain (`EVP_BytesToKey`) truncated to 32 bytes.
fn master_key(password: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut previous = Vec::new();
    for slot in out.chunks_mut(16) {
        let mut input = std::mem::take(&mut previous);
        input.extend_from_slice(password.as_bytes());
        previous = md5::compute(input).0.to_vec();
        slot.copy_from_slice(&previous);
    }
    out
}

/// Seal every `MAX_CHUNK` slice of plaintext into length-plus-payload chunks.
fn seal_all(send: &mut Cipher, plain: &[u8], out: &mut dyn Write) -> std::io::Result<()> {
    for chunk in plain.chunks(MAX_CHUNK) {
        seal_into(send, &(chunk.len() as u16).to_be_bytes(), out)?;
        seal_into(send, chunk, out)?;
    }
    Ok(())
}

/// Seal one plaintext slice plus its tag onto the stream.
fn seal_into(send: &mut Cipher, plain: &[u8], out: &mut dyn Write) -> std::io::Result<()> {
    let nonce = send.nonce();
    let mut buf = plain.to_vec();
    let tag = send
        .cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut buf)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    out.write_all(&buf)?;
    out.write_all(&tag)?;
    Ok(())
}

/// Open one length-plus-payload chunk pair into plaintext.
fn open_chunk(stream: &mut dyn Read, recv: &mut Cipher) -> Option<Vec<u8>> {
    use crate::proxy::read_exact;
    let mut length = vec![0u8; 2 + TAG_LEN];
    read_exact(stream, &mut length).ok()?;
    let length = open_into(recv, &mut length)?;
    if length.len() != 2 {
        return None;
    }
    let size = usize::from(u16::from_be_bytes([length[0], length[1]]));
    if size > MAX_CHUNK {
        return None;
    }
    let mut chunk = vec![0u8; size + TAG_LEN];
    read_exact(stream, &mut chunk).ok()?;
    open_into(recv, &mut chunk)
}

/// Decrypt one sealed buffer in place, returning its plaintext.
fn open_into(recv: &mut Cipher, chunk: &mut [u8]) -> Option<Vec<u8>> {
    if chunk.len() < TAG_LEN {
        return None;
    }
    let nonce = recv.nonce();
    let split = chunk.len() - TAG_LEN;
    let (body, tag) = chunk.split_at_mut(split);
    recv.cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            b"",
            body,
            aes_gcm::Tag::from_slice(tag),
        )
        .ok()?;
    Some(body.to_vec())
}

/// Parse a `SOCKS`-order address header, returning the target and bytes used.
fn parse_addr_header(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let &atyp = buf.first()?;
    match atyp {
        1 => {
            if buf.len() < 7 {
                return None;
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[1..5]);
            let mut port = [0u8; 2];
            port.copy_from_slice(&buf[5..7]);
            Some((
                SocketAddr::new(std::net::IpAddr::V4(ip.into()), u16::from_be_bytes(port)),
                7,
            ))
        }
        4 => {
            if buf.len() < 19 {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[1..17]);
            let mut port = [0u8; 2];
            port.copy_from_slice(&buf[17..19]);
            Some((
                SocketAddr::new(std::net::IpAddr::V6(ip.into()), u16::from_be_bytes(port)),
                19,
            ))
        }
        3 => {
            let len = usize::from(*buf.get(1)?);
            if len == 0 || buf.len() < 2 + len + 2 {
                return None;
            }
            let host = std::str::from_utf8(&buf[2..2 + len]).ok()?;
            let mut port = [0u8; 2];
            port.copy_from_slice(&buf[2 + len..4 + len]);
            let target = format!("{host}:{}", u16::from_be_bytes(port))
                .to_socket_addrs()
                .ok()?
                .next()?;
            Some((target, 4 + len))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_matches_evp_bytestokey() {
        assert_eq!(
            master_key("an-example-shared-password"),
            *b"\x5c\xb2\x9f\x91\x10\xb5\x40\xa6\xeb\x99\x5c\x35\x67\x1b\x75\x92\xa5\x07\xf5\xdb\xe4\xac\x97\x7c\xae\x2f\x7b\x98\xde\xdc\x80\x22"
        );
    }

    #[test]
    fn chunks_open_that_seal_sealed_and_reject_damage() {
        let master = master_key("an-example-shared-password");
        let salt = [7u8; SALT_LEN];
        let mut send = Cipher::new(&master, &salt).expect("derives");
        let mut wire = Vec::new();
        seal_all(&mut send, b"length-is-framing", &mut wire).expect("seals");
        let mut recv = Cipher::new(&master, &salt).expect("derives");
        let mut cursor = std::io::Cursor::new(&wire);
        let back = open_chunk(&mut cursor, &mut recv).expect("opens");
        assert_eq!(back, b"length-is-framing");
        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut damaged = std::io::Cursor::new(&tampered);
        let mut fresh = Cipher::new(&master, &salt).expect("derives");
        assert!(open_chunk(&mut damaged, &mut fresh).is_none());
    }

    #[test]
    fn relay_carries_an_echo_both_ways() {
        let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(1) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || {
                    serve(stream, "an-example-shared-password", "aes-256-gcm", true);
                });
            }
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut uplink = uplink;
        let Some((mut send, recv)) = client_send_handshake(
            &mut uplink,
            "an-example-shared-password",
            "aes-256-gcm",
            &target,
        ) else {
            panic!("handshake failed");
        };
        seal_all(&mut send, b"ping", &mut uplink).expect("seals");
        let mut recv = match recv {
            Recv::Ready(boxed) => *boxed,
            Recv::Waiting(master) => {
                let mut peer = [0u8; SALT_LEN];
                read_exact(&mut uplink, &mut peer).expect("salt");
                Cipher::new(&master, &peer).expect("derives")
            }
        };
        let back = open_chunk(&mut uplink, &mut recv).expect("opens");
        assert_eq!(back, b"ping");
    }
}
