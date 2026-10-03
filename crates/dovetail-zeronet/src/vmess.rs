//! `VMess` `AEAD` framing over blocking `TCP`, both roles.
//!
//! One authenticated request header, one authenticated response header, then
//! length-masked data frames in both directions. `ChaCha20-Poly1305` is the
//! only data cipher here, because it is what every current peer negotiates for
//! `auto`; `UDP` command, Mux, the `ws` carrier and the legacy `alterId`
//! handshake close fast rather than hanging the suite that asked for one.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::{AeadInPlace, Aes128Gcm};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest as _, Sha256};
use sha3::{digest::ExtendableOutput as _, Shake128};

use crate::proxy::{port, push_addr, read_exact, socks_addr};

/// Bytes in an auth id: one `AES` block of timestamp, randomness, checksum.
const AUTH_LEN: usize = 16;
/// Bytes in an `AEAD` tag.
const TAG_LEN: usize = 16;
/// Largest plaintext one data frame carries.
const MAX_PLAIN: usize = 8192;
/// Shortest request header: version byte through command byte.
const HEADER_MIN: usize = 38;
/// Longest header read, so one length field cannot ask for 64 KiB.
const HEADER_MAX: usize = 4096;
/// Request header version byte.
const VERSION: u8 = 1;
/// Command byte for `TCP`.
const COMMAND_TCP: u8 = 1;
/// Header option bit: chunks are length-prefixed.
const OPT_CHUNK: u8 = 0x01;
/// Header option bit: chunk lengths are masked with a `SHAKE128` stream.
const OPT_MASK: u8 = 0x04;
/// Header option bit: each chunk carries cleartext padding.
const OPT_PADDING: u8 = 0x08;
/// The framing a client asks for: what Xray asks for, and what a peer honours.
const OPTIONS: u8 = OPT_CHUNK | OPT_MASK | OPT_PADDING;
/// Wire code of the one data cipher this rung speaks.
const DATA_CIPHER: u8 = 4;
/// Bytes `MD5`-ed with the user id to make the command key every `KDF` starts from.
const COMMAND_MAGIC: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
/// Root key of the `VMess` `AEAD` key derivation chain.
const KDF_ROOT: &[u8] = b"VMess AEAD KDF";
/// How far the two clocks may disagree on an auth id, in seconds.
const TIME_SKEW: i64 = 120;
/// How long an accepted auth id stays replayable, and so is remembered.
const REPLAY_WINDOW: Duration = Duration::from_secs(120);
/// Auth ids remembered per replay window, so a busy minute cannot grow unbounded.
const REPLAY_CAPACITY: usize = 64 * 1024;
/// `SHA-256` block size, and so the length of one `HMAC` pad.
const PAD_LEN: usize = 64;

/// Serve one `VMess` connection: authenticate, dial, answer, relay framed.
pub(crate) fn serve(mut stream: TcpStream, id: &[u8; 16], freedom: bool) {
    if !freedom {
        return;
    }
    let Some(request) = read_request(&mut stream, id) else {
        return;
    };
    let (response_key, response_iv) = request.response_material();
    let (Some(send), Some(recv)) = (
        Frames::new(&response_key, &response_iv, request.options),
        Frames::new(&request.key, &request.iv, request.options),
    ) else {
        return;
    };
    let Some(header) = response_header(&response_key, &response_iv, request.auth) else {
        return;
    };
    let Ok(uplink) = TcpStream::connect_timeout(&request.target, Duration::from_secs(8)) else {
        return;
    };
    if stream.write_all(&header).is_err() {
        return;
    }
    pump_relay(&uplink, &stream, send, Recv::Frames(recv));
}

/// Write a `VMess` request for `target`, returning the data path both roles seal.
pub(crate) fn client_handshake(
    uplink: &mut TcpStream,
    id: &[u8; 16],
    target: &SocketAddr,
) -> Option<(Frames, Recv)> {
    let request = write_request(uplink, id, target)?;
    let (response_key, response_iv) = request.response_material();
    let send = Frames::new(&request.key, &request.iv, request.options)?;
    let recv = Frames::new(&response_key, &response_iv, request.options)?;
    Some((
        send,
        Recv::Response {
            frames: recv,
            key: response_key,
            iv: response_iv,
            auth: request.auth,
        },
    ))
}

/// The receive direction: a client authenticates the response header first, a
/// server has already answered and starts at data frames.
pub(crate) enum Recv {
    /// Data frames only.
    Frames(Frames),
    /// The sealed response header first, under the keys the request derived.
    Response {
        /// Data frames, already keyed.
        frames: Frames,
        /// Response key the request header hashed into.
        key: [u8; 16],
        /// Response nonce base the request header hashed into.
        iv: [u8; 16],
        /// Random byte the server has to echo back.
        auth: u8,
    },
}

/// Relay plaintext against data frames, both halves closing both sockets.
pub(crate) fn pump_relay(plain: &TcpStream, sealed: &TcpStream, mut send: Frames, recv: Recv) {
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
    let done = thread::spawn(move || {
        let mut chunk = vec![0u8; MAX_PLAIN];
        let mut wire = Vec::new();
        while let Ok(read) = plain_read.read(&mut chunk) {
            wire.clear();
            if read == 0 || send.seal(&mut wire, &chunk[..read]).is_none() {
                break;
            }
            if sealed_write.write_all(&wire).is_err() {
                break;
            }
        }
        let _ = plain_read.shutdown(Shutdown::Both);
        let _ = sealed_write.shutdown(Shutdown::Both);
    });
    let mut recv = match recv {
        Recv::Frames(frames) => frames,
        Recv::Response {
            frames,
            key,
            iv,
            auth,
        } => {
            // A damaged header ends the relay, and the send half is left to fail
            // on its own socket rather than joined: it may be parked on a read.
            if read_response(&mut sealed_read, &key, &iv, auth).is_none() {
                return;
            }
            frames
        }
    };
    let mut wire = Vec::new();
    while let Ok(Some(len)) = recv.open(&mut sealed_read, &mut wire) {
        if plain_write.write_all(&wire[..len]).is_err() {
            break;
        }
    }
    let _ = sealed_read.shutdown(Shutdown::Both);
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

/// Whether a config `security` word names the one data cipher here, or defers.
pub(crate) fn security_supported(word: &str) -> bool {
    matches!(
        word.trim().to_ascii_lowercase().as_str(),
        "" | "auto" | "chacha20-poly1305" | "chacha20-ietf-poly1305"
    )
}

/// What a request header carries: where to dial, and the keys both directions
/// are sealed under.
struct Request {
    /// Target the header names, already resolved.
    target: SocketAddr,
    /// Data key from client to server.
    key: [u8; 16],
    /// Data nonce base from client to server.
    iv: [u8; 16],
    /// Random byte the server must echo as its first response byte.
    auth: u8,
    /// Framing option bits the client asked for.
    options: u8,
}

impl Request {
    /// The keys the other direction is sealed under, each hashed once.
    fn response_material(&self) -> ([u8; 16], [u8; 16]) {
        (sha_prefix(&self.key), sha_prefix(&self.iv))
    }
}

/// Read and authenticate one `TCP` request header, `None` on any mismatch.
fn read_request(stream: &mut dyn Read, id: &[u8; 16]) -> Option<Request> {
    let mut auth = [0u8; AUTH_LEN];
    read_exact(stream, &mut auth).ok()?;
    let command = command_key(id);
    if !valid_auth_id(&command, &auth) {
        return None;
    }
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    read_exact(stream, &mut sealed_len).ok()?;
    let mut nonce = [0u8; 8];
    read_exact(stream, &mut nonce).ok()?;
    let clear_len = open_header(
        &command,
        &command,
        &auth,
        &nonce,
        LEN_AEAD_KEY,
        LEN_AEAD_IV,
        &sealed_len,
    )?;
    let len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if !(HEADER_MIN..=HEADER_MAX).contains(&len) {
        return None;
    }
    let mut sealed_header = vec![0u8; len + TAG_LEN];
    read_exact(stream, &mut sealed_header).ok()?;
    let header = open_header(
        &command,
        &command,
        &auth,
        &nonce,
        HEADER_KEY,
        HEADER_IV,
        &sealed_header,
    )?;
    parse_request(&header)
}

/// Build one request header and write it, returning the material it carries.
fn write_request(stream: &mut dyn Write, id: &[u8; 16], target: &SocketAddr) -> Option<Request> {
    let mut iv = [0u8; 16];
    getrandom::getrandom(&mut iv).ok()?;
    let mut key = [0u8; 16];
    getrandom::getrandom(&mut key).ok()?;
    let auth = random_byte()?;
    let padding = usize::from(auth % 16);
    let mut header = Vec::with_capacity(HEADER_MIN + padding + 4);
    header.push(VERSION);
    header.extend_from_slice(&iv);
    header.extend_from_slice(&key);
    header.push(auth);
    header.push(OPTIONS);
    header.push((padding as u8) << 4 | DATA_CIPHER);
    header.push(0);
    header.push(COMMAND_TCP);
    header.extend_from_slice(&target.port().to_be_bytes());
    push_addr(&mut header, target, 3);
    if padding > 0 {
        let mut noise = vec![0u8; padding];
        getrandom::getrandom(&mut noise).ok()?;
        header.extend_from_slice(&noise);
    }
    header.extend_from_slice(&fnv1a(&header).to_be_bytes());
    let command = command_key(id);
    let auth_id = make_auth_id(&command)?;
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).ok()?;
    let mut wire = Vec::with_capacity(AUTH_LEN + 18 + 8 + header.len() + TAG_LEN);
    wire.extend_from_slice(&auth_id);
    wire.extend_from_slice(&seal_header(
        &command,
        &command,
        &auth_id,
        &nonce,
        LEN_AEAD_KEY,
        LEN_AEAD_IV,
        &(header.len() as u16).to_be_bytes(),
    )?);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&seal_header(
        &command, &command, &auth_id, &nonce, HEADER_KEY, HEADER_IV, &header,
    )?);
    stream.write_all(&wire).ok()?;
    Some(Request {
        target: *target,
        key,
        iv,
        auth,
        options: OPTIONS,
    })
}

/// Read a decrypted request header, checking its checksum before its fields.
fn parse_request(header: &[u8]) -> Option<Request> {
    if header.len() < HEADER_MIN || header[0] != VERSION || header[34] & OPT_CHUNK == 0 {
        return None;
    }
    if header[35] & 0x0f != DATA_CIPHER || header[37] != COMMAND_TCP {
        return None;
    }
    let padding = usize::from(header[35] >> 4);
    let (address, addr_len) = socks_addr(&header[HEADER_MIN + 2..])?;
    let at = HEADER_MIN + 2 + addr_len;
    if at + padding + 4 > header.len() {
        return None;
    }
    let checksum = header[at + padding..at + padding + 4].try_into().ok()?;
    if fnv1a(&header[..at + padding]) != u32::from_be_bytes(checksum) {
        return None;
    }
    Some(Request {
        target: address.socket(port(&header[HEADER_MIN..])?)?,
        key: header[17..33].try_into().ok()?,
        iv: header[1..17].try_into().ok()?,
        auth: header[33],
        options: header[34],
    })
}

/// Seal the response header a client authenticates before its first frame.
///
/// Its payload is four bytes on every path both implementations speak: the
/// client's random byte, the response option byte, and the two bytes of the
/// command block an unencodable command leaves behind. Its two roots are the
/// response key and the response nonce base, which are different bytes.
fn response_header(key: &[u8; 16], iv: &[u8; 16], auth: u8) -> Option<Vec<u8>> {
    let mut out = seal_header(key, iv, b"", b"", LEN_KEY, LEN_IV, &[0, 4])?;
    out.extend_from_slice(&seal_header(
        key,
        iv,
        b"",
        b"",
        BODY_KEY,
        BODY_IV,
        &[auth, 0, 0, 0],
    )?);
    Some(out)
}

/// Open the response header, requiring the byte the client put in its request.
fn read_response(stream: &mut dyn Read, key: &[u8; 16], iv: &[u8; 16], auth: u8) -> Option<()> {
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    read_exact(stream, &mut sealed_len).ok()?;
    let clear_len = open_header(key, iv, b"", b"", LEN_KEY, LEN_IV, &sealed_len)?;
    let len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if !(4..=HEADER_MAX).contains(&len) {
        return None;
    }
    let mut sealed_body = vec![0u8; len + TAG_LEN];
    read_exact(stream, &mut sealed_body).ok()?;
    let clear = open_header(key, iv, b"", b"", BODY_KEY, BODY_IV, &sealed_body)?;
    (clear[0] == auth).then_some(())
}

/// Response length block key label.
const LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
/// Response length block nonce label.
const LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
/// Response payload key label.
const BODY_KEY: &[u8] = b"AEAD Resp Header Key";
/// Response payload nonce label.
const BODY_IV: &[u8] = b"AEAD Resp Header IV";
/// Request length block key label.
const LEN_AEAD_KEY: &[u8] = b"VMess Header AEAD Key_Length";
/// Request length block nonce label.
const LEN_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
/// Request payload key label.
const HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
/// Request payload nonce label.
const HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";
/// Auth id block key label.
const AUTH_KEY: &[u8] = b"AES Auth ID Encryption";

/// The `kdf` chain one header block derives from: its label, then the auth id
/// and the connection nonce when the block carries them. An absent element is
/// not an empty one — the two derive different keys, so they cannot unify.
fn chain<'a>(label: &'a [u8], aad: &'a [u8], nonce: &'a [u8]) -> Vec<&'a [u8]> {
    [label, aad, nonce]
        .into_iter()
        .filter(|element| !element.is_empty())
        .collect()
}

/// Seal one header block under its two `kdf` chains, the auth id as extra data.
fn seal_header(
    key_root: &[u8],
    iv_root: &[u8],
    aad: &[u8],
    nonce: &[u8],
    key_label: &[u8],
    iv_label: &[u8],
    clear: &[u8],
) -> Option<Vec<u8>> {
    let key = kdf_key(key_root, &chain(key_label, aad, nonce));
    let iv = kdf_nonce(iv_root, &chain(iv_label, aad, nonce));
    seal_gcm(&key, &iv, aad, clear)
}

/// Open one header block under its two `kdf` chains, its tag the last bytes.
fn open_header(
    key_root: &[u8],
    iv_root: &[u8],
    aad: &[u8],
    nonce: &[u8],
    key_label: &[u8],
    iv_label: &[u8],
    wire: &[u8],
) -> Option<Vec<u8>> {
    let key = kdf_key(key_root, &chain(key_label, aad, nonce));
    let iv = kdf_nonce(iv_root, &chain(iv_label, aad, nonce));
    open_gcm(&key, &iv, aad, wire)
}

/// Seal `clear` into its own buffer with the `AES-128-GCM` tag appended.
fn seal_gcm(key: &[u8; 16], iv: &[u8; 12], aad: &[u8], clear: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    let mut body = clear.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut body)
        .ok()?;
    body.extend_from_slice(&tag);
    Some(body)
}

/// Open one sealed block, its tag the last `TAG_LEN` bytes.
fn open_gcm(key: &[u8; 16], iv: &[u8; 12], aad: &[u8], wire: &[u8]) -> Option<Vec<u8>> {
    if wire.len() < TAG_LEN {
        return None;
    }
    let cipher = Aes128Gcm::new_from_slice(key).ok()?;
    let split = wire.len() - TAG_LEN;
    let mut body = wire[..split].to_vec();
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(iv), aad, &mut body, wire[split..].into())
        .ok()?;
    Some(body)
}

/// One data direction: counter, nonce base, and the stream masking its lengths.
pub(crate) struct Frames {
    /// Frame cipher for this direction.
    cipher: ChaCha20Poly1305,
    /// Nonce base; the counter occupies its first two bytes.
    iv: [u8; 16],
    /// Frames sealed or opened so far, which is the nonce.
    counter: u16,
    /// Length masking, absent when the peer asked for plain lengths.
    mask: Option<Masker>,
}

impl Frames {
    /// Key one direction from the data key and the option bits that chose it.
    fn new(key: &[u8; 16], iv: &[u8; 16], options: u8) -> Option<Self> {
        Some(Self {
            cipher: ChaCha20Poly1305::new_from_slice(&chacha_key(key)).ok()?,
            iv: *iv,
            counter: 0,
            mask: (options & OPT_MASK != 0).then(|| Masker::new(iv, options & OPT_PADDING != 0)),
        })
    }

    /// This frame's nonce, refusing the one that would reuse a counter.
    fn nonce(&mut self) -> Option<Nonce> {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        self.counter = self.counter.checked_add(1)?;
        Some(*Nonce::from_slice(&nonce))
    }

    /// Append one sealed frame: masked length, ciphertext, tag, clear padding.
    fn seal(&mut self, out: &mut Vec<u8>, clear: &[u8]) -> Option<()> {
        let nonce = self.nonce()?;
        let padding = usize::from(self.mask.as_mut().map_or(0, Masker::padding));
        let sealed = clear.len() + TAG_LEN;
        let total = sealed.checked_add(padding)?;
        if total > usize::from(u16::MAX) {
            return None;
        }
        let size = match &mut self.mask {
            Some(mask) => mask.mask(total as u16),
            None => total as u16,
        };
        out.extend_from_slice(&size.to_be_bytes());
        let at = out.len();
        out.extend_from_slice(clear);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, b"", &mut out[at..])
            .ok()?;
        out.extend_from_slice(&tag);
        if padding > 0 {
            out.resize(at + total, 0);
            getrandom::getrandom(&mut out[at + sealed..]).ok()?;
        }
        Some(())
    }

    /// Read one frame into `out`, `None` at the end marker or on damage.
    ///
    /// A frame's padding is part of the stream, so it is read before the end
    /// marker is reported: skipping it would read every later length one frame
    /// late. An empty plaintext is that marker, and a frame too short to hold a
    /// tag is damage; both stop the pump rather than being handed on.
    fn open(&mut self, stream: &mut dyn Read, out: &mut Vec<u8>) -> std::io::Result<Option<usize>> {
        let mut wire = [0u8; 2];
        read_exact(stream, &mut wire)?;
        let (sealed, padding) = match &mut self.mask {
            Some(mask) => {
                let padding = usize::from(mask.padding());
                let size = usize::from(mask.mask(u16::from_be_bytes(wire)));
                match size.checked_sub(padding) {
                    Some(remainder) if remainder >= TAG_LEN => (remainder, padding),
                    _ => return Ok(None),
                }
            }
            None => (usize::from(u16::from_be_bytes(wire)), 0),
        };
        out.resize(sealed + padding, 0);
        read_exact(stream, out)?;
        let clear_len = sealed - TAG_LEN;
        if clear_len == 0 {
            return Ok(None);
        }
        let Some(nonce) = self.nonce() else {
            return Ok(None);
        };
        let (body, tag) = out.split_at_mut(clear_len);
        self.cipher
            .decrypt_in_place_detached(&nonce, b"", body, (&tag[..TAG_LEN]).into())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        Ok(Some(clear_len))
    }
}

/// `SHAKE128` stream that masks chunk lengths and draws padding lengths.
struct Masker {
    /// Reader over the stream, two bytes drawn at a time.
    reader: sha3::Shake128Reader,
    /// Whether padding lengths come from the same stream.
    padding: bool,
}

impl Masker {
    /// Seed one direction's stream with that direction's nonce base.
    fn new(iv: &[u8; 16], padding: bool) -> Self {
        use sha3::digest::Update as _;
        let mut shake = Shake128::default();
        shake.update(iv);
        Self {
            reader: shake.finalize_xof(),
            padding,
        }
    }

    /// Two bytes of the stream, big endian.
    fn next(&mut self) -> u16 {
        let mut bytes = [0u8; 2];
        let _ = self.reader.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }

    /// Padding for the next frame, drawn before its length is masked.
    fn padding(&mut self) -> u16 {
        if self.padding {
            self.next() % 64
        } else {
            0
        }
    }

    /// The length as it goes on the wire.
    fn mask(&mut self, size: u16) -> u16 {
        self.next() ^ size
    }
}

/// The `VMess` `AEAD` key derivation: an `HMAC-SHA256` chain whose layers share
/// one hash object, so each outer pass re-feeds its own opad through the chain.
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let root = pads(KDF_ROOT);
    let mut inner = Sha256::new();
    inner.update(root.0);
    for layer in path {
        inner.update(pads(layer).0);
    }
    inner.update(key);
    for at in (0..path.len()).rev() {
        let digest = outer(&inner, &root.1);
        inner = Sha256::new();
        inner.update(root.0);
        for layer in &path[..at] {
            inner.update(pads(layer).0);
        }
        inner.update(pads(path[at]).1);
        inner.update(digest);
    }
    outer(&inner, &root.1)
}

/// `kdf` narrowed to an `AES` key.
fn kdf_key(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&kdf(key, path)[..16]);
    out
}

/// `kdf` narrowed to an `AEAD` nonce.
fn kdf_nonce(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(&kdf(key, path)[..12]);
    out
}

/// `HMAC-SHA256` pads for a key: the key xored into two pad blocks.
fn pads(key: &[u8]) -> ([u8; PAD_LEN], [u8; PAD_LEN]) {
    let mut flat = [0u8; PAD_LEN];
    match key.len() {
        0..=PAD_LEN => flat[..key.len()].copy_from_slice(key),
        _ => flat[..32].copy_from_slice(&Sha256::digest(key)),
    }
    let mut inner = [0x36u8; PAD_LEN];
    let mut outer = [0x5cu8; PAD_LEN];
    for (at, byte) in flat.iter().enumerate() {
        inner[at] ^= byte;
        outer[at] ^= byte;
    }
    (inner, outer)
}

/// The outer half of one `HMAC` layer: opad, then the inner digest.
fn outer(inner: &Sha256, opad: &[u8; PAD_LEN]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(opad);
    hash.update(inner.clone().finalize());
    hash.finalize().into()
}

/// The command key every request `KDF` starts from: the id and a fixed string.
fn command_key(id: &[u8; 16]) -> [u8; 16] {
    let mut context = md5::Context::new();
    context.consume(id);
    context.consume(COMMAND_MAGIC);
    context.compute().0
}

/// `ChaCha20-Poly1305` key from a 16-byte body key: two `MD5` rounds.
fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5::compute(key).0;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&md5::compute(first).0);
    out
}

/// First 16 bytes of `SHA-256`, which is what both response keys are.
fn sha_prefix(bytes: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&Sha256::digest(bytes)[..16]);
    out
}

/// One random byte, for the header padding a request is not without.
fn random_byte() -> Option<u8> {
    let mut byte = [0u8; 1];
    getrandom::getrandom(&mut byte).ok()?;
    Some(byte[0])
}

/// Seal an auth id: a timestamp, four random bytes and their `CRC-32`, one block.
fn make_auth_id(command: &[u8; 16]) -> Option<[u8; AUTH_LEN]> {
    let mut block = [0u8; AUTH_LEN];
    block[..8].copy_from_slice(&unix_now().cast_unsigned().to_be_bytes());
    getrandom::getrandom(&mut block[8..12]).ok()?;
    let checksum = crc32(&block[..12]).to_be_bytes();
    block[12..].copy_from_slice(&checksum);
    aes_block(&auth_key(command), &mut block, true)?;
    Some(block)
}

/// Whether an auth id is this user's, unexpired and not already accepted.
fn valid_auth_id(command: &[u8; 16], auth: &[u8; AUTH_LEN]) -> bool {
    let mut block = *auth;
    if aes_block(&auth_key(command), &mut block, false).is_none() {
        return false;
    }
    let checksum: [u8; 4] = block[12..].try_into().unwrap_or_default();
    if crc32(&block[..12]) != u32::from_be_bytes(checksum) {
        return false;
    }
    let stamp = i64::from_be_bytes(block[..8].try_into().unwrap_or_default());
    (stamp - unix_now()).abs() <= TIME_SKEW && fresh_auth(&block)
}

/// One `AES` block in place, which is what an auth id is made of.
fn aes_block(key: &[u8; 16], block: &mut [u8; AUTH_LEN], encrypt: bool) -> Option<()> {
    let cipher = Aes128::new_from_slice(key).ok()?;
    let block = GenericArray::from_mut_slice(block);
    if encrypt {
        cipher.encrypt_block(block);
    } else {
        cipher.decrypt_block(block);
    }
    Some(())
}

/// The auth id block key.
fn auth_key(command: &[u8; 16]) -> [u8; 16] {
    kdf_key(command, &[AUTH_KEY])
}

/// Remember an auth id, answering `false` when it was already accepted.
///
/// Two rotating sets cover the window: an id presented after the rotation is
/// still in the previous set, so a capture cannot be replayed across one. The
/// cap rotates early rather than growing, because an unbounded set is a memory
/// leak wearing a security hat.
fn fresh_auth(auth: &[u8; AUTH_LEN]) -> bool {
    static WINDOW: OnceLock<Mutex<ReplayWindow>> = OnceLock::new();
    let mut window = WINDOW
        .get_or_init(|| Mutex::new(ReplayWindow::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    window.insert(auth)
}

/// Two generations of accepted auth ids and when the current one started.
struct ReplayWindow {
    /// Ids accepted in the current generation.
    current: HashSet<[u8; AUTH_LEN]>,
    /// Ids accepted in the generation before it.
    previous: HashSet<[u8; AUTH_LEN]>,
    /// When the current generation started.
    rotated: Instant,
}

impl ReplayWindow {
    /// Two empty sets, both starting now.
    fn new() -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            rotated: Instant::now(),
        }
    }

    /// Record one id, rotating generations on a full window or a full set.
    fn insert(&mut self, auth: &[u8; AUTH_LEN]) -> bool {
        let elapsed = Instant::now().saturating_duration_since(self.rotated);
        if elapsed >= REPLAY_WINDOW * 2 {
            self.current.clear();
            self.previous.clear();
            self.rotated = Instant::now();
        } else if elapsed >= REPLAY_WINDOW || self.current.len() >= REPLAY_CAPACITY {
            self.previous = std::mem::take(&mut self.current);
            self.rotated = Instant::now();
        }
        if self.current.contains(auth) || self.previous.contains(auth) {
            return false;
        }
        self.current.insert(*auth);
        true
    }
}

/// Seconds since the epoch, saturating rather than failing a handshake.
fn unix_now() -> i64 {
    let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return i64::MAX;
    };
    i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
}

/// `CRC-32` (IEEE, reflected) over the twelve bytes an auth id checksums.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc = (crc >> 8) ^ CRC[((crc ^ u32::from(*byte)) & 0xff) as usize];
    }
    !crc
}

/// The `CRC-32` byte table.
static CRC: [u32; 256] = crc_table();

/// `CRC-32` (IEEE, reflected): the byte table the loop above folds.
const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut at = 0;
    while at < 256 {
        let mut value = at as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ 0xedb8_8320
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[at] = value;
        at += 1;
    }
    table
}

/// `FNV-1a` over a request header, the checksum its last four bytes carry.
fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A user id for the tests: two keys would hide a swapped-word bug.
    fn id() -> [u8; 16] {
        [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ]
    }

    /// A decrypted request header, so the parser can be handed one directly.
    fn clear_header(cipher: u8, command: u8) -> Vec<u8> {
        let mut header = vec![0u8; HEADER_MIN + 7];
        header[0] = VERSION;
        header[1..17].copy_from_slice(&[9u8; 16]);
        header[17..33].copy_from_slice(&[7u8; 16]);
        header[33] = 3;
        header[34] = OPTIONS;
        header[35] = cipher;
        header[37] = command;
        header[HEADER_MIN..HEADER_MIN + 2].copy_from_slice(&443u16.to_be_bytes());
        header[HEADER_MIN + 2] = 1;
        header[HEADER_MIN + 3..HEADER_MIN + 7].copy_from_slice(&[192, 0, 2, 53]);
        let checksum = fnv1a(&header).to_be_bytes();
        header.extend_from_slice(&checksum);
        header
    }

    #[test]
    fn checksums_match_their_definitions() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(fnv1a(b""), 0x811c_9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
    }

    #[test]
    fn the_kdf_chain_separates_its_elements() {
        let key = [7u8; 16];
        assert_eq!(kdf(&key, &[b"one", &key]), kdf(&key, &[b"one", &key]));
        assert_ne!(kdf(&key, &[b"one"]), kdf(&key, &[b"two"]));
        // An absent element is not an empty one: dropping it must not equal
        // chaining it, which is why `chain` filters rather than pads.
        assert_ne!(kdf(&key, &[b"one"]), kdf(&key, &[b"one", b""]));
        let wide = kdf(&key, &[b"one"]);
        assert_eq!(kdf_key(&key, &[b"one"]), wide[..16]);
        assert_eq!(kdf_nonce(&key, &[b"one"]), wide[..12]);
    }

    #[test]
    fn a_request_is_accepted_whole_and_refused_anywhere_damaged() {
        let mut wire = Vec::new();
        write_request(&mut wire, &id(), &"192.0.2.53:443".parse().expect("addr")).expect("writes");
        let request = read_request(&mut wire.as_slice(), &id()).expect("reads");
        assert_eq!(request.target.to_string(), "192.0.2.53:443");
        assert_eq!(request.options, OPTIONS);

        // Every single-byte change has to fail: a header that authenticates is
        // the only thing standing between a replay and a dial.
        for at in 0..wire.len() {
            let mut damaged = wire.clone();
            damaged[at] ^= 1;
            assert!(
                read_request(&mut damaged.as_slice(), &id()).is_none(),
                "byte {at} was accepted"
            );
        }
        // Another user's id derives a different command key, so nothing opens.
        let mut stranger = Vec::new();
        write_request(
            &mut stranger,
            &id(),
            &"192.0.2.53:443".parse().expect("addr"),
        )
        .expect("writes");
        assert!(read_request(&mut stranger.as_slice(), &[9u8; 16]).is_none());
    }

    #[test]
    fn a_replayed_request_is_refused() {
        let mut wire = Vec::new();
        let target: SocketAddr = "192.0.2.53:443".parse().expect("addr");
        write_request(&mut wire, &id(), &target).expect("writes");
        assert!(read_request(&mut wire.as_slice(), &id()).is_some());
        assert!(read_request(&mut wire.as_slice(), &id()).is_none());
    }

    #[test]
    fn only_this_rungs_cipher_and_command_are_served() {
        assert!(parse_request(&clear_header(DATA_CIPHER, COMMAND_TCP)).is_some());
        assert!(parse_request(&clear_header(3, COMMAND_TCP)).is_none());
        assert!(parse_request(&clear_header(5, COMMAND_TCP)).is_none());
        assert!(parse_request(&clear_header(DATA_CIPHER, 2)).is_none());
        assert!(parse_request(&clear_header(DATA_CIPHER, COMMAND_TCP | 4)).is_none());
        assert!(security_supported("auto") && security_supported("ChaCha20-Poly1305"));
        assert!(!security_supported("aes-128-gcm") && !security_supported("none"));
    }

    #[test]
    fn frames_carry_their_plaintext_and_stop_at_the_end_marker() {
        let key = [5u8; 16];
        let iv = [6u8; 16];
        let mut send = Frames::new(&key, &iv, OPTIONS).expect("keys");
        let mut recv = Frames::new(&key, &iv, OPTIONS).expect("keys");
        let mut wire = Vec::new();
        for clear in [
            b"one frame".as_slice(),
            [9u8; 3000].as_slice(),
            b"tail".as_slice(),
        ] {
            send.seal(&mut wire, clear).expect("seals");
        }
        send.seal(&mut wire, b"").expect("seals the end marker");
        let mut back = Vec::new();
        let mut cursor = wire.as_slice();
        assert_eq!(recv.open(&mut cursor, &mut back).expect("opens"), Some(9));
        assert_eq!(&back[..9], b"one frame");
        assert_eq!(
            recv.open(&mut cursor, &mut back).expect("opens"),
            Some(3000)
        );
        assert_eq!(back[..3000], [9u8; 3000]);
        assert_eq!(recv.open(&mut cursor, &mut back).expect("opens"), Some(4));
        assert_eq!(recv.open(&mut cursor, &mut back).expect("opens"), None);

        let mut damaged = wire.clone();
        damaged[8] ^= 1;
        let mut fresh = Frames::new(&key, &iv, OPTIONS).expect("keys");
        let mut cursor = damaged.as_slice();
        assert!(fresh.open(&mut cursor, &mut back).is_err());
    }

    #[test]
    fn the_response_header_needs_the_byte_the_request_chose() {
        let request = write_request(
            &mut Vec::new(),
            &id(),
            &"192.0.2.53:443".parse().expect("addr"),
        )
        .expect("writes");
        let (key, iv) = request.response_material();
        let header = response_header(&key, &iv, request.auth).expect("seals");
        assert!(read_response(&mut header.as_slice(), &key, &iv, request.auth).is_some());
        assert!(read_response(&mut header.as_slice(), &key, &iv, request.auth ^ 1).is_none());
        let mut damaged = header.clone();
        damaged[20] ^= 1;
        assert!(read_response(&mut damaged.as_slice(), &key, &iv, request.auth).is_none());
    }

    #[test]
    fn the_two_roles_carry_an_echo_both_ways() {
        let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 4096];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let relay = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = relay.local_addr().expect("addr").port();
        let user = id();
        thread::spawn(move || {
            for stream in relay.incoming().take(1) {
                let Ok(stream) = stream else { continue };
                serve(stream, &user, true);
            }
        });

        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let Some((send, recv)) = client_handshake(&mut uplink, &id(), &target) else {
            panic!("the client handshake failed");
        };
        let pair = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let pair_port = pair.local_addr().expect("addr").port();
        let mut peer = TcpStream::connect(("127.0.0.1", pair_port)).expect("connects");
        // A relay that never answers must fail this test rather than hang it.
        peer.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("sets");
        let (plain, _) = pair.accept().expect("accepts");
        thread::spawn(move || pump_relay(&plain, &uplink, send, recv));

        for len in [64usize, 150_000] {
            let payload: Vec<u8> = (0..len).map(|at| (at as u8) ^ 0x5a).collect();
            let mut echoed = vec![0u8; len];
            peer.write_all(&payload).expect("writes");
            peer.read_exact(&mut echoed).expect("echoes");
            assert_eq!(echoed, payload, "payload came back altered at {len} bytes");
        }
        drop(peer);
    }
}
