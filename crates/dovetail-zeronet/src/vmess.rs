//! `VMess` `AEAD` framing over blocking `TCP`, both roles.
//!
//! Request header, response header and length-masked data frames; only `TCP`
//! command exists here, anything else closes fast rather than hanging a suite.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::proxy::read_exact;

/// Wire auth id bytes.
const AUTH_LEN: usize = 16;
/// `AEAD` tag bytes per sealed block.
const TAG_LEN: usize = 16;
/// Largest plaintext bytes per data frame, matching the oracle's framing.
const MAX_PLAIN: usize = 8192;
/// Option bits that change data framing.
const OPT_STREAM: u8 = 0x01;
/// Option bit for `SHAKE`-masked lengths.
const OPT_MASK: u8 = 0x04;
/// Option bit for cleartext padding after each frame.
const OPT_PAD: u8 = 0x08;

/// Data cipher negotiated in the request header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    /// Negotiate, always sent as `ChaCha20-Poly1305` like the oracle client does.
    Auto,
    /// `AES-128-GCM` data frames.
    Aes,
    /// `ChaCha20-Poly1305` data frames.
    Chacha,
    /// Plaintext frames with no `AEAD`.
    None,
}

impl Cipher {
    /// Parse a config `security` word, defaulting to `Auto`.
    pub(crate) fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Self::Chacha,
            "none" => Self::None,
            _ => Self::Auto,
        }
    }
    /// Wire code actually sent, with `Auto` resolved.
    fn code(self) -> u8 {
        match self {
            Self::Auto | Self::Chacha => 4,
            Self::Aes => 3,
            Self::None => 5,
        }
    }
    /// Cipher from a wire code, `None` on any other value.
    fn from_code(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::Aes),
            4 => Some(Self::Chacha),
            5 => Some(Self::None),
            _ => None,
        }
    }
}

/// Seen auth ids, rejecting verbatim replays within this process.
fn replay_seen(id: &[u8; AUTH_LEN]) -> bool {
    static SEEN: OnceLock<Mutex<HashSet<[u8; AUTH_LEN]>>> = OnceLock::new();
    let mut guard = SEEN
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    !guard.insert(*id)
}

/// `HMAC-SHA256` pads for a key.
fn hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    use sha2::Digest as _;
    let mut flat = [0u8; 64];
    if key.len() > 64 {
        flat[..32].copy_from_slice(&sha2::Sha256::digest(key));
    } else {
        flat[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..64 {
        inner[i] ^= flat[i];
        outer[i] ^= flat[i];
    }
    (inner, outer)
}

/// One `HMAC-SHA256` with restartable state.
struct Hmac {
    /// Inner hash with its pad already fed.
    inner: sha2::Sha256,
    /// Outer hash with its pad already fed.
    outer: sha2::Sha256,
    /// Fresh inner for restarts.
    fresh_inner: sha2::Sha256,
    /// Fresh outer for restarts.
    fresh_outer: sha2::Sha256,
}

impl Hmac {
    /// New `HMAC` under `key`.
    fn fresh(key: &[u8]) -> Self {
        use sha2::Digest as _;
        let (ipad, opad) = hmac_pads(key);
        let mut inner = sha2::Sha256::new();
        let mut outer = sha2::Sha256::new();
        inner.update(ipad);
        outer.update(opad);
        Self {
            fresh_inner: inner.clone(),
            fresh_outer: outer.clone(),
            inner,
            outer,
        }
    }
    /// Feed bytes to the inner hash.
    fn push(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.inner.update(data);
    }
    /// Restore the post-pad state.
    fn restart(&mut self) {
        self.inner = self.fresh_inner.clone();
        self.outer = self.fresh_outer.clone();
    }
    /// Finalize the `HMAC`.
    fn digest(&mut self) -> [u8; 32] {
        use sha2::Digest as _;
        let mid = self.inner.clone().finalize();
        let mut outer = self.outer.clone();
        outer.update(mid);
        outer.finalize().into()
    }
}

/// Nested `VMess` key schedule, one link per path element.
enum Kdf {
    /// Bottom link keyed by the fixed salt.
    Root(Box<Hmac>),
    /// Upper link keyed by one path element over the link below.
    Link {
        below: Box<Kdf>,
        seal_in: [u8; 64],
        seal_out: [u8; 64],
    },
}

impl Kdf {
    /// Bottom link under the fixed salt.
    fn root() -> Self {
        Self::Root(Box::new(Hmac::fresh(b"VMess AEAD KDF")))
    }
    /// Wrap the schedule with one more path element.
    fn wrap(mut self, key: &[u8]) -> Self {
        let (seal_in, seal_out) = hmac_pads(key);
        self.push(&seal_in);
        Self::Link {
            below: Box::new(self),
            seal_in,
            seal_out,
        }
    }
    /// Feed bytes through to the bottom link.
    fn push(&mut self, data: &[u8]) {
        match self {
            Self::Root(h) => h.push(data),
            Self::Link { below, .. } => below.push(data),
        }
    }
    /// Restore every link to its post-pad state.
    fn restart(&mut self) {
        match self {
            Self::Root(h) => h.restart(),
            Self::Link { below, seal_in, .. } => {
                below.restart();
                below.push(seal_in);
            }
        }
    }
    /// Finalize the whole schedule.
    fn digest(&mut self) -> [u8; 32] {
        match self {
            Self::Root(h) => h.digest(),
            Self::Link {
                below, seal_out, ..
            } => {
                let mid = below.digest();
                below.restart();
                below.push(seal_out);
                below.push(&mid);
                below.digest()
            }
        }
    }
}

/// `VMess` key schedule over `key` and `path`.
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut chain = Kdf::root();
    for layer in path {
        chain = chain.wrap(layer);
    }
    chain.push(key);
    chain.digest()
}

/// First sixteen bytes of the schedule.
fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

/// `MD5` of two slices concatenated.
fn md5_two(first: &[u8], second: &[u8]) -> [u8; 16] {
    let mut input = Vec::with_capacity(first.len() + second.len());
    input.extend_from_slice(first);
    input.extend_from_slice(second);
    md5::compute(input).0
}

/// Instruction key: `MD5` of the uuid bytes plus the fixed magic.
fn instruction_key(uuid: &[u8; 16]) -> [u8; 16] {
    md5_two(uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21")
}

/// Thirty-two-byte `ChaCha` key from a sixteen-byte data key.
fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5::compute(key).0;
    let second = md5::compute(first).0;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

/// `IEEE CRC-32`, bit at a time; auth ids are twelve bytes so this never matters.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// `FNV-1a` over the clear request header.
fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

/// Fill a buffer with portable randomness, false when the platform has none.
fn random_into(buf: &mut [u8]) -> bool {
    getrandom::getrandom(buf).is_ok()
}

/// Current unix seconds, zero when the clock is before the epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One `AES-ECB` block either way.
fn aes_block(key: &[u8; 16], block: &mut [u8; 16], encrypt: bool) -> bool {
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as _};
    let Ok(cipher) = aes::Aes128::new_from_slice(key) else {
        return false;
    };
    let cell = aes::cipher::generic_array::GenericArray::from_mut_slice(block.as_mut_slice());
    if encrypt {
        cipher.encrypt_block(cell);
    } else {
        cipher.decrypt_block(cell);
    }
    true
}

/// Seal a header block under `AES-128-GCM`.
fn seal_header(key: &[u8; 16], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let mut body = plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut body)
        .ok()?;
    body.extend_from_slice(&tag);
    Some(body)
}

/// Open a header block sealed the same way.
fn open_header(key: &[u8; 16], nonce: &[u8; 12], sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;
    if sealed.len() < TAG_LEN {
        return None;
    }
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let split = sealed.len() - TAG_LEN;
    let mut body = sealed[..split].to_vec();
    cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(nonce),
            aad,
            &mut body,
            aes_gcm::Tag::from_slice(&sealed[split..]),
        )
        .ok()?;
    Some(body)
}

/// Response key and iv from the data key and iv.
fn response_material(data_iv: &[u8; 16], data_key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use sha2::Digest as _;
    let iv: [u8; 16] = sha2::Sha256::digest(data_iv)[..16].try_into().unwrap();
    let key: [u8; 16] = sha2::Sha256::digest(data_key)[..16].try_into().unwrap();
    (key, iv)
}

/// Sealed response prefix the server sends right after the request.
fn response_prefix(response_key: &[u8; 16], response_iv: &[u8; 16], auth: u8) -> Option<Vec<u8>> {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_full = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let mut out = seal_header(&len_key, &len_nonce, &[0, 4], &[])?;
    let body_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let body_full = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let body_nonce: [u8; 12] = body_full[..12].try_into().unwrap();
    out.extend_from_slice(&seal_header(&body_key, &body_nonce, &[auth, 0, 0, 0], &[])?);
    Some(out)
}

/// Fresh auth id for one request.
fn make_auth_id(instruction: &[u8; 16]) -> Option<[u8; 16]> {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&now_secs().to_be_bytes());
    if !random_into(&mut plain[8..12]) {
        return None;
    }
    let checksum = crc32(&plain[..12]).to_be_bytes();
    plain[12..].copy_from_slice(&checksum);
    let key = kdf16(instruction, &[b"AES Auth ID Encryption"]);
    if !aes_block(&key, &mut plain, true) {
        return None;
    }
    Some(plain)
}

/// Whether an auth id decrypts, checksums and sits inside the time window.
fn valid_auth_id(instruction: &[u8; 16], auth_id: &[u8; 16]) -> bool {
    let key = kdf16(instruction, &[b"AES Auth ID Encryption"]);
    let mut plain = *auth_id;
    if !aes_block(&key, &mut plain, false) {
        return false;
    }
    if crc32(&plain[..12]) != u32::from_be_bytes(plain[12..].try_into().unwrap()) {
        return false;
    }
    u64::from_be_bytes(plain[..8].try_into().unwrap()).abs_diff(now_secs()) <= 120
}

/// Length-masking `SHAKE128` stream, one per direction when negotiated.
struct Shake {
    /// Expanding reader seeded with that direction's iv.
    reader: sha3::Shake128Reader,
    /// Whether trailing padding lengths are drawn.
    padding: bool,
}

impl Shake {
    /// Seed the stream with a direction iv.
    fn fresh(iv: &[u8; 16], padding: bool) -> Self {
        use sha3::digest::{ExtendableOutput as _, Update as _};
        let mut shake = sha3::Shake128::default();
        shake.update(iv);
        Self {
            reader: shake.finalize_xof(),
            padding,
        }
    }
    /// Next two-byte draw.
    fn draw(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        sha3::digest::XofReader::read(&mut self.reader, &mut buf);
        u16::from_be_bytes(buf)
    }
    /// Padding length first, then the caller draws the mask.
    fn pad_len(&mut self) -> u16 {
        if self.padding {
            self.draw() % 64
        } else {
            0
        }
    }
}

/// One direction's data cipher plus its counter and optional masker.
pub(crate) struct Flow {
    /// Negotiated cipher for this direction.
    cipher: Cipher,
    /// `AES` cipher when negotiated.
    aes: Option<aes_gcm::Aes128Gcm>,
    /// `ChaCha` cipher when negotiated.
    chacha: Option<chacha20poly1305::ChaCha20Poly1305>,
    /// Direction iv, seeding nonces and masking.
    iv: [u8; 16],
    /// Frames sealed or opened so far.
    counter: u16,
    /// Masking stream when the peer negotiated it.
    shake: Option<Shake>,
}

impl Flow {
    /// Build a direction from the negotiated cipher, key, iv and options.
    fn fresh(
        cipher: Cipher,
        key: &[u8; 16],
        iv: &[u8; 16],
        options: u8,
        mask_seed: &[u8; 16],
    ) -> Option<Self> {
        use aes_gcm::KeyInit as _;
        let masking = options & OPT_MASK != 0;
        let padding = options & OPT_PAD != 0;
        let actual = match cipher {
            Cipher::Auto => Cipher::Chacha,
            other => other,
        };
        let (aes, chacha) = match actual {
            Cipher::Aes => (Some(aes_gcm::Aes128Gcm::new_from_slice(key).ok()?), None),
            Cipher::Chacha => {
                let expanded = chacha_key(key);
                (
                    None,
                    Some(chacha20poly1305::ChaCha20Poly1305::new_from_slice(&expanded).ok()?),
                )
            }
            Cipher::None => (None, None),
            Cipher::Auto => return None,
        };
        let shake = masking.then(|| Shake::fresh(mask_seed, padding));
        Some(Self {
            cipher: actual,
            aes,
            chacha,
            iv: *iv,
            counter: 0,
            shake,
        })
    }
    /// Nonce for the current counter.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        nonce
    }
    /// Seal one plaintext slice onto `out`.
    fn seal_onto(&mut self, plain: &[u8], out: &mut Vec<u8>) -> bool {
        let at = out.len();
        out.extend_from_slice(plain);
        let sealed = match (&self.aes, &self.chacha) {
            (Some(aes), None) => {
                use aes_gcm::aead::AeadInPlace as _;
                let nonce = self.nonce();
                match aes.encrypt_in_place_detached(
                    aes_gcm::Nonce::from_slice(&nonce),
                    b"",
                    &mut out[at..],
                ) {
                    Ok(tag) => {
                        out.extend_from_slice(&tag);
                        true
                    }
                    Err(_) => false,
                }
            }
            (None, Some(chacha)) => {
                use chacha20poly1305::aead::AeadInPlace as _;
                let nonce = self.nonce();
                match chacha.encrypt_in_place_detached(
                    chacha20poly1305::Nonce::from_slice(&nonce),
                    b"",
                    &mut out[at..],
                ) {
                    Ok(tag) => {
                        out.extend_from_slice(&tag);
                        true
                    }
                    Err(_) => false,
                }
            }
            (None, None) => true,
            _ => false,
        };
        if !sealed {
            out.truncate(at);
            return false;
        }
        if self.counter == u16::MAX {
            out.truncate(at);
            return false;
        }
        self.counter += 1;
        true
    }
    /// Open one sealed chunk in place, returning its plaintext length.
    fn open_chunk(&mut self, chunk: &mut [u8]) -> Option<usize> {
        let plain_len = match (&self.aes, &self.chacha) {
            (Some(aes), None) => {
                use aes_gcm::aead::AeadInPlace as _;
                if chunk.len() < TAG_LEN {
                    return None;
                }
                let nonce = self.nonce();
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                aes.decrypt_in_place_detached(
                    aes_gcm::Nonce::from_slice(&nonce),
                    b"",
                    body,
                    aes_gcm::Tag::from_slice(tag),
                )
                .ok()?;
                split
            }
            (None, Some(chacha)) => {
                use chacha20poly1305::aead::AeadInPlace as _;
                if chunk.len() < TAG_LEN {
                    return None;
                }
                let nonce = self.nonce();
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                chacha
                    .decrypt_in_place_detached(
                        chacha20poly1305::Nonce::from_slice(&nonce),
                        b"",
                        body,
                        chacha20poly1305::Tag::from_slice(tag),
                    )
                    .ok()?;
                split
            }
            (None, None) => chunk.len(),
            _ => return None,
        };
        if self.counter == u16::MAX {
            return None;
        }
        self.counter += 1;
        Some(plain_len)
    }
}

/// Encode port plus address in the order the header carries them.
fn encode_target(out: &mut Vec<u8>, target: &SocketAddr) {
    out.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
    }
}

/// Decode the same encoding, resolving domain names where they appear.
fn decode_target(header: &[u8], cursor: &mut usize) -> Option<SocketAddr> {
    if *cursor + 3 > header.len() {
        return None;
    }
    let port = u16::from_be_bytes([header[*cursor], header[*cursor + 1]]);
    *cursor += 2;
    match header[*cursor] {
        1 => {
            *cursor += 1;
            if *cursor + 4 > header.len() {
                return None;
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&header[*cursor..*cursor + 4]);
            *cursor += 4;
            Some(SocketAddr::new(std::net::IpAddr::V4(ip.into()), port))
        }
        2 => {
            *cursor += 1;
            let len = usize::from(*header.get(*cursor)?);
            *cursor += 1;
            if *cursor + len > header.len() {
                return None;
            }
            let host = std::str::from_utf8(&header[*cursor..*cursor + len]).ok()?;
            *cursor += len;
            format!("{host}:{port}").to_socket_addrs().ok()?.next()
        }
        3 => {
            *cursor += 1;
            if *cursor + 16 > header.len() {
                return None;
            }
            let ip: [u8; 16] = header[*cursor..*cursor + 16].try_into().unwrap();
            *cursor += 16;
            Some(SocketAddr::new(std::net::IpAddr::V6(ip.into()), port))
        }
        _ => None,
    }
}

/// Request bytes plus the session keys they were sealed under.
type RequestParts = (Vec<u8>, [u8; 16], [u8; 16], u8);

/// Build a client request and its session keys.
fn request_bytes(uuid: &[u8; 16], cipher: Cipher, target: &SocketAddr) -> Option<RequestParts> {
    let instruction = instruction_key(uuid);
    let auth_id = make_auth_id(&instruction)?;
    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    let mut auth = [0u8; 1];
    let mut nonce = [0u8; 8];
    if !random_into(&mut data_iv) || !random_into(&mut data_key) {
        return None;
    }
    if !random_into(&mut auth) || !random_into(&mut nonce) {
        return None;
    }
    let mut pad_len = [0u8; 1];
    if !random_into(&mut pad_len) {
        return None;
    }
    let pad_len = usize::from(pad_len[0] % 16);
    let options = OPT_STREAM | OPT_MASK | OPT_PAD;
    let mut clear = Vec::with_capacity(64);
    clear.push(1);
    clear.extend_from_slice(&data_iv);
    clear.extend_from_slice(&data_key);
    clear.push(auth[0]);
    clear.push(options);
    clear.push((pad_len as u8) << 4 | cipher.code());
    clear.push(0);
    clear.push(1);
    encode_target(&mut clear, target);
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        if !random_into(&mut pad) {
            return None;
        }
        clear.extend_from_slice(&pad);
    }
    clear.extend_from_slice(&fnv1a(&clear).to_be_bytes());
    let len_key = kdf16(
        &instruction,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_full = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let sealed_len = seal_header(
        &len_key,
        &len_nonce,
        &(clear.len() as u16).to_be_bytes(),
        &auth_id,
    )?;
    let head_key = kdf16(&instruction, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
    let head_full = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let head_nonce: [u8; 12] = head_full[..12].try_into().unwrap();
    let sealed_head = seal_header(&head_key, &head_nonce, &clear, &auth_id)?;
    let mut request = Vec::with_capacity(16 + 18 + 8 + sealed_head.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&sealed_len);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&sealed_head);
    Some((request, data_key, data_iv, auth[0]))
}

/// Read one sealed length plus its padding draws.
fn read_wire_len(stream: &mut TcpStream, shake: Option<&mut Shake>) -> Option<(usize, usize)> {
    let mut prefix = [0u8; 2];
    read_exact(stream, &mut prefix).ok()?;
    let wire = u16::from_be_bytes(prefix);
    match shake {
        None => Some((usize::from(wire), 0)),
        Some(sizes) => {
            let padding = usize::from(sizes.pad_len());
            let total = usize::from(sizes.draw() ^ wire);
            Some((total, padding))
        }
    }
}

/// Write one data frame carrying `plain`.
fn write_frame(stream: &mut TcpStream, send: &mut Flow, plain: &[u8]) -> bool {
    let mut sealed = Vec::with_capacity(plain.len() + TAG_LEN + 64);
    if !send.seal_onto(plain, &mut sealed) {
        return false;
    }
    let encrypted = sealed.len();
    let padding = send.shake.as_mut().map_or(0, |s| usize::from(s.pad_len()));
    let total = encrypted + padding;
    if total > u16::MAX as usize {
        return false;
    }
    let wire = send
        .shake
        .as_mut()
        .map_or(total as u16, |s| s.draw() ^ total as u16);
    if stream.write_all(&wire.to_be_bytes()).is_err() {
        return false;
    }
    if stream.write_all(&sealed).is_err() {
        return false;
    }
    if padding > 0 {
        let mut noise = vec![0u8; padding];
        if !random_into(&mut noise) {
            return false;
        }
        if stream.write_all(&noise).is_err() {
            return false;
        }
    }
    true
}

/// Read one data frame, returning its plaintext or `None` on error.
fn read_frame(stream: &mut TcpStream, recv: &mut Flow) -> Option<Vec<u8>> {
    let (total, padding) = read_wire_len(stream, recv.shake.as_mut())?;
    if total <= padding {
        let mut discard = vec![0u8; total];
        read_exact(stream, &mut discard).ok()?;
        return Some(Vec::new());
    }
    if total - padding
        < match recv.cipher {
            Cipher::None => 0,
            _ => TAG_LEN,
        }
    {
        return None;
    }
    let mut wire = vec![0u8; total];
    read_exact(stream, &mut wire).ok()?;
    let payload = total - padding;
    let plain_len = recv.open_chunk(&mut wire[..payload])?;
    if plain_len == 0 {
        return Some(Vec::new());
    }
    Some(wire[..plain_len].to_vec())
}

/// Client session: both directions plus the response keys to consume.
pub(crate) type ClientSession = (Flow, Flow, [u8; 16], [u8; 16], u8);
/// Dial a `VMess` server for a target, returning the two directions.
pub(crate) fn client_handshake(
    uplink: &mut TcpStream,
    id: &[u8; 16],
    cipher: Cipher,
    target: &SocketAddr,
) -> Option<ClientSession> {
    let (request, data_key, data_iv, auth) = request_bytes(id, cipher, target)?;
    if uplink.write_all(&request).is_err() {
        return None;
    }
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let options = OPT_STREAM | OPT_MASK | OPT_PAD;
    let actual = match cipher {
        Cipher::Auto => Cipher::Chacha,
        other => other,
    };
    let send = Flow::fresh(actual, &data_key, &data_iv, options, &data_iv)?;
    let recv = Flow::fresh(actual, &response_key, &response_iv, options, &response_iv)?;
    Some((send, recv, response_key, response_iv, auth))
}

/// Read and check the server's response header on a client stream.
fn read_response(
    stream: &mut TcpStream,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    auth: u8,
) -> bool {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_full = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    if read_exact(stream, &mut sealed_len).is_err() {
        return false;
    }
    let Some(clear_len) = open_header(&len_key, &len_nonce, &sealed_len, &[]) else {
        return false;
    };
    if clear_len.len() != 2 {
        return false;
    }
    let body_len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if body_len > 64 {
        return false;
    }
    let mut sealed_body = vec![0u8; body_len + TAG_LEN];
    if read_exact(stream, &mut sealed_body).is_err() {
        return false;
    }
    let body_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let body_full = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let body_nonce: [u8; 12] = body_full[..12].try_into().unwrap();
    let Some(clear_body) = open_header(&body_key, &body_nonce, &sealed_body, &[]) else {
        return false;
    };
    clear_body.len() == 4 && clear_body[0] == auth
}

/// Read and open one sealed request header, returning its clear bytes.
fn read_open_header(
    stream: &mut TcpStream,
    instruction: &[u8; 16],
    auth_id: &[u8; AUTH_LEN],
) -> Option<Vec<u8>> {
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    read_exact(stream, &mut sealed_len).ok()?;
    let mut nonce = [0u8; 8];
    read_exact(stream, &mut nonce).ok()?;
    let len_key = kdf16(
        instruction,
        &[b"VMess Header AEAD Key_Length", auth_id, &nonce],
    );
    let len_full = kdf(
        instruction,
        &[b"VMess Header AEAD Nonce_Length", auth_id, &nonce],
    );
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let clear_len = open_header(&len_key, &len_nonce, &sealed_len, auth_id)?;
    if clear_len.len() != 2 {
        return None;
    }
    let head_len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if !(38..=4096).contains(&head_len) {
        return None;
    }
    let mut sealed_head = vec![0u8; head_len + TAG_LEN];
    read_exact(stream, &mut sealed_head).ok()?;
    let head_key = kdf16(instruction, &[b"VMess Header AEAD Key", auth_id, &nonce]);
    let head_full = kdf(instruction, &[b"VMess Header AEAD Nonce", auth_id, &nonce]);
    let head_nonce: [u8; 12] = head_full[..12].try_into().unwrap();
    open_header(&head_key, &head_nonce, &sealed_head, auth_id)
}
/// Decode clear header bytes into its target, flows and response prefix.
fn decode_header(header: &[u8]) -> Option<(SocketAddr, Flow, Flow, Vec<u8>)> {
    if header.len() < 38 || header[0] != 1 || header[34] & OPT_STREAM == 0 {
        return None;
    }
    if header[37] != 1 {
        return None;
    }
    let cipher = Cipher::from_code(header[35] & 0x0f)?;
    let options = header[34];
    let mut cursor = 38;
    let target = decode_target(header, &mut cursor)?;
    let margin = usize::from(header[35] >> 4);
    if cursor + margin + 4 > header.len() {
        return None;
    }
    cursor += margin;
    if fnv1a(&header[..cursor])
        != u32::from_be_bytes(header[cursor..cursor + 4].try_into().unwrap())
    {
        return None;
    }
    let data_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let data_key: [u8; 16] = header[17..33].try_into().unwrap();
    let auth = header[33];
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let prefix = response_prefix(&response_key, &response_iv, auth)?;
    let recv = Flow::fresh(cipher, &data_key, &data_iv, options, &data_iv)?;
    let send = Flow::fresh(cipher, &response_key, &response_iv, options, &response_iv)?;
    Some((target, send, recv, prefix))
}
/// Read and check one request, returning its target and both directions.
fn accept_request(
    stream: &mut TcpStream,
    id: &[u8; 16],
) -> Option<(SocketAddr, Flow, Flow, Vec<u8>)> {
    let mut auth_id = [0u8; AUTH_LEN];
    read_exact(stream, &mut auth_id).ok()?;
    let instruction = instruction_key(id);
    if !valid_auth_id(&instruction, &auth_id) || replay_seen(&auth_id) {
        return None;
    }
    let header = read_open_header(stream, &instruction, &auth_id)?;
    decode_header(&header)
}

/// Accept one `VMess` connection, dial its target and relay sealed both ways.
pub(crate) fn serve(mut stream: TcpStream, id: &[u8; 16], freedom: bool) {
    let Some((target, send, recv, prefix)) = accept_request(&mut stream, id) else {
        return;
    };
    if !freedom {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if stream.write_all(&prefix).is_err() {
        return;
    }
    pump_relay(&uplink, &stream, send, recv, None);
}

/// Response keys the client still has to consume, read on first reply.
pub(crate) type PendingResponse = ([u8; 16], [u8; 16], u8);

/// Relay plaintext one side against sealed frames the other, both ways to close.
pub(crate) fn pump_relay(
    plain: &TcpStream,
    sealed: &TcpStream,
    send: Flow,
    recv: Flow,
    pending: Option<PendingResponse>,
) {
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
        let mut buf = vec![0u8; MAX_PLAIN];
        while let Ok(read) = plain_read.read(&mut buf) {
            if read == 0 {
                let _ = write_frame(&mut sealed_write, &mut send, &[]);
                break;
            }
            let mut at = 0;
            let mut ok = true;
            while at < read {
                let end = (at + MAX_PLAIN).min(read);
                if !write_frame(&mut sealed_write, &mut send, &buf[at..end]) {
                    ok = false;
                    break;
                }
                at = end;
            }
            if !ok {
                break;
            }
        }
        let _ = plain_read.shutdown(Shutdown::Both);
        let _ = sealed_write.shutdown(Shutdown::Both);
    });
    let mut recv = recv;
    if let Some((response_key, response_iv, auth)) = pending {
        if !read_response(&mut sealed_read, &response_key, &response_iv, auth) {
            let _ = sealed_read.shutdown(Shutdown::Both);
            let _ = plain_write.shutdown(Shutdown::Both);
            let _ = done.join();
            return;
        }
    }
    loop {
        match read_frame(&mut sealed_read, &mut recv) {
            Some(chunk) if chunk.is_empty() => break,
            Some(chunk) => {
                if plain_write.write_all(&chunk).is_err() {
                    break;
                }
            }
            None => break,
        }
    }
    let _ = sealed_read.shutdown(Shutdown::Both);
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn instruction_splits_uuid_and_magic() {
        let uuid = [0x11u8; 16];
        assert_ne!(instruction_key(&uuid), uuid);
        assert_eq!(instruction_key(&uuid), instruction_key(&uuid));
    }

    #[test]
    fn auth_ids_round_trip_and_reject_damage() {
        let instruction = instruction_key(&[0x22u8; 16]);
        let id = make_auth_id(&instruction).expect("makes");
        assert!(valid_auth_id(&instruction, &id));
        let mut bad = id;
        bad[0] ^= 1;
        assert!(!valid_auth_id(&instruction, &bad));
    }

    #[test]
    fn headers_open_that_seal_sealed() {
        let key = [0x33u8; 16];
        let nonce = [0x44u8; 12];
        let sealed = seal_header(&key, &nonce, b"length-is-framing", b"aad").expect("seals");
        let back = open_header(&key, &nonce, &sealed, b"aad").expect("opens");
        assert_eq!(back, b"length-is-framing");
        let mut cut = sealed.clone();
        cut.pop();
        assert!(open_header(&key, &nonce, &cut, b"aad").is_none());
    }

    #[test]
    fn frames_carry_an_echo_both_ways() {
        let cipher = Cipher::Chacha;
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(cipher, &key, &iv, options, &iv).expect("sends");
        let mut recv = Flow::fresh(cipher, &key, &iv, options, &iv).expect("recvs");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            read_frame(&mut stream, &mut recv).expect("reads")
        });
        let mut reader = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        assert!(write_frame(&mut reader, &mut send, b"ping"));
        assert_eq!(writer.join().expect("joins"), b"ping");
    }

    #[test]
    fn kdf_is_stable_and_keyed() {
        let a = kdf(b"key", &[b"path"]);
        assert_eq!(a, kdf(b"key", &[b"path"]));
        assert_ne!(a, kdf(b"other", &[b"path"]));
        assert_ne!(a, kdf(b"key", &[b"other"]));
    }

    #[test]
    fn kdf_matches_the_oracle_vectors() {
        fn hex(bytes: &[u8]) -> String {
            let mut out = String::new();
            for b in bytes {
                out.push("0123456789abcdef".as_bytes()[(b >> 4) as usize] as char);
                out.push("0123456789abcdef".as_bytes()[(b & 15) as usize] as char);
            }
            out
        }
        assert_eq!(
            hex(&md5::compute(b"abc").0),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&kdf(b"key", &[b"path"])),
            "f5952ea326376193226ffe760d8aa2ad8587c6a0cc7c32efeda02eb0b5d430ed"
        );
        assert_eq!(
            hex(&kdf(
                b"key",
                &[
                    b"VMess Header AEAD Key_Length",
                    b"authid1234567890",
                    b"nonce123"
                ]
            )),
            "fa9ff42e922d36e727fe11148c5bfae1e57feb2a8bc5671be1014e8a5554c70a"
        );
        assert_eq!(
            hex(&kdf16(b"test-instruction-16", &[b"AES Auth ID Encryption"])),
            "a69474c1eddf8c94283389cc76ac64be"
        );
        let uuid: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        assert_eq!(
            hex(&instruction_key(&uuid)),
            "b50d916ac0cec067981af8e5f38a758f"
        );
    }

    #[test]
    fn handshake_relay_round_trips() {
        use std::io::{Read as _, Write as _};
        let id = [0xabu8; 16];
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
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
        let server = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            super::serve(stream, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut send, mut recv, response_key, response_iv, auth) =
            super::client_handshake(&mut uplink, &id, Cipher::Auto, &target).expect("handshakes");
        assert!(super::read_response(
            &mut uplink,
            &response_key,
            &response_iv,
            auth
        ));
        assert!(write_frame(&mut uplink, &mut send, b"ping"));
        let back = read_frame(&mut uplink, &mut recv).expect("reads");
        assert_eq!(back, b"ping");
    }

    #[test]
    fn response_prefix_is_stable() {
        let prefix = response_prefix(&[0x71u8; 16], &[0x72u8; 16], 0xAB).expect("prefixes");
        assert_eq!(prefix.len(), 38);
        assert_eq!(
            prefix,
            [
                0xab, 0xe4, 0x1f, 0x65, 0xdb, 0xa0, 0x80, 0xd4, 0xcc, 0x9d, 0x50, 0xd3, 0x0a, 0xda,
                0x8b, 0x09, 0xaa, 0x89, 0x82, 0xf9, 0xa8, 0xfe, 0x3d, 0xf3, 0x20, 0xc3, 0x7b, 0x61,
                0xcd, 0x45, 0x4e, 0x47, 0x98, 0x8d, 0x4a, 0xf9, 0x11, 0xd7,
            ]
        );
    }

    #[test]
    fn frames_seal_to_stable_bytes() {
        let cases = [
            (
                Cipher::Chacha,
                [
                    0x15, 0xe6, 0x71, 0x0e, 0x43, 0x79, 0x84, 0x37, 0x1c, 0xc5, 0xf6, 0x4d, 0xd4,
                    0x8f, 0x7c, 0xc4, 0x58, 0x69, 0xc8, 0xeb, 0xec,
                ],
            ),
            (
                Cipher::Aes,
                [
                    0xc9, 0x02, 0x32, 0x56, 0x14, 0x1e, 0xff, 0x1c, 0xe0, 0xfc, 0x09, 0xbf, 0x9f,
                    0xc1, 0xa9, 0x16, 0xfc, 0xeb, 0x35, 0xbd, 0x5a,
                ],
            ),
        ];
        for (cipher, golden) in cases {
            let mut flow = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let mut sealed = Vec::new();
            assert!(flow.seal_onto(b"hello", &mut sealed));
            assert_eq!(sealed, golden);
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let back = recv.open_chunk(&mut sealed).expect("opens");
            assert_eq!(&sealed[..back], b"hello");
        }
    }

    #[test]
    fn seal_open_round_trips_every_length_and_cipher() {
        let lens = [
            0, 1, 2, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1000, 1023, 1024, 4095,
            4096, 8191, 8192, 8193, 16383, 16384, 20000,
        ];
        for cipher in [Cipher::Chacha, Cipher::Aes, Cipher::None] {
            let tag = if cipher == Cipher::None { 0 } else { TAG_LEN };
            for &len in &lens {
                let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut send = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("sends");
                let mut recv = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("recvs");
                let mut sealed = Vec::new();
                assert!(send.seal_onto(&plain, &mut sealed));
                assert_eq!(sealed.len(), plain.len() + tag);
                let back = recv.open_chunk(&mut sealed).expect("opens");
                assert_eq!(back, plain.len());
                assert_eq!(&sealed[..back], &plain[..]);
            }
        }
    }

    #[test]
    fn masked_frames_carry_every_length() {
        let lens = [0, 1, 100, 8191, 8192, 8193, 20000];
        for cipher in [Cipher::Chacha, Cipher::Aes, Cipher::None] {
            let options = OPT_STREAM | OPT_MASK | OPT_PAD;
            let payloads: Vec<Vec<u8>> = lens
                .iter()
                .map(|&len| (0..len).map(|i| (i % 251) as u8).collect())
                .collect();
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let writer = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut recv =
                    Flow::fresh(cipher, &[0x55u8; 16], &[0x66u8; 16], options, &[0x66u8; 16])
                        .expect("recvs");
                let mut all = Vec::new();
                for _ in &lens {
                    all.extend_from_slice(&read_frame(&mut stream, &mut recv).expect("reads"));
                }
                all
            });
            let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut send =
                Flow::fresh(cipher, &[0x55u8; 16], &[0x66u8; 16], options, &[0x66u8; 16])
                    .expect("sends");
            let mut want = Vec::new();
            for plain in &payloads {
                assert!(write_frame(&mut uplink, &mut send, plain));
                want.extend_from_slice(plain);
            }
            assert_eq!(writer.join().expect("joins"), want);
        }
    }

    #[test]
    fn counters_advance_one_per_frame_at_any_offset() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            for &at in &[0u16, 1, 255, 256, 1000, 32767, 32768, 65533, 65534] {
                let mut send = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("sends");
                let mut recv = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("recvs");
                send.counter = at;
                recv.counter = at;
                let mut first = [0u8; 12];
                first.copy_from_slice(&send.nonce());
                let mut sealed = Vec::new();
                assert!(send.seal_onto(b"ping", &mut sealed));
                let back = recv.open_chunk(&mut sealed).expect("opens");
                assert_eq!(&sealed[..back], b"ping");
                assert_eq!(send.counter, at.wrapping_add(1));
                assert_eq!(recv.counter, at.wrapping_add(1));
                assert_ne!(send.nonce(), first);
            }
        }
    }

    #[test]
    fn counter_wrap_is_refused_not_reused() {
        let mut flow = Flow::fresh(
            Cipher::Chacha,
            &[0x55u8; 16],
            &[0x66u8; 16],
            OPT_STREAM,
            &[0x66u8; 16],
        )
        .expect("fresh");
        flow.counter = u16::MAX;
        let mut sealed = vec![0xAAu8; 4];
        assert!(!flow.seal_onto(b"ping", &mut sealed));
        assert_eq!(sealed, [0xAAu8; 4]);
        assert!(flow.open_chunk(&mut sealed).is_none());
    }

    #[test]
    fn wire_codes_and_security_words_map_exactly() {
        assert_eq!(Cipher::from_code(3), Some(Cipher::Aes));
        assert_eq!(Cipher::from_code(4), Some(Cipher::Chacha));
        assert_eq!(Cipher::from_code(5), Some(Cipher::None));
        for code in [0, 1, 2, 6, 7, 255] {
            assert!(Cipher::from_code(code).is_none());
        }
        assert_eq!(Cipher::parse("auto"), Cipher::Auto);
        assert_eq!(Cipher::parse("AUTO"), Cipher::Auto);
        assert_eq!(Cipher::parse("aes-128-gcm"), Cipher::Aes);
        assert_eq!(Cipher::parse("AES-128-GCM"), Cipher::Aes);
        assert_eq!(Cipher::parse("chacha20-poly1305"), Cipher::Chacha);
        assert_eq!(Cipher::parse("chacha20-ietf-poly1305"), Cipher::Chacha);
        assert_eq!(Cipher::parse("none"), Cipher::None);
        assert_eq!(Cipher::parse("NONE"), Cipher::None);
        assert_eq!(Cipher::parse("garbage"), Cipher::Auto);
        assert_eq!(Cipher::parse(""), Cipher::Auto);
    }

    #[test]
    fn tampered_seals_do_not_open() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            let key = [0x33u8; 16];
            let nonce = [0x44u8; 12];
            let sealed = seal_header(&key, &nonce, b"length-is-framing", b"aad").expect("seals");
            for at in [0, sealed.len() / 2, sealed.len() - 1] {
                let mut cut = sealed.clone();
                cut[at] ^= 1;
                assert!(open_header(&key, &nonce, &cut, b"aad").is_none());
            }
            assert!(open_header(&key, &nonce, &sealed, b"wrong").is_none());
            assert!(open_header(&[0x34u8; 16], &nonce, &sealed, b"aad").is_none());
            assert!(open_header(&key, &nonce, &sealed[..sealed.len() - 1], b"aad").is_none());
            let mut send = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("sends");
            let mut frame = Vec::new();
            assert!(send.seal_onto(b"ping", &mut frame));
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("recvs");
            frame[0] ^= 1;
            assert!(recv.open_chunk(&mut frame).is_none());
        }
    }

    #[test]
    fn expired_auth_ids_are_refused() {
        let instruction = instruction_key(&[0x22u8; 16]);
        let key = kdf16(&instruction, &[b"AES Auth ID Encryption"]);
        let seal = |ago: u64| {
            let mut plain = [0u8; 16];
            plain[..8].copy_from_slice(&now_secs().saturating_sub(ago).to_be_bytes());
            plain[8..12].copy_from_slice(&[9u8, 8, 7, 6]);
            let checksum = crc32(&plain[..12]).to_be_bytes();
            plain[12..].copy_from_slice(&checksum);
            assert!(aes_block(&key, &mut plain, true));
            plain
        };
        assert!(valid_auth_id(&instruction, &seal(0)));
        assert!(valid_auth_id(&instruction, &seal(119)));
        assert!(!valid_auth_id(&instruction, &seal(121)));
        assert!(!valid_auth_id(&instruction, &seal(3600)));
    }

    #[test]
    fn replays_close_on_second_use() {
        let id = [0x77u8; AUTH_LEN];
        assert!(!replay_seen(&id));
        assert!(replay_seen(&id));
    }

    #[test]
    fn clear_headers_decode_and_reject() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let mut header = vec![1u8];
        header.extend_from_slice(&[0x01u8; 16]);
        header.extend_from_slice(&[0x02u8; 16]);
        header.push(0x03);
        header.push(OPT_STREAM | OPT_MASK | OPT_PAD);
        header.push(0x04);
        header.push(0);
        header.push(1);
        header.extend_from_slice(&target.port().to_be_bytes());
        header.push(1);
        header.extend_from_slice(&[127, 0, 0, 1]);
        header.extend_from_slice(&fnv1a(&header).to_be_bytes());
        let (got, _send, _recv, prefix) = decode_header(&header).expect("decodes");
        assert_eq!(got, target);
        assert_eq!(prefix.len(), 38);
        let mut bad = header.clone();
        bad[0] = 2;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[37] = 2;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[35] = 0x07;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[34] &= !OPT_STREAM;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[35] = 0xF4;
        assert!(decode_header(&bad).is_none());
        assert!(decode_header(&header[..header.len() - 1]).is_none());
    }

    #[test]
    fn requests_open_to_their_own_lengths_and_targets() {
        let uuid = [0xabu8; 16];
        let targets = [
            "127.0.0.1:8080".parse().expect("addr"),
            "[::1]:443".parse().expect("addr"),
        ];
        for cipher in [Cipher::Auto, Cipher::Aes, Cipher::Chacha, Cipher::None] {
            for target in targets {
                let (request, _, _, _) = request_bytes(&uuid, cipher, &target).expect("builds");
                assert!(request.len() > 42 + TAG_LEN);
                let instruction = instruction_key(&uuid);
                let auth_id: [u8; AUTH_LEN] = request[..AUTH_LEN].try_into().expect("auth");
                let nonce = &request[16 + 18..16 + 18 + 8];
                let len_key = kdf16(
                    &instruction,
                    &[b"VMess Header AEAD Key_Length", &auth_id, nonce],
                );
                let len_full = kdf(
                    &instruction,
                    &[b"VMess Header AEAD Nonce_Length", &auth_id, nonce],
                );
                let len_nonce: [u8; 12] = len_full[..12].try_into().expect("nonce");
                let clear_len =
                    open_header(&len_key, &len_nonce, &request[16..34], &auth_id).expect("opens");
                assert_eq!(
                    usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]])),
                    request.len() - 42 - TAG_LEN
                );
                let head_key = kdf16(&instruction, &[b"VMess Header AEAD Key", &auth_id, nonce]);
                let head_full = kdf(&instruction, &[b"VMess Header AEAD Nonce", &auth_id, nonce]);
                let head_nonce: [u8; 12] = head_full[..12].try_into().expect("nonce");
                let clear =
                    open_header(&head_key, &head_nonce, &request[42..], &auth_id).expect("opens");
                let (got, _, _, _) = decode_header(&clear).expect("decodes");
                assert_eq!(got, target);
            }
        }
    }

    #[test]
    fn garbage_short_and_wrong_user_close_fast() {
        let id = [0xabu8; 16];
        let server = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(3) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || super::serve(stream, &id, true));
            }
        });
        let mut refused = 0;
        for body in [
            vec![0u8; 16],
            request_bytes(
                &[0xccu8; 16],
                Cipher::Auto,
                &"127.0.0.1:1".parse().expect("addr"),
            )
            .expect("builds")
            .0,
            request_bytes(&id, Cipher::Auto, &"127.0.0.1:1".parse().expect("addr"))
                .expect("builds")
                .0[..20]
                .to_vec(),
        ] {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            stream.write_all(&body).expect("writes");
            stream.shutdown(std::net::Shutdown::Write).expect("shuts");
            let mut back = [0u8; 1];
            match stream.read(&mut back) {
                Ok(0) | Err(_) => refused += 1,
                Ok(_) => {}
            }
        }
        assert_eq!(refused, 3);
    }
}
