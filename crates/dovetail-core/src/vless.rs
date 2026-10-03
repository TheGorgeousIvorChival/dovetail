//! `VLESS` share-link parsing: the entry point every app pastes.
//!
//! A `ZeroNet` / `v2rayNG` / `PattNG` user never writes JSON. They paste
//! `vless://uuid@host:port?security=...&type=...&flow=...#name`. This module
//! parses exactly that, preserves every query key (including `PattNG`'s
//! `cipherSuites` and `unsafe-*` fingerprints), and reports whether the link's
//! transport is the one this core implements yet.
//!
//! Only one transport is implemented: `type=tcp + security=reality +
//! flow=xtls-rprx-vision` (the link in the project brief). Every other
//! combination parses successfully but reports [`Support::Planned`] with a
//! reason, so a comparison table shows it as empty-with-reason rather than
//! omitting it. That is deliberate: an omitted cell reads as "not measured",
//! an empty-with-reason cell reads as "measured, unsupported".
//!
//! # `PattNG` superset
//!
//! `PattNG` adds two things beyond upstream Xray-core:
//!
//! * `cipherSuites` and `unsafe-*` fingerprints in settings and share-links.
//!   Accepted here and carried through to [`VlessLink::fingerprint`]; an
//!   `unsafe-` fingerprint never enables itself — see [`crate::policy`].
//! * Plaintext (`security=none`) to *public* addresses in VLESS (and TROJAN).
//!   Upstream refuses this; `PattNG` allows it. Accepted here as
//!   [`Security::NoneToPublic`], which dials only with an explicit opt-in —
//!   see [`crate::transport`].
//!
//! # Licence
//!
//! Parsed, not copied: no Xray-core, sing-box, xray-rust, `PattNG` or `ZeroNet`
//! source appears here. The link format is a user-facing string, not a test
//! suite, so re-implementing its parser is licence-clean.

use std::collections::BTreeMap;
use std::fmt;

use crate::transport::{Security, Support, TransportKind};

/// A parsed `vless://` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessLink {
    /// Client UUID, lowercase, without braces.
    pub uuid: String,
    /// Server host (IP or domain), as written.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Raw query map, preserving `PattNG` keys (`cipherSuites`, `fp`, ...).
    pub params: BTreeMap<String, String>,
    /// Fragment after `#` (the user-visible name), percent-decoded once.
    pub name: String,
}

impl VlessLink {
    /// Parse a `vless://` link. Percent-decoding is applied to keys, values
    /// and the fragment; `+` is left alone (these links never use it for space).
    ///
    /// # Errors
    ///
    /// If the scheme is not `vless://`, the UUID is not a UUID, or the
    /// `host:port` does not split. A link whose transport is not implemented
    /// yet is *not* an error — see [`Self::support`].
    pub fn parse(link: &str) -> Result<Self, VlessError> {
        let rest = link.strip_prefix("vless://").ok_or(VlessError::Scheme)?;
        let (before_hash, name_enc) = match rest.split_once('#') {
            Some((a, b)) => (a, b),
            None => (rest, ""),
        };
        let (before_q, query) = match before_hash.split_once('?') {
            Some((a, b)) => (a, b),
            None => (before_hash, ""),
        };
        let (uuid, hostport) = before_q.split_once('@').ok_or(VlessError::Shape)?;
        validate_uuid(uuid)?;
        let (host, port_str) = hostport.rsplit_once(':').ok_or(VlessError::Shape)?;
        if host.is_empty() {
            return Err(VlessError::Shape);
        }
        // IPv6 hosts arrive bracketed (`[::1]:443`); keep the brackets off.
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let port: u16 = port_str.parse().map_err(|_| VlessError::Port)?;
        let mut params = BTreeMap::new();
        if !query.is_empty() {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = match pair.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (pair, ""),
                };
                params.insert(percent_decode(k), percent_decode(v));
            }
        }
        Ok(Self {
            uuid: uuid.to_ascii_lowercase(),
            host: host.to_string(),
            port,
            params,
            name: percent_decode(name_enc),
        })
    }

    /// Query value, or `""` when absent (so missing == empty, as Xray treats it).
    #[must_use]
    pub fn param(&self, key: &str) -> &str {
        self.params.get(key).map_or("", String::as_str)
    }

    /// Transport type (`type=tcp|ws|xhttp|grpc|...)`, defaulting to `tcp`
    /// because Xray does: a link without `type` is a TCP link.
    #[must_use]
    pub fn transport_kind(&self) -> TransportKind {
        TransportKind::from_link(self.param("type"))
    }

    /// `security=reality|tls|none` (default `none`).
    #[must_use]
    pub fn security(&self) -> Security {
        Security::from_link(self.param("security"), &self.host)
    }

    /// `flow=xtls-rprx-vision|none` (default `none`).
    #[must_use]
    pub fn flow(&self) -> &str {
        let f = self.param("flow");
        if f.is_empty() {
            "none"
        } else {
            f
        }
    }

    /// `fp=chrome|firefox|...|unsafe-*` (default `""` = stack default).
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        self.param("fp")
    }

    /// Whether the fingerprint asks for an unsafe `ClientHello`.
    #[must_use]
    pub fn wants_unsafe_fingerprint(&self) -> bool {
        self.fingerprint().starts_with("unsafe-") || self.param("allowUnsafeFp") == "1"
    }

    /// REALITY public key (`pbk`), empty when not a REALITY link.
    #[must_use]
    pub fn reality_pbk(&self) -> &str {
        self.param("pbk")
    }

    /// REALITY short id (`sid`).
    #[must_use]
    pub fn reality_sid(&self) -> &str {
        self.param("sid")
    }

    /// REALITY / TLS SNI (`sni`).
    #[must_use]
    pub fn sni(&self) -> &str {
        self.param("sni")
    }

    /// Whether this link is the first implemented method:
    /// `type=tcp & security=reality & encryption=none & flow=xtls-rprx-vision`.
    #[must_use]
    pub fn is_first_method(&self) -> bool {
        self.transport_kind() == TransportKind::Tcp
            && matches!(self.security(), Security::Reality)
            && self.param("encryption") == "none"
            && self.flow() == "xtls-rprx-vision"
    }

    /// Support status for this link: implemented, planned-with-reason, or
    /// unsafe-requires-opt-in. Never panics; unknown combinations are
    /// `Planned`, not errors, so the matrix stays a superset.
    #[must_use]
    pub fn support(&self) -> Support {
        if self.is_first_method() {
            if self.wants_unsafe_fingerprint() {
                return Support::UnsafeRequiresOptIn {
                    reason: "unsafe fingerprint requested: re-run with explicit opt-in",
                };
            }
            return Support::Implemented {
                method: "vless-tcp-reality-vision",
            };
        }
        if matches!(self.security(), Security::NoneToPublic) {
            return Support::UnsafeRequiresOptIn {
                reason:
                    "security=none to a public address (`PattNG` extension): explicit opt-in required",
            };
        }
        Support::Planned {
            reason: planned_reason(self),
        }
    }

    /// Length of [`Self::encode_request_header`] for a target, without encoding.
    #[must_use]
    pub fn request_header_len(&self, target_host: &str) -> usize {
        // 1 version + 16 uuid + addons + 1 cmd + 2 port + atyp/address, no trailer.
        let addons = if self.flow() == "xtls-rprx-vision" {
            1 + VISION_ADDONS.len()
        } else {
            1
        };
        // An IPv4 literal never contains ':' and an IPv6 literal always does, so
        // only one parse is ever attempted. Same result as trying both, one failed
        // parse fewer: names pay one parse instead of two, IPv6 pays one, IPv4 pays
        // one as before.
        let has_colon = target_host.contains(':');
        let addr = if !has_colon && target_host.parse::<std::net::Ipv4Addr>().is_ok() {
            1 + 4
        } else if has_colon && target_host.parse::<std::net::Ipv6Addr>().is_ok() {
            1 + 16
        } else {
            1 + 1 + target_host.len().min(255)
        };
        1 + 16 + addons + 1 + 2 + addr
    }

    /// Encode into the caller's buffer: zero allocations, zero copies beyond
    /// the writes themselves. Returns bytes written.
    ///
    /// # Panics
    ///
    /// If `out` is shorter than [`Self::request_header_len`], rather than
    /// truncating a handshake.
    pub fn encode_into(&self, target_host: &str, target_port: u16, out: &mut [u8]) -> usize {
        let need = self.request_header_len(target_host);
        assert!(out.len() >= need, "vless header buffer too short");
        let mut o = 0;
        out[o] = 0;
        o += 1;
        out[o..o + 16].copy_from_slice(&uuid_bytes(&self.uuid));
        o += 16;
        let vision = self.flow() == "xtls-rprx-vision";
        if vision {
            out[o] = VISION_ADDONS.len() as u8;
            o += 1;
            out[o..o + VISION_ADDONS.len()].copy_from_slice(&VISION_ADDONS);
            o += VISION_ADDONS.len();
        } else {
            out[o] = 0;
            o += 1;
        }
        out[o] = 1;
        o += 1;
        out[o..o + 2].copy_from_slice(&target_port.to_be_bytes());
        o += 2;
        // Same ':' rule as `request_header_len`: at most one parse runs, and the
        // skipped one could never have succeeded. Same bytes on every input,
        // including a mistaken `host:port` (falls through to domain, as before).
        let has_colon = target_host.contains(':');
        let v4 = if has_colon {
            None
        } else {
            target_host.parse::<std::net::Ipv4Addr>().ok()
        };
        let v6 = if has_colon {
            target_host.parse::<std::net::Ipv6Addr>().ok()
        } else {
            None
        };
        if let Some(ipv4) = v4 {
            out[o] = 1;
            o += 1;
            out[o..o + 4].copy_from_slice(&ipv4.octets());
            o += 4;
        } else if let Some(ipv6) = v6 {
            out[o] = 3;
            o += 1;
            out[o..o + 16].copy_from_slice(&ipv6.octets());
            o += 16;
        } else {
            out[o] = 2;
            o += 1;
            let n = target_host.len().min(255);
            out[o] = n as u8;
            o += 1;
            out[o..o + n].copy_from_slice(&target_host.as_bytes()[..n]);
            o += n;
        }
        debug_assert_eq!(o, need);
        o
    }

    /// Encode the `VLESS` client request header for a `TCP` target.
    ///
    /// Layout: `version(1)` + `UUID(16)` + `addons` + `command(1: 1=TCP)` +
    /// `port(2 BE)` + `atyp(1)` + `addr`, and nothing after. Vision addons are the
    /// fixed 18-byte protobuf with a length byte; anything else is one zero byte.
    #[must_use]
    pub fn encode_request_header(&self, target_host: &str, target_port: u16) -> Vec<u8> {
        let mut out = vec![0u8; self.request_header_len(target_host)];
        let n = self.encode_into(target_host, target_port, &mut out);
        debug_assert_eq!(n, out.len());
        out
    }

    /// Decode a server response header: version 0 plus length-prefixed addons.
    ///
    /// Returns bytes consumed. Rejects a version mismatch and a truncated prefix.
    pub fn decode_response_header(buf: &[u8]) -> Result<usize, VlessError> {
        let &[version, len, ..] = buf else {
            return Err(VlessError::Response);
        };
        if version != 0 {
            return Err(VlessError::Response);
        }
        let need = 2 + usize::from(len);
        if buf.len() < need {
            return Err(VlessError::Response);
        }
        Ok(need)
    }
}

/// Marshaled `Addons{ Flow: "xtls-rprx-vision" }`: tag `0A`, length `10`, 16 chars.
const VISION_ADDONS: [u8; 18] = *b"\x0A\x10xtls-rprx-vision";

fn planned_reason(link: &VlessLink) -> &'static str {
    match link.transport_kind() {
        TransportKind::Tcp => match link.security() {
            Security::Tls => "vless-tcp-tls: parses, dials after the reality rung lands",
            Security::None | Security::NoneToPublic => {
                "vless-tcp-none: parses, dials after the reality rung lands"
            }
            Security::Reality => "vless-tcp-reality without vision: parses, vision rung first",
            Security::Other => "unknown security: parses, transport not scheduled",
        },
        TransportKind::Ws => "vless-ws: parses, scheduled after tcp-tls",
        TransportKind::Xhttp => "vless-xhttp: parses, scheduled after tcp-tls",
        TransportKind::Grpc => "vless-grpc: parses, scheduled after xhttp",
        TransportKind::Quic => "vless-quic: parses, scheduled after grpc",
        TransportKind::Other => "unknown type: parses, transport not scheduled",
    }
}

/// Lowercase-hex UUID without braces; 8-4-4-4-12.
fn validate_uuid(uuid: &str) -> Result<(), VlessError> {
    let parts: Vec<&str> = uuid.split('-').collect();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
        || !uuid.chars().all(|c| c == '-' || c.is_ascii_hexdigit())
    {
        return Err(VlessError::Uuid);
    }
    Ok(())
}

fn uuid_bytes(uuid: &str) -> [u8; 16] {
    // No allocation: the validated UUID is 32 hex digits and 4 dashes, and each
    // pair of hex digits is one byte. A byte with either nibble non-hex encodes
    // as 0, exactly like the previous `from_str_radix(..).unwrap_or(0)` per pair —
    // but `parse` rejects non-hex before this is reached, so the fallback never
    // fires on a constructed link. This runs per header encode, so the `String`
    // it replaces was one heap allocation on the hot path.
    let mut out = [0u8; 16];
    let mut idx = 0usize;
    let mut hi: Option<(u8, bool)> = None;
    for &b in uuid.as_bytes() {
        if b == b'-' {
            continue;
        }
        let (v, ok) = match b {
            b'0'..=b'9' => (b - b'0', true),
            b'a'..=b'f' => (b - b'a' + 10, true),
            b'A'..=b'F' => (b - b'A' + 10, true),
            _ => (0, false),
        };
        if let Some((h, hok)) = hi.take() {
            if idx < 16 {
                out[idx] = if hok && ok { (h << 4) | v } else { 0 };
                idx += 1;
            }
        } else {
            hi = Some((v, ok));
        }
        if idx >= 16 {
            break;
        }
    }
    out
}

/// Minimal percent-decoder (UTF-8 aware): `%XX` -> byte, `+` left alone.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// What went wrong parsing a link. Transport-not-implemented is not here —
/// that is [`Support::Planned`], not a parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessError {
    /// Missing `vless://` prefix.
    Scheme,
    /// No `uuid@host:port` shape.
    Shape,
    /// UUID is not 8-4-4-4-12 hex.
    Uuid,
    /// Port is not a `u16`.
    Port,
    /// Response header is truncated or its version mismatches.
    Response,
}

impl fmt::Display for VlessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheme => write!(f, "link must start with vless://"),
            Self::Shape => write!(f, "link must look like vless://uuid@host:port?..."),
            Self::Uuid => write!(f, "uuid must be 8-4-4-4-12 hex"),
            Self::Port => write!(f, "port must be 0-65535"),
            Self::Response => write!(f, "response header is truncated or versioned wrong"),
        }
    }
}

impl std::error::Error for VlessError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of the brief's link (VLESS + TCP + REALITY + Vision), with
    /// documentation addresses and synthetic credentials: no live UUID, key,
    /// or server ever lands in this tree (see scripts/check-fixture-safety.sh).
    const BRIEF_LINK: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&host=%2Ftest-path&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8#reality-vision-test";

    #[test]
    fn parses_the_brief_link() {
        let l = VlessLink::parse(BRIEF_LINK).expect("brief link parses");
        assert_eq!(l.uuid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert_eq!(l.host, "192.0.2.1");
        assert_eq!(l.port, 443);
        assert_eq!(l.param("security"), "reality");
        assert_eq!(l.param("encryption"), "none");
        assert_eq!(l.param("flow"), "xtls-rprx-vision");
        assert_eq!(l.param("type"), "tcp");
        assert_eq!(l.param("fp"), "firefox");
        assert_eq!(l.sni(), "example.com");
        assert_eq!(
            l.reality_pbk(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(l.reality_sid(), "a8");
        assert!(l.is_first_method());
        assert_eq!(
            l.support(),
            Support::Implemented {
                method: "vless-tcp-reality-vision"
            }
        );
    }

    #[test]
    fn first_method_header_is_stable() {
        // Golden bytes: version + uuid + addons + cmd + port + atyp + ipv4.
        // The UUID and addon bytes are spelled out, not derived from the code
        // that wrote them: a wrong-but-consistent encoder passes a test that
        // compares against itself, which is how the old single-byte addon and
        // the phantom trailer survived.
        let l = VlessLink::parse(BRIEF_LINK).expect("parses");
        let hdr = l.encode_request_header("192.0.2.53", 80);
        assert_eq!(hdr.len(), 44);
        assert_eq!(hdr[0], 0); // version
        assert_eq!(
            &hdr[1..17],
            &[
                0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee
            ]
        );
        assert_eq!(uuid_bytes(&l.uuid), hdr[1..17]);
        assert_eq!(hdr[17], 18); // addon length: fixed protobuf below
        assert_eq!(&hdr[18..36], b"\x0A\x10xtls-rprx-vision" as &[u8]);
        assert_eq!(hdr[36], 1); // TCP
        assert_eq!(&hdr[37..39], &[0, 80]);
        assert_eq!(hdr[39], 1); // IPv4
        assert_eq!(&hdr[40..44], &[192, 0, 2, 53]);
        // The zero-alloc form writes the same bytes.
        let mut buf = vec![0u8; l.request_header_len("192.0.2.53")];
        let n = l.encode_into("192.0.2.53", 80, &mut buf);
        assert_eq!(&buf[..n], &hdr[..]);
    }

    #[test]
    fn header_address_families_encode_stably() {
        // The ':' rule (IPv4 never has one, IPv6 always does) decides which parse
        // runs. All three families must keep their wire bytes: IPv4 atyp 1, IPv6
        // atyp 3, domain atyp 2 with a length byte.
        let l = VlessLink::parse(BRIEF_LINK).expect("parses");
        let v4 = l.encode_request_header("192.0.2.53", 80);
        assert_eq!(v4[39], 1);
        assert_eq!(&v4[40..44], &[192, 0, 2, 53]);
        assert_eq!(v4.len(), l.request_header_len("192.0.2.53"));

        let v6 = l.encode_request_header("2001:db8::1", 443);
        // 2001:0db8::1 -> 20 01 0d b8 + 11 zero bytes + 01.
        assert_eq!(v6[39], 3);
        assert_eq!(
            &v6[40..56],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(v6.len(), l.request_header_len("2001:db8::1"));

        let name = l.encode_request_header("example.com", 443);
        assert_eq!(name[39], 2);
        assert_eq!(name[40], 11);
        assert_eq!(&name[41..52], b"example.com");
        assert_eq!(name.len(), l.request_header_len("example.com"));

        // `encode_into` agrees with `encode_request_header` on every family, so
        // the single-parse path and the length function cannot drift apart.
        for (host, port) in [
            ("192.0.2.53", 80),
            ("2001:db8::1", 443),
            ("example.com", 443),
        ] {
            let expect = l.encode_request_header(host, port);
            let mut buf = vec![0u8; l.request_header_len(host)];
            let n = l.encode_into(host, port, &mut buf);
            assert_eq!(&buf[..n], &expect[..], "family {host}");
        }
    }

    #[test]
    fn non_vision_header_carries_empty_addons() {
        // No flow: one zero length byte, no protobuf, no trailer.
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.53:80?security=tls&encryption=none&type=tcp#tls",
        )
        .expect("parses");
        let hdr = l.encode_request_header("192.0.2.53", 80);
        assert_eq!(hdr.len(), 26);
        assert_eq!(hdr[17], 0);
        assert_eq!(hdr[18], 1); // TCP
        assert_eq!(&hdr[19..21], &[0, 80]);
        assert_eq!(&hdr[21..26], &[1, 192, 0, 2, 53]);
    }

    #[test]
    fn response_header_decodes() {
        assert_eq!(VlessLink::decode_response_header(&[0, 0]), Ok(2));
        let mut vision = vec![0u8, 18];
        vision.extend_from_slice(b"\x0A\x10xtls-rprx-vision");
        assert_eq!(VlessLink::decode_response_header(&vision), Ok(20));
        assert_eq!(
            VlessLink::decode_response_header(&[1, 0]).unwrap_err(),
            VlessError::Response
        );
        assert_eq!(
            VlessLink::decode_response_header(&[0]).unwrap_err(),
            VlessError::Response
        );
        assert_eq!(
            VlessLink::decode_response_header(&[0, 5, 1, 2]).unwrap_err(),
            VlessError::Response
        );
    }

    #[test]
    fn unknown_transports_parse_but_stay_planned() {
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=tls&type=ws&path=%2Fws#ws",
        )
        .expect("parses");
        assert!(matches!(l.support(), Support::Planned { .. }));
        assert!(!l.is_first_method());
    }

    #[test]
    fn pattng_plaintext_to_public_needs_opt_in() {
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:80?security=none&encryption=none&type=tcp#plain",
        )
        .expect("parses");
        assert!(matches!(l.support(), Support::UnsafeRequiresOptIn { .. }));
    }

    #[test]
    fn pattng_unsafe_fingerprint_needs_opt_in() {
        let l = VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=k&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8&fp=unsafe-chrome#x",
        )
        .expect("parses");
        assert!(matches!(l.support(), Support::UnsafeRequiresOptIn { .. }));
    }

    #[test]
    fn rejects_bad_links() {
        assert_eq!(
            VlessLink::parse("http://x").unwrap_err(),
            VlessError::Scheme
        );
        assert_eq!(
            VlessLink::parse("vless://not-a-uuid@example.com:443").unwrap_err(),
            VlessError::Uuid
        );
        assert_eq!(
            VlessLink::parse("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:notaport")
                .unwrap_err(),
            VlessError::Port
        );
    }
}
