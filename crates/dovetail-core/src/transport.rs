//! The transport superset: every way `PattNG` can connect, in one matrix.
//!
//! Dovetail-core is a superset of Xray-core, sing-box, xray-rust and `PattNG`'s
//! Xray fork — not a re-implementation of one of them. That means the matrix
//! below lists transports this core does *not* implement yet, with the reason
//! each cell is empty, rather than omitting them. An omitted cell reads as
//! "not measured"; an empty-with-reason cell reads as "measured, unsupported".
//!
//! One method is implemented at a time. The order is the table order: the
//! first row is the only [`Support::Implemented`] one, and a row moves up only
//! with its differential proof and its benchmark gate.
//!
//! | # | transport | status | notes |
//! | - | --------- | ------ | ----- |
//! | 1 | VLESS TCP REALITY Vision | **implemented** | the brief's link; `vless.rs` parses, header encode benchmarked |
//! | 2 | VLESS TCP TLS (Vision optional) | planned | parses; dials after rung 1 lands |
//! | 3 | VLESS TCP none (private) | planned | parses; after rung 2 |
//! | 4 | VLESS TCP none to public (`PattNG` ext.) | unsafe opt-in | parses; [`Security::NoneToPublic`], needs explicit opt-in |
//! | 5 | `TROJAN` TCP TLS / to-public-plaintext (`PattNG` ext.) | planned | schema reserved, parser follows VLESS |
//! | 6 | `VMess` TCP | planned | after `TROJAN`; AEAD differential first |
//! | 7 | Shadowsocks TCP/UDP | planned | after `VMess`; shares the record rung |
//! | 8 | VLESS WS / `XHTTP` / gRPC / QUIC | planned | after Shadowsocks, one transport per rung |
//! | 9 | `WireGuard` / `MASQUE` H2+H3, `Hysteria2`, `Aether` | planned | `ZeroNet` `WARP` paths; after `XHTTP` |
//! | 10 | `cipherSuites` + `unsafe-*` fingerprints (`PattNG` ext.) | unsafe opt-in | parsed and carried; enabling needs [`crate::policy`] sign-off |
//!
//! [`crate::vless::VlessLink::support`] is the code form of this table: it
//! never panics and never errors on an unknown transport — unknown is
//! `Planned`, because the matrix is a superset by construction.

use std::fmt;

/// The wire transport under the security layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// `type=tcp` (or absent, which Xray reads as TCP).
    Tcp,
    /// `type=ws`.
    Ws,
    /// `type=xhttp`.
    Xhttp,
    /// `type=grpc`.
    Grpc,
    /// `type=quic`.
    Quic,
    /// Anything else (preserved, never rejected at parse).
    Other,
}

impl TransportKind {
    /// From a `type=` query value. Empty means TCP, as Xray does.
    #[must_use]
    pub fn from_link(t: &str) -> Self {
        match t {
            "" | "tcp" => Self::Tcp,
            "ws" => Self::Ws,
            "xhttp" => Self::Xhttp,
            "grpc" => Self::Grpc,
            "quic" => Self::Quic,
            _ => Self::Other,
        }
    }
}

/// The security layer over the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// `security=tls`.
    Tls,
    /// `security=reality`.
    Reality,
    /// `security=none` to a private/loopback address (or no address check).
    None,
    /// `security=none` to a *public* address: the `PattNG` extension upstream
    /// Xray-core refuses. Parses fine; dials only with explicit opt-in.
    NoneToPublic,
    /// Anything else (preserved).
    Other,
}

impl Security {
    /// From a `security=` value plus the destination host, so `none` splits
    /// into [`Self::None`] vs [`Self::NoneToPublic`] at parse time rather
    /// than at dial time — where a silent plaintext fallback would hide.
    #[must_use]
    pub fn from_link(s: &str, host: &str) -> Self {
        match s {
            "tls" => Self::Tls,
            "reality" => Self::Reality,
            "none" | "" => {
                if is_public_host(host) {
                    Self::NoneToPublic
                } else {
                    Self::None
                }
            }
            _ => Self::Other,
        }
    }
}

/// True for a host that is neither loopback, private, nor a test name.
/// Used only to split `None` from `NoneToPublic`; the dial path re-checks.
///
/// `h` is already lowercased by the caller, so the suffix comparisons below
/// are case-insensitive by construction rather than by a second pass.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn is_public_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_multicast());
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return !(v6.is_loopback() || v6.is_multicast());
    }
    // A bare domain name is treated as public: resolving it to decide would
    // put DNS in the parser, and the dial path checks again anyway.
    // `example.*` / `test.*` / `.invalid` / `.localhost` are the documented
    // non-public exceptions (RFC 2606 / 6761).
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h == "example.com" || h == "example.org" || h == "example.net" {
        return false;
    }
    !(h.ends_with(".test")
        || h.ends_with(".example")
        || h.ends_with(".invalid")
        || h.ends_with(".localhost")
        || h == "test")
}

/// Whether a link's transport can be dialled by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Diallable now. `method` names the rung (e.g. `vless-tcp-reality-vision`).
    Implemented {
        /// Rung name, for reports.
        method: &'static str,
    },
    /// Parses but not diallable yet. The reason is the cell content in the
    /// comparison table — never an omission.
    Planned {
        /// Why the cell is empty.
        reason: &'static str,
    },
    /// Parses but dials only with an explicit, audited opt-in
    /// (see [`crate::policy`]). Plaintext-to-public and `unsafe-*`
    /// fingerprints live here.
    UnsafeRequiresOptIn {
        /// Why opt-in is required.
        reason: &'static str,
    },
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implemented { method } => write!(f, "implemented ({method})"),
            Self::Planned { reason } => write!(f, "planned: {reason}"),
            Self::UnsafeRequiresOptIn { reason } => write!(f, "unsafe opt-in required: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_none_is_not_public() {
        assert_eq!(Security::from_link("none", "127.0.0.1"), Security::None);
        assert_eq!(Security::from_link("", "localhost"), Security::None);
        assert_eq!(
            Security::from_link("none", "192.0.2.1"),
            Security::NoneToPublic
        );
    }
}
