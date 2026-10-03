//! Per-method proof matrix: one row per transport rung, each naming its proof.
//!
//! Dovetail implements one connection method at a time
//! (`docs/arch/superset.md`). A row moves from "parses" to "dials" only with
//! its differential proof and its benchmark gate green — the same rule the
//! comparators enforce by reading each core's own validator rather than its
//! documentation: support here is read from `VlessLink::support`, not asserted
//! by hand, wherever the `vless://` format can express the row. Rows that format cannot express
//! (`TROJAN`, `VMess`, Shadowsocks, `WireGuard`, …) are static text mirroring
//! the transport matrix, and the test below pins the row count so a dropped row
//! fails loudly instead of silently narrowing the claim.
//!
//! When a rung lands, its row gains three things: the differential test name,
//! the gate that runs it, and the upstream suite flip in `upstream/pins.toml`
//! (`test_enabled = true`). Until then every suite in Xray-core, ZeroNet/Zray,
//! xray-rust and sing-box covering the row stays wired to `Planned` or
//! `UnsafeRequiresOptIn` with its reason — executed in CI from the pin by
//! `scripts/run-upstream-suite.sh`, never copied into this tree (licence-clean).

use std::fmt::Write as _;

/// A synthetic `vless://` link exercising one rung, TEST-NET hosts and
/// credentials only (see `scripts/check-fixture-safety.sh`).
fn rung_link(query: &str, host: &str) -> String {
    format!("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@{host}:443?{query}#x")
}

/// The live `transport::Support` of a synthetic rung link,
/// read from the parser rather than written by hand.
fn live_support(query: &str, host: &str) -> String {
    let link = dovetail_core::vless::VlessLink::parse(&rung_link(query, host))
        .expect("synthetic rung link parses");
    link.support().to_string()
}

/// The per-method matrix, appended to every benchmark report so an unimplemented
/// cell is always empty *with its reason*, never omitted.
pub fn table() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "\n## Per-method proof (one row per rung)\n");
    let _ = writeln!(s, "| # | method | status | proof |");
    let _ = writeln!(s, "|---|---|---|---|");
    let _ = writeln!(
        s,
        "| 1 | VLESS TCP REALITY `xtls-rprx-vision` | {} | `vless::tests` + header-family test; gate 1 (3600 shapes, dense not exhaustive), gate 2 (0 allocs, record + header), gate 3 (0.95x at every measured length); xray-core suite enabled |",
        live_support(
            "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "192.0.2.1",
        )
    );
    let _ = writeln!(
        s,
        "| 2 | VLESS TCP TLS (Vision optional) | {} | TLS handshake differential vs Xray-core pin lands with the rung; suite flips when it does |",
        live_support("security=tls&encryption=none&type=tcp", "192.0.2.1")
    );
    let _ = writeln!(
        s,
        "| 3 | VLESS TCP none (private) | {} | framing differential lands with the rung |",
        live_support("security=none&encryption=none&type=tcp", "127.0.0.1")
    );
    let _ = writeln!(
        s,
        "| 4 | VLESS/TROJAN `security=none` to public (`PattNG` ext.) | {} | `policy::UnsafeOptIn::allow_plaintext_to_public` + isolated test net only |",
        live_support("security=none&encryption=none&type=tcp", "192.0.2.1")
    );
    let _ = writeln!(
        s,
        "| 5 | `TROJAN` TCP TLS | planned: schema reserved, parser follows VLESS | password framing differential |"
    );
    let _ = writeln!(
        s,
        "| 6 | `VMess` TCP | planned: after `TROJAN` | AEAD differential first |"
    );
    let _ = writeln!(
        s,
        "| 7 | Shadowsocks TCP/UDP | planned: after `VMess` | shares the record rung (`record::fill_exact` gates 1–3) |"
    );
    let _ = writeln!(
        s,
        "| 8 | VLESS WS / `XHTTP` / gRPC / QUIC | planned: after Shadowsocks, one transport per rung | one differential + gate per rung, never batched |"
    );
    let _ = writeln!(
        s,
        "| 9 | `WireGuard` / MASQUE (H2+H3), `Hysteria2`, Aether (`ZeroNet` WARP paths) | planned: after `XHTTP` | loopback tunnel benchmark per protocol vs pinned comparators |"
    );
    let _ = writeln!(
        s,
        "| 10 | `cipherSuites` + `unsafe-*` fingerprints (`PattNG` ext.) | {} | `policy::UnsafeOptIn::allow_unsafe_fingerprint` + `ClientHello` differential |",
        live_support(
            "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=unsafe-chrome&sni=example.com&sid=a8&pbk=k",
            "192.0.2.1",
        )
    );
    let _ = writeln!(
        s,
        "\n> Status cells above are read from the parser at report time for every row the\n\
         > `vless://` format can express; the rest mirror `transport.rs` until their rung\n\
         > lands. Upstream suites (Xray-core, ZeroNet/Zray, xray-rust, sing-box) check each\n\
         > implemented rung from their pins — see `docs/conformance.md`."
    );
    s
}

#[cfg(test)]
mod tests {
    use dovetail_core::transport::Support;

    fn support_of(query: &str, host: &str) -> Support {
        let link = dovetail_core::vless::VlessLink::parse(&super::rung_link(query, host))
            .expect("synthetic rung link parses");
        link.support()
    }

    #[test]
    fn rung_statuses_are_read_not_written() {
        assert!(matches!(
            support_of(
                "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8&pbk=k",
                "192.0.2.1",
            ),
            Support::Implemented { .. }
        ));
        assert!(matches!(
            support_of("security=tls&encryption=none&type=tcp", "192.0.2.1"),
            Support::Planned { .. }
        ));
        assert!(matches!(
            support_of("security=none&encryption=none&type=tcp", "127.0.0.1"),
            Support::Planned { .. }
        ));
        assert!(matches!(
            support_of("security=none&encryption=none&type=tcp", "192.0.2.1"),
            Support::UnsafeRequiresOptIn { .. }
        ));
        assert!(matches!(
            support_of(
                "security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=unsafe-chrome&sni=example.com&sid=a8&pbk=k",
                "192.0.2.1",
            ),
            Support::UnsafeRequiresOptIn { .. }
        ));
    }

    #[test]
    fn the_table_has_ten_rows() {
        let rows = super::table()
            .lines()
            .filter(|l| l.starts_with("| "))
            .count();
        // Header + 10 rungs = 11 pipe rows.
        assert_eq!(
            rows, 11,
            "a rung was added or dropped without updating this table"
        );
    }
}
