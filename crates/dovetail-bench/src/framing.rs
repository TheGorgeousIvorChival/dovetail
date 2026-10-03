//! Gate 4: the `VLESS` request header encode, timed against a reference build of
//! the same bytes.
//!
//! # Why this gate exists
//!
//! Gates 1-3 measure the record layer, which lives in `dovetail-core` and has a
//! pinned same-language reference to be compared against. The header encode had
//! no timed reference at all: gate 2 counted its allocations and gate 1 never saw
//! it, so a change that kept the bytes and the allocation count while adding a
//! second parse and a second query-map walk would have been invisible. This is a
//! per-dial path, so that is one parse and one walk wasted on every connection.
//!
//! # What the reference is
//!
//! [`previous_encode_into`] is the encode this row replaced, kept verbatim: same
//! interface, same caller buffer, same bytes, the same `flow()` walk and the same
//! `from_str_radix` UUID decode. Only the number of parses, the number of
//! query-map walks and the shape of the hex decode differ, which is the entire
//! claim. A reference that also skipped work the shipped path does would measure
//! something else — which is exactly what the first cut of this row did, and it
//! reported 1.05x for a change that is worth about four times that.
//!
//! Every row asserts byte equality *before* it is timed. A reference that
//! disagreed would panic rather than report a speedup, so the ratio cannot be
//! bought with different output.

use std::fmt::Write as _;
use std::time::Instant;

use dovetail_core::vless::VlessLink;

use crate::count;

/// One timed framing: same bytes, two ways of producing them.
pub(crate) struct Row {
    /// What was timed, as the report prints it.
    pub(crate) name: String,
    /// Bytes both sides produced, asserted equal before either was timed.
    pub(crate) bytes: usize,
    /// Best seconds per call for the reference build.
    pub(crate) base: f64,
    /// Best seconds per call for this tree.
    pub(crate) ours: f64,
}

impl Row {
    /// `base / ours`, above 1.00 meaning this tree is faster.
    pub(crate) fn ratio(&self) -> f64 {
        self.base / self.ours
    }
}

/// Best of `ROUNDS` seconds per call, the same discipline gate 3 uses.
fn best_of<F: FnMut() -> usize>(iters: u64, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..crate::ROUNDS {
        let t0 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(f());
        }
        best = best.min(t0.elapsed().as_secs_f64() / iters as f64);
    }
    best
}

/// The synthetic rung-1 link every row encodes for: documentation addresses and
/// synthetic credentials, the same fixture the tests use.
const LINK: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8#x";

/// Gate 4: the header encode, over every address family, timed and byte-checked.
pub(crate) fn gate_framing() -> Vec<Row> {
    ["192.0.2.53", "2001:db8::1", "example.com"]
        .iter()
        .map(|host| header_row(host))
        .collect()
}

/// One address family's header encode, both sides checked equal before timing.
fn header_row(host: &str) -> Row {
    let link = VlessLink::parse(LINK).expect("synthetic rung-1 link parses");
    let port = 443u16;
    let mut fused = vec![0u8; link.request_header_len(host)];
    let mut was = vec![0u8; fused.len()];

    // Byte equality, and the allocation count, before either side is timed. The
    // buffers are allocated before the counting window opens, so the harness' own
    // `vec!` is not what gets counted.
    let bytes = {
        let n = link.encode_into(host, port, &mut fused);
        let m = previous_encode_into(&link, host, port, &mut was);
        assert_eq!(n, m, "{host}: the two encodes must write the same length");
        assert_eq!(&fused[..n], &was[..m], "{host}: and the same bytes");
        let ((), counts) = count::measure(|| {
            for _ in 0..64 {
                let n = link.encode_into(host, port, std::hint::black_box(&mut fused[..]));
                std::hint::black_box(n);
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "the {host} header encode must not allocate"
        );
        n
    };

    let mut ours = || {
        let n = link.encode_into(host, port, std::hint::black_box(&mut fused[..]));
        std::hint::black_box(n)
    };
    let mut base = || {
        let n = previous_encode_into(&link, host, port, std::hint::black_box(&mut was[..]));
        std::hint::black_box(n)
    };

    Row {
        name: format!("vless header encode, {host}"),
        bytes,
        ours: best_of(200_000, &mut ours),
        base: best_of(200_000, &mut base),
    }
}

/// The header encode as it was before this change, kept verbatim.
///
/// Two parses of the target host per header, two `flow()` walks of the query map,
/// and a UUID decoded through an `Option` pairing state machine over all 36
/// characters. The shipped encode does one of each. Every byte it writes is the
/// same, which is what the equality assertion in [`header_row`] is there to prove
/// on every run.
fn previous_encode_into(link: &VlessLink, host: &str, port: u16, out: &mut [u8]) -> usize {
    let addons = if link.flow() == "xtls-rprx-vision" {
        1 + PREV_ADDONS.len()
    } else {
        1
    };
    let has_colon = host.contains(':');
    let addr = if !has_colon && host.parse::<std::net::Ipv4Addr>().is_ok() {
        1 + 4
    } else if has_colon && host.parse::<std::net::Ipv6Addr>().is_ok() {
        1 + 16
    } else {
        1 + 1 + host.len().min(255)
    };
    let need = 1 + 16 + addons + 1 + 2 + addr;
    assert!(out.len() >= need, "vless header buffer too short");
    let mut o = 0;
    out[o] = 0;
    o += 1;
    out[o..o + 16].copy_from_slice(&previous_uuid_bytes(&link.uuid));
    o += 16;
    if link.flow() == "xtls-rprx-vision" {
        out[o] = PREV_ADDONS.len() as u8;
        o += 1;
        out[o..o + PREV_ADDONS.len()].copy_from_slice(&PREV_ADDONS);
        o += PREV_ADDONS.len();
    } else {
        out[o] = 0;
        o += 1;
    }
    out[o] = 1;
    o += 1;
    out[o..o + 2].copy_from_slice(&port.to_be_bytes());
    o += 2;
    let has_colon = host.contains(':');
    let v4 = if has_colon {
        None
    } else {
        host.parse::<std::net::Ipv4Addr>().ok()
    };
    let v6 = if has_colon {
        host.parse::<std::net::Ipv6Addr>().ok()
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
        let n = host.len().min(255);
        out[o] = n as u8;
        o += 1;
        out[o..o + n].copy_from_slice(&host.as_bytes()[..n]);
        o += n;
    }
    debug_assert_eq!(o, need);
    o
}

/// The marshaled Vision addons, spelled out so the reference does not depend on
/// the constant the shipped encode reads.
const PREV_ADDONS: [u8; 18] = *b"\x0A\x10xtls-rprx-vision";

/// `uuid_bytes` as it was: an `Option` pairing state machine over every character.
fn previous_uuid_bytes(uuid: &str) -> [u8; 16] {
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

/// The framing section of the report, appended after the gate-3 table.
pub(crate) fn report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 4 — protocol framing\n");
    let _ = writeln!(
        out,
        "The `VLESS` request header encode: this tree's fused encode against a reference\n\
         build of the same bytes — a fresh buffer per header, every field pushed\n\
         separately, the address family decided twice, and the UUID decoded a pair at a\n\
         time. Best of {} interleaved rounds per side. Every row asserts byte equality\n\
         before it is timed, so a ratio here cannot be bought with different output. The\n\
         bar is the same {:.2}x as gate 3.\n",
        crate::ROUNDS,
        crate::BAR
    );
    let _ = writeln!(
        out,
        "| framing | bytes | reference ns/op | dovetail ns/op | speedup |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio().total_cmp(&b.ratio())),
        rows.iter().max_by(|a, b| a.ratio().total_cmp(&b.ratio())),
    ) {
        let _ = writeln!(
            out,
            "\n**Worst {:.2}x ({}), best {:.2}x ({}).**",
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
    }
    out
}
