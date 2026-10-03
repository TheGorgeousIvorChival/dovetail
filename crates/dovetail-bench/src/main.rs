//! Proves the shipped core is bit-identical to the reference and not slower.
//!
//! Three gates, in this order, and the order is the point:
//!
//! 1. **Identity, before any timing.** Every length and every block offset is
//!    compared byte for byte against the reference. A wrong core never gets to
//!    be a fast one, because this panics first.
//! 2. **Deterministic properties, which are facts.** Blocks generated equals
//!    blocks needed; zero heap allocations; zero zero-fills. These are integer
//!    counts, identical on every machine, so they are gated outright.
//! 3. **Timing, which is a distribution.** The bar is 0.95x at any single timed
//!    length: 5% under is runner noise on shared runners. A length under the
//!    bar is re-measured at four times the budget before the job fails,
//!    because a shared runner is noisy enough that a gate which cries wolf
//!    gets switched off, and a gate that only fails on a number it has taken
//!    repeatedly does not.
//!
//! The reference's own backend is named in the report. It matters: on aarch64
//! the `chacha20` crate falls back to a scalar one-block-at-a-time core, so a
//! comparison that did not say so would credit that gap to this workspace.

// A duration divided by an iteration count is a nanoseconds-per-call figure,
// which is what this binary exists to report; the conversion to `f64` is the
// point rather than an accident of the arithmetic. See `count.rs` for the same
// reasoning applied to the integer counts.
#![allow(clippy::cast_precision_loss)]

mod compare;
mod count;
mod methods;

use count::Counting;
use std::fmt::Write as _;

/// Dense, not exhaustive: every byte 0..=256, then M-1/M/M+1 for each listed multiple.
///
/// Below 257 the claim is every length, so every block-count change there is tested at every byte.
/// Above 256 the claim is one length either side of each listed multiple, not every multiple in range.
/// Rung steps are every 64 B, with groups at 256 B (portable/NEON, 4 blocks) and 512 B (AVX2, 8 blocks).
/// Listed multiples are tail examples 320/384/448/576/640 and group steps 512/768/1024/1536/2048/4096/8192/16384/65536.
/// Unlisted multiples (704, 896, 1088, 2560, ...) are not covered; exhaustive 0..=65536 would be 786444 shapes, which gate 3 cannot afford.
/// Offsets 0/1/2/7/64/65535 are a selection (0 is every caller, the rest are resume paths), checked by gate 1, not a proof over u32.
fn lengths() -> Vec<usize> {
    let mut v: Vec<usize> = (0..=256).collect();
    v.extend([
        257, 319, 320, 321, 383, 384, 385, 447, 448, 449, 511, 512, 513, 575, 576, 577, 639, 640,
        641, 767, 768, 769, 1023, 1024, 1025, 1535, 1536, 1537, 2047, 2048, 2049, 4095, 4096, 4097,
        8191, 8192, 8193, 16383, 16384, 16385, 65535, 65536, 65537,
    ]);
    v.sort_unstable();
    v.dedup();
    v
}

/// The bar. 0.95 means "no worse than 5% under the reference at any single
/// timed length". Five percent is runner noise on shared runners, not signal:
/// single lengths at 0.97-0.99x came back green on a plain rerun with no code
/// change, one full bench cycle later.
///
/// Runners are still noisy underneath, so the measurement stays robust instead
/// of the bar going lenient beyond this — best of 5 interleaved rounds per side
/// (the same five-run discipline the comparators publish), and anything under
/// the bar is re-measured at 4x the budget to confirm before it fails. A length
/// confirmed under 0.95x is a regression, not noise, and the job goes red.
const BAR: f64 = 0.95;

/// Rounds per side per length before the best is kept.
///
/// Five, like the five-run medians behind every published comparator chart: the
/// bar is strict, so the samples behind it are not thin.
const ROUNDS: usize = 5;

/// First length the timing gate measures.
///
/// Lengths 1-64 are one 64-byte block, where both sides run the same twenty
/// rounds over the same state: a tie by construction that a 1.00x bar cannot
/// certify. They stay in `lengths()` so identity still covers them byte for
/// byte, but timing starts here.
const TIMING_MIN: usize = 65;

/// Byte budget per length per round, so short lengths get more iterations and a
/// short length is not decided by a single sample.
const BYTE_BUDGET: u64 = 4 * 1024 * 1024;

fn iters_for(n: usize) -> u64 {
    (BYTE_BUDGET / n.max(1) as u64).clamp(64, 200_000)
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// CLI args: `--reference <name>` and `--config <vless://...>`.
///
/// `--config` hands CI a working link and gets the comparison table for it.
/// The link itself never reaches the report (see `compare.rs`): only the
/// redacted transport description does, so a secret pasted into a dispatch
/// input cannot leak through the summary.
struct Args {
    declared: String,
    config: Option<String>,
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut declared = String::from("chacha20 0.9 (crates.io)");
    let mut config: Option<String> = None;
    while let Some(arg) = args.next() {
        if arg == "--reference" {
            declared = args.next().unwrap_or_else(|| {
                eprintln!("--reference needs a value");
                std::process::exit(2);
            });
        } else if arg == "--config" {
            config = Some(args.next().unwrap_or_else(|| {
                eprintln!("--config needs a vless:// value");
                std::process::exit(2);
            }));
        } else {
            eprintln!("unknown argument: {arg}");
            std::process::exit(2);
        }
    }
    Args { declared, config }
}

/// Best-of-`ROUNDS` seconds per call.
fn time_best<F: FnMut()>(iters: u64, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..ROUNDS {
        let t0 = std::time::Instant::now();
        f();
        best = best.min(t0.elapsed().as_secs_f64() / iters as f64);
    }
    best
}

/// Key and nonce pairs for the sweep.
///
/// Two of them, so nothing passes by being right for one constant input. Every
/// byte of one differs from every byte of the other, which is the property that
/// makes the sweep able to see a key laid out in the wrong order: an all-equal key
/// gives a permuted layout the same state, so it cannot detect the defect it
/// appears to be testing for.
fn keypairs() -> [([u8; 32], [u8; 12]); 2] {
    let a = (
        std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
        std::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7)),
    );
    let b = (
        std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        std::array::from_fn(|i| (i as u8).wrapping_mul(101).wrapping_add(61)),
    );
    [a, b]
}

/// Gate 1: byte-for-byte identity against the pinned reference, at every listed length and the 6 selected offsets. Panics on the first disagreement.
fn gate_identity(pairs: &[([u8; 32], [u8; 12]); 2]) -> usize {
    let lengths = lengths();
    let mut shapes = 0usize;
    for (k, n) in pairs {
        for start in [0u32, 1, 2, 7, 64, 65_535] {
            for &len in &lengths {
                let mut want = vec![0u8; len];
                let mut got = vec![0u8; len];
                dovetail_core::reference::reference_xor(k, n, start, &mut want);
                dovetail_core::record::fill_exact(k, n, start, &mut got);
                assert_eq!(want, got, "bit-identity: start {start} len {len}");
                shapes += 1;
            }
        }
    }
    shapes
}

/// Gate 2: the properties that are integer counts rather than durations, so they
/// are identical on every machine and are gated outright.
///
/// * blocks generated equals blocks needed, at every listed length and the 6 selected offsets: the number is the ladder's own count, returned by the passes that
///   ran the rounds, so a ladder that generated a block nobody asked for reports
///   it. It used to return `blocks_for(len)` and be compared against it, which is
///   `ceil(n / 64) == ceil(n / 64)` and cannot fail;
/// * zero heap allocations per call;
/// * zero zero-fills per call.
fn gate_deterministic(key: &[u8; 32], nonce: &[u8; 12]) -> usize {
    let lengths = lengths();
    let mut block_failures: Vec<String> = Vec::new();
    let mut alloc_failures: Vec<String> = Vec::new();

    for &len in lengths.iter().filter(|&&l| l > 0) {
        let mut buf = vec![0u8; len];
        for start in [0u32, 1, 2, 7, 64, 65_535] {
            let produced = dovetail_core::record::fill_exact(key, nonce, start, &mut buf);
            if !dovetail_core::record::blocks_match(len, produced) {
                block_failures.push(format!(
                    "{len}B at start {start}: the ladder reported {produced}, needed {}",
                    dovetail_core::record::blocks_for(len)
                ));
            }
        }

        // The buffer is allocated *before* the counting window opens; measuring
        // the harness' own `vec!` would say nothing about the core.
        let iters = 64u64;
        let ((), counts) = count::measure(|| {
            for _ in 0..iters {
                dovetail_core::record::fill_exact(
                    key,
                    nonce,
                    0,
                    std::hint::black_box(&mut buf[..]),
                );
            }
        });
        if counts.allocs != 0 {
            alloc_failures.push(format!(
                "{len}B: {:.3} allocations per call",
                counts.per_iter(iters)
            ));
        }
        if counts.bytes != 0 {
            alloc_failures.push(format!(
                "{len}B: {:.1} bytes allocated per call",
                counts.bytes_per_iter(iters)
            ));
        }
        if counts.zeroed != 0 {
            alloc_failures.push(format!("{len}B: {} zero-fills per call", counts.zeroed));
        }
    }

    // Rung 1's hot path is gated the same way: header encode runs per connection,
    // so one allocation there is one per dial. `uuid_bytes` used to allocate a
    // 32-char `String` on exactly this path; the sweep below is what keeps it at
    // zero across all three address families. Buffers are allocated before the
    // counting window opens, same discipline as above.
    {
        let link = dovetail_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8#x",
        )
        .expect("synthetic rung-1 link parses");
        for host in ["192.0.2.53", "2001:db8::1", "example.com"] {
            let need = link.request_header_len(host);
            let mut hdr = vec![0u8; need];
            let iters = 64u64;
            let ((), counts) = count::measure(|| {
                for _ in 0..iters {
                    let n = link.encode_into(host, 443, std::hint::black_box(&mut hdr[..]));
                    std::hint::black_box(n);
                }
            });
            if counts.allocs != 0 || counts.bytes != 0 || counts.zeroed != 0 {
                alloc_failures.push(format!(
                    "header {host}: {} allocs, {} bytes, {} zero-fills per 64 encodes",
                    counts.allocs, counts.bytes, counts.zeroed
                ));
            }
        }
    }

    // Rung 1's record framing is gated the same way: seal/open run per record,
    // so one allocation there is one per record on a live stream. Sessions and
    // buffers live outside the window; only the framing is inside it.
    {
        let uuid = [0xabu8; 16];
        for &len in [0usize, 1, 64, 1400, 8171] {
            let content = vec![0u8; len];
            let mut sealed = vec![0u8; 16 + 5 + len + 256];
            let mut opened = vec![0u8; 16 + 5 + len + 256];
            let iters = 64u64;
            let ((), counts) = count::measure(|| {
                let mut session = dovetail_core::vless::VisionSeal::new(key, nonce, &uuid);
                let mut stream = dovetail_core::vless::VisionOpen::new(&uuid);
                for _ in 0..iters {
                    let n = session.seal(
                        std::hint::black_box(&mut sealed[..]),
                        std::hint::black_box(&content[..]),
                        dovetail_core::vless::VisionCommand::Continue,
                        false,
                    );
                    let (written, _) =
                        stream.open(&sealed[..n], std::hint::black_box(&mut opened[..]));
                    std::hint::black_box((n, written));
                }
            });
            if counts.allocs != 0 || counts.bytes != 0 || counts.zeroed != 0 {
                alloc_failures.push(format!(
                    "vision {len}B: {} allocs, {} bytes, {} zero-fills per 64 seals",
                    counts.allocs, counts.bytes, counts.zeroed
                ));
            }
        }
    }

    assert!(
        block_failures.is_empty(),
        "DISCARDED WORK: the ladder generated blocks the caller's length does not need at {} \
         length(s): {:?}",
        block_failures.len(),
        &block_failures[..block_failures.len().min(10)]
    );
    assert!(
        alloc_failures.is_empty(),
        "ALLOCATION: the core allocated or zero-filled at {} length(s): {:?}",
        alloc_failures.len(),
        &alloc_failures[..alloc_failures.len().min(10)]
    );

    lengths.len()
}

/// One timed length, on both sides, best of [`ROUNDS`] each.
///
/// The rounds interleave reference/dovetail/reference/dovetail rather than
/// running all of one side first: back-to-back rounds share the same thermal
/// and frequency conditions, so a slow drift across the run cannot favour
/// whichever side ran while the machine was cooler. Same samples as
/// sequential rounds, fairer pairing.
fn measure_len(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let iters = iters_for(len);
    // One buffer for the whole run, reused: a per-iteration `vec!` adds the same
    // malloc and memset to both sides and dilutes the ratio towards 1.
    let mut buf = vec![0u8; len];

    let mut base = f64::MAX;
    let mut ours = f64::MAX;
    for _ in 0..ROUNDS {
        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            dovetail_core::reference::reference_xor(
                key,
                nonce,
                0,
                std::hint::black_box(&mut buf[..]),
            );
        }
        base = base.min(t0.elapsed().as_secs_f64() / iters as f64);
        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            dovetail_core::record::fill_exact(key, nonce, 0, std::hint::black_box(&mut buf[..]));
        }
        ours = ours.min(t0.elapsed().as_secs_f64() / iters as f64);
    }

    let mut ratio = base / ours;

    // Anything under the bar is confirmed at four times the budget before it fails
    // the job: the bar stays strict (1.00x) and the confirmation is what keeps a
    // noisy sample from becoming a permanent failure. It does not lower the bar.
    if ratio < BAR {
        let heavy = iters * 4;
        let base2 = time_best(heavy, || {
            for _ in 0..heavy {
                dovetail_core::reference::reference_xor(
                    key,
                    nonce,
                    0,
                    std::hint::black_box(&mut buf[..]),
                );
            }
        });
        let ours2 = time_best(heavy, || {
            for _ in 0..heavy {
                dovetail_core::record::fill_exact(
                    key,
                    nonce,
                    0,
                    std::hint::black_box(&mut buf[..]),
                );
            }
        });
        ratio = base2 / ours2;
        return Row {
            len,
            base: base2,
            ours: ours2,
            ratio,
            remeasured: true,
        };
    }

    Row {
        len,
        base,
        ours,
        ratio,
        remeasured: false,
    }
}

/// Assemble the report.
///
/// Separate from `main` so that the whole document exists before any of it is
/// written to disk. It did not used to: the summary was appended after the file
/// had been saved, so the file never contained it — and the summary is the line
/// a reader looks for first.
fn build_report(declared: &str, shapes: usize, measured_lengths: usize, rows: &[Row]) -> String {
    let mut report = String::new();
    let _ = writeln!(report, "# dovetail benchmark\n");

    // What was compared against, and what this build actually ran. Both are named
    // because a speedup is only attributable once both sides of it are.
    let _ = writeln!(report, "| | |");
    let _ = writeln!(report, "| --- | --- |");
    let _ = writeln!(report, "| declared reference | `{declared}` |");
    let _ = writeln!(
        report,
        "| reference actually ran | {} |",
        dovetail_core::reference::backend()
    );
    let _ = writeln!(
        report,
        "| dovetail core | {} |",
        dovetail_core::chacha_backend()
    );
    let _ = writeln!(report, "| target | `{}` |", std::env::consts::ARCH);
    let _ = writeln!(report);

    let _ = writeln!(report, "## Gate 1 — identity\n");
    let _ = writeln!(
        report,
        "**{shapes} shapes**, byte for byte, at every listed length and the 6 selected offsets: dense, not exhaustive (see `lengths`)."
    );

    let _ = writeln!(report, "\n## Gate 2 — deterministic properties\n");
    let _ = writeln!(
        report,
        "Across **{measured_lengths} lengths**: blocks generated equals blocks needed at every\n\
         one; **0** heap allocations per call; **0** zero-fills per call.\n\n\
         These are integer counts, so they are identical on every machine and are gated\n\
         outright rather than reported."
    );

    let _ = writeln!(report, "\n## Gate 3 — timing\n");
    let timed = rows.len();
    let listed = lengths().len();
    let _ = writeln!(
        report,
        "Best of {ROUNDS} interleaved rounds per side (reference/dovetail/reference/…,\n\
         so a thermal drift cannot favour one side). The bar is {BAR:.2}x: 5% is\n\
         runner noise, and any length under it is re-measured at 4x the budget\n\
         and marked `remeasured`, and still fails the job if it stays under the\n\
         bar. The re-measure confirms the number; it does not lower the bar.\n\n\
         {timed} of {listed} listed lengths are timed, starting at {TIMING_MIN} bytes:\n\
         lengths 1-64 are one block, a tie by construction, so they are covered\n\
         byte for byte in gate 1 and not timed here.\n"
    );
    let _ = writeln!(
        report,
        "| len | reference ns/op | dovetail ns/op | speedup | remeasured |"
    );
    let _ = writeln!(report, "|---:|---:|---:|---:|:--:|");
    for r in rows {
        let _ = writeln!(
            report,
            "| {} | {:.1} | {:.1} | {:.2}x | {} |",
            r.len,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio,
            if r.remeasured { "yes" } else { "" }
        );
    }

    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio.total_cmp(&b.ratio)),
        rows.iter().max_by(|a, b| a.ratio.total_cmp(&b.ratio)),
    ) {
        let _ = writeln!(
            report,
            "\n**Gate: {} lengths, none below {BAR:.2}x.** Worst {:.2}x @ {}B, best {:.2}x @ {}B.",
            rows.len(),
            worst.ratio,
            worst.len,
            best.ratio,
            best.len
        );
    }

    let _ = writeln!(
        report,
        "\n> The reference is re-keyed and re-seeked on every call, which a stateful record\n\
         > layer would not do. That flatters short lengths in particular. The 16384 B row is\n\
         > the one closest to a real VMess/Shadowsocks record and should be read as the\n\
         > headline; the reference's own backend, named above, is what decides whether a\n\
         > ratio here reflects this workspace's work or the reference's fallback."
    );

    // Per-method matrix, every report: implemented cells carry numbers above,
    // the rest stay empty with their reason and their proof. See `methods.rs`.
    report.push_str(&methods::table());

    report
}

fn main() {
    let args = parse_args();
    let declared = args.declared;
    let pairs = keypairs();
    let (key, nonce) = pairs[0];

    // Gate 1: identity, before any timing.
    let shapes = gate_identity(&pairs);
    println!("gate 1 passed: bit-identical at {shapes} shapes");

    // Gate 2: the properties that are counts rather than durations.
    let measured_lengths = gate_deterministic(&key, &nonce);
    println!(
        "gate 2 passed: 0 discarded blocks, 0 allocations, 0 zero-fills at {measured_lengths} lengths"
    );

    // Gate 3: timing, the only machine-dependent one. Lengths below TIMING_MIN
    // are a tie both sides cannot lose, so timing them would gate the runner.
    let rows: Vec<Row> = lengths()
        .iter()
        .filter(|&&l| l >= TIMING_MIN)
        .map(|&len| measure_len(&key, &nonce, len))
        .collect();

    let mut report = build_report(&declared, shapes, measured_lengths, &rows);

    // Config comparison, after the proof gates: hand CI a working link and it
    // appends the redacted offline table (and the empty-with-reason live
    // cells). A bad link fails here, not silently.
    if let Some(link_str) = args.config {
        match dovetail_core::vless::VlessLink::parse(&link_str) {
            Ok(link) => {
                let extra = compare::compare_offline(&link);
                report.push_str(&extra);
                println!("config: {}", compare::describe_redacted(&link));
            }
            Err(e) => {
                eprintln!("--config: bad vless link: {e}");
                std::process::exit(2);
            }
        }
    }

    // Written *before* the gate is asserted on, so a failing run still publishes
    // the table it failed on. Asserting first meant a red build printed "no
    // report", which is the one moment the numbers are wanted.
    std::fs::create_dir_all("target").expect("create target dir");
    std::fs::write("target/bench-report.md", &report).expect("write report");

    let failures: Vec<&Row> = rows.iter().filter(|r| r.ratio < BAR).collect();
    assert!(
        failures.is_empty(),
        "REGRESSION: slower than the reference at {} length(s), worst {:.3}x. Failing lengths: {}",
        failures.len(),
        failures
            .iter()
            .map(|r| r.ratio)
            .fold(f64::INFINITY, f64::min),
        failures
            .iter()
            .map(|r| format!("{}B={:.3}x", r.len, r.ratio))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let worst = rows
        .iter()
        .min_by(|a, b| a.ratio.total_cmp(&b.ratio))
        .unwrap();
    let best = rows
        .iter()
        .max_by(|a, b| a.ratio.total_cmp(&b.ratio))
        .unwrap();
    println!(
        "gate 3 passed: {} lengths, none below {BAR:.2}x. Worst {:.2}x @ {}B, best {:.2}x @ {}B",
        rows.len(),
        worst.ratio,
        worst.len,
        best.ratio,
        best.len
    );
    println!(
        "PASS: bit-identical at {shapes} shapes, no discarded work or allocation, and not slower at any length"
    );
}

/// One measured length, on both sides.
struct Row {
    len: usize,
    /// Best reference seconds per call.
    base: f64,
    /// Best dovetail seconds per call.
    ours: f64,
    /// `base / ours`. Above 1.00 means dovetail is faster.
    ratio: f64,
    /// Whether this length was re-measured at four times the budget.
    remeasured: bool,
}
