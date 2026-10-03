//! `ChaCha20` keystream: one algorithm, one portable implementation, one thin
//! layer per architecture.
//!
//! # Why there is only one algorithm
//!
//! Every backend implements the same [`Lanes`] trait and the round function is
//! written once, generically. A per-architecture core would be faster to write
//! and impossible to trust: three hand-written `ChaCha20` cores drift, and the
//! differential test then reports a mismatch without saying which one is wrong.
//! Written this way, the only thing that can differ between architectures is the
//! five primitives below, and every one of them is a single instruction on each
//! target.
//!
//! Bit-identity is therefore structural rather than merely tested: the portable
//! implementation and the NEON and AVX2 cores execute *the same source*, so they
//! cannot disagree about the algorithm. What still has to be checked is that each
//! `Lanes` impl means what it claims — which is what the differential test at
//! every length and every block offset is for.
//!
//! # What Miri covers, and what it does not
//!
//! [`portable`] is safe Rust, so Miri interprets the ladder, the counter
//! arithmetic, the group boundaries and every store offset. The architecture
//! modules contain no control flow and no pointer arithmetic beyond what Miri
//! cannot interpret anyway: they read and write through `core::arch` intrinsics,
//! whose safety rests on the `Lanes` contract, not on bounds. That contract is
//! discharged by the differential test rather than by Miri.
//!
//! # The lane layout
//!
//! A vector carries four consecutive state words per 128-bit *chunk*. Chunk `c`
//! of register `g` holds words `4g..4g+3` of block `c * 4 + g`, which is the
//! layout the Crypto++ core uses: no store-time transpose is needed, because each
//! register is already a run of consecutive output bytes.
//!
//! ```text
//!            register g=0        g=1          g=2          g=3
//!   chunk 0   words  0..3       words 4..7   words 8..11   words 12..15   -> block 0
//!   chunk 1   words  0..3       words 4..7   words 8..11   words 12..15   -> block 4
//! ```
//!
//! `NST` such groups run interleaved. Interleaving is the whole point: one
//! `ChaCha20` chain is a dependent add-xor-rotate chain with nothing to overlap, so
//! a wide out-of-order core stalls on it. Four independent chains fill the gap.

// Every function in this module that touches a lane primitive is
// `inline(always)`. The reason is one sentence: an outlined generic function does
// not inherit the `#[target_feature]` of the function that called it, so the
// AVX2 intrinsics inside it lose their feature, drop to 128-bit registers and
// spill the state to the stack on every call. The ladder instantiates its core
// over four widths, which is enough call sites for the inliner to make exactly
// that choice, and the AVX2 runners measured it as 0.16x at two blocks against
// 1.86x at four. `inline` is a hint; this is a guarantee.
#![allow(
    clippy::inline_always,
    reason = "lane primitives are only sound inside the caller's target_feature function"
)]

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "aarch64")]
mod neon;
mod portable;
#[cfg(target_arch = "x86_64")]
mod sse2;

/// A vector of 32-bit words, in the layout described in the module docs.
///
/// # Safety
///
/// An implementor must uphold all of the following, and the differential test is
/// what checks them:
///
/// - `LANES` words, and `CHUNKS = LANES / 4` independent 128-bit chunks;
/// - the four words of a chunk are consecutive state words of **one** block, in
///   increasing order;
/// - `add`, `bitxor` and the rotates are applied lane-wise, so chunk `c` of the
///   result depends only on chunk `c` of the inputs;
/// - `rot_chunks(n)` rotates the four words *within each chunk*, leaving chunk
///   membership alone;
/// - `xor_chunk(c, dst)` XORs chunk `c`'s four words, in increasing order and as
///   little-endian bytes, into `dst`.
pub(crate) trait Lanes: Copy {
    /// Words per vector: 4 for a 128-bit vector, 8 for a 256-bit one.
    const LANES: usize;
    /// Independent 128-bit chunks per vector, i.e. blocks in flight per register.
    const CHUNKS: usize = Self::LANES / 4;

    /// From exactly `LANES` words, in lane order.
    fn from_lanes(words: &[u32]) -> Self;

    fn add(self, o: Self) -> Self;
    fn bitxor(self, o: Self) -> Self;

    fn rotl16(self) -> Self;
    fn rotl12(self) -> Self;
    fn rotl8(self) -> Self;
    fn rotl7(self) -> Self;

    /// Rotate the four words of each chunk left by `n`, where `1 <= n <= 3`.
    fn rot_chunks(self, n: usize) -> Self;

    /// XOR chunk `c`'s four words into `dst` as 16 little-endian bytes.
    fn xor_chunk(self, c: usize, dst: &mut [u8; 16]);
}

/// `expand 32-byte k`, the `ChaCha20` constants.
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// States the vector core interleaves per pass.
///
/// The cliff is the register file, and the register file is not the same size on
/// both architectures this builds for. Sixteen `ymm` is the whole of `x86_64`'s,
/// so four states of four registers is the most that fits with nothing spilled:
/// one more state spills the state to stack on every instruction of every round.
/// `aarch64` has thirty-two `q` registers, and the same four states were leaving
/// half of them idle — measured at 1.26 GB/s against 1.85 GB/s on the same
/// machine with the same sixteen states and the same twenty rounds.
#[cfg(target_arch = "x86_64")]
const GROUP_STATES: usize = 4;
#[cfg(target_arch = "aarch64")]
const GROUP_STATES: usize = 8;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const GROUP_STATES: usize = 4;

/// The widest pass the tail can take: one state short of a whole group.
///
/// Capped at eight so the dispatch in [`xor_tail`] is one fixed list rather than a
/// list that has to be kept in step with this constant. The clamp here and the
/// arms there are the two halves of one contract, and a contract written twice
/// is a contract that can be broken once: a `TAIL_STATES` wider than the widest
/// arm asks [`xor_groups`] for a pass it never runs, and the bytes of the blocks
/// nobody generated come back zero — wrong at exactly the lengths where the tail
/// overshoots, and nowhere else.
const TAIL_STATES: usize = if GROUP_STATES < 8 { GROUP_STATES } else { 8 } - 1;

/// The 16-word state for `key` and `nonce`, with the counter left at zero.
#[inline]
fn base_state(key: &[u8; 32], nonce: &[u8; 12]) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&CONSTANTS);
    for (i, word) in s[4..12].iter_mut().enumerate() {
        *word = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("key is 32 bytes"));
    }
    for (i, word) in s[13..16].iter_mut().enumerate() {
        *word = u32::from_le_bytes(
            nonce[i * 4..i * 4 + 4]
                .try_into()
                .expect("nonce is 12 bytes"),
        );
    }
    s
}

/// The part of a state that every block in a call shares.
///
/// Words 0..12 of the state are identical in every block; only word 12, the
/// counter, moves. Holding the shared part in registers for the whole call —
/// rather than rebuilding it per pass and keeping a full second copy of the
/// initial state alive for the feed-forward — is what stops the rounds from
/// competing with their own inputs for registers. The copy cost sixteen
/// registers on aarch64 and thirty-two on `x86_64`, which is the whole file.
#[derive(Clone, Copy)]
pub(crate) struct Base<V> {
    /// Words 0..3, 4..7 and 8..11, each broadcast into every chunk of a vector.
    regs: [V; 3],
    /// Words 13..16: the nonce tail, which follows the counter in every block.
    tail: [u32; 3],
}

/// Build [`Base`] once per call rather than once per pass.
///
/// The key and the nonce are the same for every block the call produces, so
/// parsing them per group is the same thirty-two key loads and twelve nonce
/// loads per 512 bytes of keystream, every one of them discarded at the end of
/// the pass.
#[inline]
fn base<V: Lanes>(key: &[u8; 32], nonce: &[u8; 12]) -> Base<V> {
    let state = base_state(key, nonce);
    let mut lanes = [0u32; 16];
    let regs = core::array::from_fn(|g| {
        for c in 0..V::CHUNKS {
            lanes[4 * c..4 * c + 4].copy_from_slice(&state[4 * g..4 * g + 4]);
        }
        V::from_lanes(&lanes[..V::LANES])
    });
    Base {
        regs,
        tail: [state[13], state[14], state[15]],
    }
}

/// Word 12 of every chunk is the block counter; words 13..15 are the nonce tail.
///
/// Built where it is needed and dropped again, which is cheaper than keeping it
/// live across the rounds: a handful of scalar inserts against a register held
/// for the whole pass.
#[inline(always)]
fn counter<V: Lanes>(base: &Base<V>, start: u32, s: usize) -> V {
    let mut lanes = [0u32; 16];
    for c in 0..V::CHUNKS {
        lanes[4 * c] = start.wrapping_add((s * V::CHUNKS + c) as u32);
        lanes[4 * c + 1] = base.tail[0];
        lanes[4 * c + 2] = base.tail[1];
        lanes[4 * c + 3] = base.tail[2];
    }
    V::from_lanes(&lanes[..V::LANES])
}

/// Eight quarter-round steps over the four registers of one state.
///
/// `r[0..4]` hold words `0..3`, `4..7`, `8..11` and `12..15`. Because each
/// register holds four consecutive words, one vector add does the work of four
/// scalar adds; that is the entire reason the core is vectorised this way round
/// rather than with one word per lane.
///
/// `inline(always)`: this is the innermost function that touches a lane
/// primitive, so it has to end up lexically inside whatever `#[target_feature]`
/// function reaches it. Outlined, it loses the feature with it — 128-bit
/// registers, the state spilled to the stack and reloaded on every call — which
/// is the 6x the AVX2 runner measured for two blocks against four on the same
/// core.
#[allow(
    clippy::inline_always,
    reason = "load-bearing: keeps the lane intrinsics inside the caller's target_feature function"
)]
#[inline(always)]
fn quarter_round<V: Lanes>(r: &mut [V; 4]) {
    r[0] = r[0].add(r[1]);
    r[3] = r[3].bitxor(r[0]).rotl16();
    r[2] = r[2].add(r[3]);
    r[1] = r[1].bitxor(r[2]).rotl12();
    r[0] = r[0].add(r[1]);
    r[3] = r[3].bitxor(r[0]).rotl8();
    r[2] = r[2].add(r[3]);
    r[1] = r[1].bitxor(r[2]).rotl7();
}

/// Ten double rounds over `NST` interleaved states, with the register rotation
/// that turns the row round into the diagonal round and back.
///
/// One loop per half-round rather than four: each state is independent, so
/// running a state's quarter-round and its shuffle together is the same bytes as
/// running all quarter-rounds then all shuffles, with a quarter of the passes over
/// `regs` (10 instead of 40 per group) and the state hot in cache.
#[inline(always)]
fn rounds<V: Lanes, const NST: usize>(regs: &mut [[V; 4]; NST]) {
    for _ in 0..10 {
        for s in regs.iter_mut() {
            quarter_round(s);
            s[1] = s[1].rot_chunks(1);
            s[2] = s[2].rot_chunks(2);
            s[3] = s[3].rot_chunks(3);
            quarter_round(s);
            s[1] = s[1].rot_chunks(3);
            s[2] = s[2].rot_chunks(2);
            s[3] = s[3].rot_chunks(1);
        }
    }
}

/// Generate `NST * V::CHUNKS` blocks of keystream at `start` and XOR them into
/// `out`, which may be shorter than that if the caller's last block is partial.
///
/// Returns the blocks it generated: `NST * V::CHUNKS`, counted here because this
/// is the code that ran the rounds, not because the caller worked it out. A pass
/// handed more states than the caller's bytes need therefore reports the excess,
/// which is what makes "no discarded work" a fact about the ladder instead of a
/// restatement of the length.
///
/// A partial last block is generated with the block before it and stored short —
/// its twenty rounds run over the whole state whatever the caller keeps — so the
/// blocks generated are the blocks needed, rounded up to one, never more.
///
/// Every store is a sub-slice of `out` produced by `as_chunks_mut`, so a write
/// past the end is an index panic rather than a silent overrun.
#[inline(always)]
pub(crate) fn xor_groups<V: Lanes, const NST: usize>(
    base: &Base<V>,
    start: u32,
    out: &mut [u8],
) -> u32 {
    // `NST * CHUNKS` blocks of 64 bytes, and `CHUNKS = LANES / 4`.
    debug_assert!(out.len() <= NST * V::LANES * 16);

    // Built directly rather than from a zero array: every register is produced
    // once here, so starting from zeros would be `NST * 4` dead vector
    // constructions per group. The three shared registers hold the *same* value
    // in every state, so they are copied rather than rebuilt.
    let mut regs: [[V; 4]; NST] =
        core::array::from_fn(|s| [base.regs[0], base.regs[1], base.regs[2], counter(base, start, s)]);

    rounds::<V, NST>(&mut regs);

    // Feed-forward fused into the store: `reg[g].add(initial[g])` is lane-wise
    // pure, so `add-then-store` and `store(add(...))` are the same bytes. Doing
    // it here removes a whole pass over `regs` with no change in output.
    //
    // The loop is group-major (`s`, then `c`) rather than block-major, so
    // `group = block / CHUNKS` and `c = block % CHUNKS` are never computed: `s`
    // *is* the group and `c` *is* the lane. Same stores, no division.
    //
    // The store walks whole 64-byte blocks — four 16-byte chunks of a register,
    // which is what the lane load needs — so the test "is this block inside
    // `out`" is made once per 64 bytes rather than once per 16. The bytes that
    // do not fill a whole block are staged exactly as before, so a short `out`
    // still never has a byte written past its end.
    let (blocks, partial) = out.as_chunks_mut::<64>();
    let mut i = 0usize;
    'stores: for s in 0..NST {
        // Rebuilt here rather than kept: four registers live at the store, not
        // `NST * 4` live across the rounds.
        let ff = [
            base.regs[0],
            base.regs[1],
            base.regs[2],
            counter(base, start, s),
        ];
        for c in 0..V::CHUNKS {
            let Some(block) = blocks.get_mut(i) else {
                // `out` is no longer than a whole group, so at most one block per
                // call is partial: this runs once and then stops.
                let (chunks, tail) = partial.as_chunks_mut::<16>();
                for (g, chunk) in chunks.iter_mut().enumerate() {
                    regs[s][g].add(ff[g]).xor_chunk(c, chunk);
                }
                if !tail.is_empty() {
                    let mut staged = [0u8; 16];
                    let g = chunks.len();
                    regs[s][g].add(ff[g]).xor_chunk(c, &mut staged);
                    for (dst, ks) in tail.iter_mut().zip(staged) {
                        *dst ^= ks;
                    }
                }
                break 'stores;
            };
            let (chunks, _) = block.as_chunks_mut::<16>();
            for (g, chunk) in chunks.iter_mut().enumerate() {
                regs[s][g].add(ff[g]).xor_chunk(c, chunk);
            }
            i += 1;
        }
    }
    (NST * V::CHUNKS) as u32
}

/// The bytes one pass of `V`'s core covers: `GROUP_STATES` states, `CHUNKS`
/// blocks each, 64 bytes a block.
const fn group_bytes<V: Lanes>() -> usize {
    GROUP_STATES * V::CHUNKS * 64
}

/// The blocks left after the group loop, on the widest core that covers them.
///
/// `xor_groups::<V, n>` generates exactly `n * V::CHUNKS` blocks, so the tail
/// runs the largest `n <= TAIL_STATES` that does not overshoot and comes back for
/// the rest; what is left when a single block is all that remains goes to the
/// scalar core, which is the only width that generates exactly one. Two blocks is
/// the floor for the vector core because one block is a single chain with nothing
/// to interleave, and at one block the vector core measures slower than scalar
/// code for the same 20 rounds.
///
/// Returns what the passes reported, which is the same number the counter advanced
/// by: the report and the advance are one value read twice, so they cannot drift.
#[inline(always)]
fn xor_tail<V: Lanes>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    base: &Base<V>,
    start: u32,
    buf: &mut [u8],
) -> u32 {
    let mut ctr = start;
    let mut rest = buf;
    let mut blocks = 0u32;
    while rest.len() > 64 {
        let states = (rest.len().div_ceil(64) / V::CHUNKS).clamp(1, TAIL_STATES);
        let (head, tail) = rest.split_at_mut((states * V::CHUNKS * 64).min(rest.len()));
        // One arm per width, up to the cap `TAIL_STATES` clamps to. Written as a
        // list rather than a `_ =>` catch-all so a width with no arm is a
        // compile-time hole rather than a silently unwritten tail.
        macro_rules! pass {
            ($($n:literal),+ $(,)?) => {
                match states {
                    $($n => xor_groups::<V, $n>(base, ctr, head),)+
                    _ => unreachable!("`states` is clamped to TAIL_STATES"),
                }
            };
        }
        blocks += pass!(1, 2, 3, 4, 5, 6, 7);
        ctr = ctr.wrapping_add((states * V::CHUNKS) as u32);
        rest = tail;
    }
    if !rest.is_empty() {
        blocks += one_block(key, nonce, ctr, rest);
    }
    blocks
}

/// The best one-block core this build has, for the last block of a tail.
///
/// `x86_64` gets [`sse2`] and everywhere else gets [`portable`], and the reason is
/// measured rather than assumed: on `x86_64` the portable core is compiled to
/// scalar code, while a 128-bit core keeps the state in registers, and on aarch64
/// the portable core is *faster* than NEON at one block because a single chain has
/// nothing to interleave (91.9 ns against 119.7 ns).
#[cfg(target_arch = "x86_64")]
#[inline]
fn one_block(key: &[u8; 32], nonce: &[u8; 12], ctr: u32, out: &mut [u8]) -> u32 {
    sse2::xor_block(key, nonce, ctr, out)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn one_block(key: &[u8; 32], nonce: &[u8; 12], ctr: u32, out: &mut [u8]) -> u32 {
    portable::xor_block(key, nonce, ctr, out)
}

/// XOR keystream over `buf` from block counter `start`, and return the blocks it
/// generated.
///
/// Whole vector groups while one still fits, then [`xor_tail`] for the blocks that
/// are left. The counter is advanced by the blocks each pass actually produced,
/// which is the single place the two offsets — the group offset and the block
/// offset — have to be added together. Deriving one of them from a byte index and
/// the other from a loop counter is how this went wrong before.
#[cfg(target_arch = "x86_64")]
pub(crate) fn xor_blocks(key: &[u8; 32], nonce: &[u8; 12], start: u32, buf: &mut [u8]) -> u32 {
    // SAFETY: the probe is what makes `avx2`'s `target_feature` sound on a build
    // that was not compiled with `+avx2`, and it is the same check the whole
    // ladder ran per group before it was hoisted out of the loop: hoisting it
    // cannot select a path the per-group check would not have taken.
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: delegated to this probe.
        unsafe { avx2::xor_blocks(key, nonce, start, buf) }
    } else {
        xor_ladder::<portable::U4>(key, nonce, start, buf)
    }
}

/// XOR keystream over `buf` from block counter `start`, and return the blocks it
/// generated.
///
/// Whole vector groups while one still fits, then [`xor_tail`] for the blocks that
/// are left. The counter is advanced by the blocks each pass actually produced,
/// which is the single place the two offsets — the group offset and the block
/// offset — have to be added together. Deriving one of them from a byte index and
/// the other from a loop counter is how this went wrong before.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn xor_blocks(key: &[u8; 32], nonce: &[u8; 12], start: u32, buf: &mut [u8]) -> u32 {
    xor_ladder::<Wide>(key, nonce, start, buf)
}

/// The ladder for one core: whole groups, then the blocks that are left.
///
/// `#[inline]` because on `x86_64` this is only ever inlined into `avx2`'s
/// `#[target_feature]` function, and that is what makes the AVX2 primitives
/// reachable at all: they are only sound in code built with the feature on.
#[inline(always)]
fn xor_ladder<V: Lanes>(key: &[u8; 32], nonce: &[u8; 12], start: u32, buf: &mut [u8]) -> u32 {
    // Once for the whole call, not once per pass.
    let base = base::<V>(key, nonce);
    let mut ctr = start;
    let mut rest = buf;
    let mut blocks = 0u32;
    while rest.len() >= group_bytes::<V>() {
        // The length is exactly one group by the loop condition, so the split
        // cannot fail and cannot be short.
        let (head, tail) = rest.split_at_mut(group_bytes::<V>());
        blocks += xor_groups::<V, GROUP_STATES>(&base, ctr, head);
        ctr = ctr.wrapping_add((GROUP_STATES * V::CHUNKS) as u32);
        rest = tail;
    }
    blocks + xor_tail::<V>(key, nonce, &base, ctr, rest)
}

/// The vector core this build dispatches to for the tail, named once so the
/// ladder and the group loop cannot disagree about which core they run.
#[cfg(target_arch = "aarch64")]
type Wide = neon::N4;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
type Wide = portable::U4;

/// Which core this build dispatches to, and how wide it is.
///
/// Reported next to the reference's own backend by the benchmark, because a
/// speedup is only attributable once both sides of it are named.
pub const fn backend() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "4-lane core: AVX2, 8 blocks per iteration, at runtime-detected width"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "4-lane core: NEON, 4 blocks per iteration"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "4-lane core: portable, 4 blocks per iteration"
    }
}
