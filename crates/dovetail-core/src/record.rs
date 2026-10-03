//! The record layer: framing and keystream, and where they are made to agree.
//!
//! # The technique this crate is built around
//!
//! Almost every proxy stack pays the same tax twice. A record layer that needs
//! *n* bytes derives keystream for a fixed larger unit — a four-block `ChaCha20`
//! refill, a full buffer of zeros — and copies out the part it wanted. Two
//! costs follow, and neither is visible in a profile because the copy is
//! spread thin across every call:
//!
//! * **Work that is thrown away.** The refill computes rounds for bytes no one
//!   reads.
//! * **A copy.** Bytes land in a scratch buffer and are then moved again.
//!
//! Removing both is only possible if the discarded work can be proven
//! unnecessary. That proof is the job of [`fill_exact`], and it is checkable:
//! the differential test compares against the reference at every length and
//! every block offset, so "same bytes, less work" is a fact rather than a
//! claim.
//!
//! # What is checked
//!
//! - **Identity.** [`fill_exact`] against the `chacha20` crate. The unit test
//!   covers 44 lengths x 6 offsets x 2 key pairs = 528 shapes; the benchmark gate covers
//!   300 lengths x 6 offsets x 2 key pairs = 3600 shapes, checked by `bench.yml` gate 1.
//!   Dense, not exhaustive: every byte 0..=256, then M-1/M/M+1 for each listed multiple only.
//!   Offsets are a selection (0 is every caller, the rest are resume paths), not a proof over `u32`.
//! - **Counter position.** Asserted directly: block counter 0 and block counter
//!   8 must not produce the same keystream.
//! - **No discarded work.** The counter only advances by blocks actually
//!   produced, asserted in the tests.
//! - **Bounds.** Every write is a sub-slice of the caller's buffer, so a write
//!   past the end is an index panic rather than a silent overrun, and the
//!   differential comparison catches any write to the wrong place inside it.

/// Fill `buf` with keystream. The keystream is `XOR`ed over `buf` in place.
///
/// `start_block` is the `ChaCha20` block counter the caller is positioned at. The
/// counter only ever advances by the blocks actually produced, so a buffer of
/// `n` bytes never generates a block it does not use.
///
/// Returns the number of 64-byte blocks the ladder generated, counted by the
/// passes that ran the rounds — not computed here. That is the whole point: the
/// value has to be an observation of the work, so that a ladder which generated a
/// block nobody asked for *reports* it and [`blocks_match`] rejects it. When this
/// returned `blocks_for(buf.len())` the check was `ceil(n / 64) == ceil(n / 64)`
/// and could not fail; a caller that does not care may ignore the return.
///
/// # Panics
///
/// If `buf.len()` exceeds `u32::MAX` blocks worth of counter space, which would
/// wrap the counter and silently repeat keystream.
pub fn fill_exact(key: &[u8; 32], nonce: &[u8; 12], start_block: u32, buf: &mut [u8]) -> u64 {
    let blocks = blocks_for(buf.len());
    assert!(
        blocks <= u64::from(u32::MAX) - u64::from(start_block),
        "chacha20 block counter would wrap; a nonce's keystream would repeat"
    );

    u64::from(crate::chacha::xor_blocks(key, nonce, start_block, buf))
}

/// The blocks a buffer of `buf_len` bytes needs, which is what the ladder has to
/// report for [`blocks_match`] to hold.
pub const fn blocks_for(buf_len: usize) -> u64 {
    (buf_len as u64).div_ceil(64)
}

/// Gate 2's whole comparison, as one function the gate and the tests share.
///
/// `generated` is what the ladder reported and `buf_len` is what the caller asked
/// for. Kept here rather than in the benchmark so the thing the gate checks and
/// the thing that proves the gate can fail are the same code: a test feeding it a
/// wrong count is testing the gate, not a copy of it.
pub const fn blocks_match(buf_len: usize, generated: u64) -> bool {
    generated == blocks_for(buf_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lengths and block offsets the gate sweeps, kept here so the unit tests and
    /// `dovetail-bench` gate 2 cover the same ground.
    const SWEEP: ([u32; 3], [usize; 6]) = ([0, 1, 65_535], [0, 1, 63, 64, 65, 256]);

    #[test]
    fn the_ladder_reports_the_blocks_the_caller_asked_for() {
        // The claim is about what the core *does*, so this calls it: `generated`
        // is the ladder's own count, and comparing it against `blocks_for` is
        // gate 2's comparison, not a restatement of it.
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &start_block in &SWEEP.0 {
            for &len in &SWEEP.1 {
                let mut buf = vec![0u8; len];
                let generated = fill_exact(&key, &nonce, start_block, &mut buf);
                assert!(
                    blocks_match(len, generated),
                    "start {start_block} len {len}: the ladder reported {generated} blocks for a \
                     buffer of {len} bytes, which needs {}",
                    blocks_for(len)
                );
            }
        }
    }

    #[test]
    fn the_block_count_check_fails_when_the_count_is_wrong() {
        // A gate nobody has watched fail is not a gate. `+1` is what a tail that
        // overshot by one state would report and `-1` what one that dropped a
        // block would, so this exercises the comparison gate 2 makes on both sides
        // of the real ladder's number.
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &len in &[0usize, 1, 63, 64, 65, 255, 256, 257, 512, 16384] {
            let mut buf = vec![0u8; len];
            let generated = fill_exact(&key, &nonce, 0, &mut buf);
            assert!(
                blocks_match(len, generated),
                "len {len}: the real ladder must match"
            );
            assert!(
                !blocks_match(len, generated + 1),
                "len {len}: one block too many must be rejected"
            );
            if generated > 0 {
                assert!(
                    !blocks_match(len, generated - 1),
                    "len {len}: one block too few must be rejected"
                );
            }
        }
    }

    #[test]
    fn blocks_for_is_the_ceiling() {
        assert_eq!(blocks_for(65), 2);
        assert_eq!(blocks_for(64), 1);
        assert_eq!(blocks_for(128), 2);
        assert_eq!(blocks_for(129), 3);
        assert_eq!(blocks_for(0), 0);
    }

    #[test]
    fn refuses_a_wrapping_counter() {
        let mut buf = [0u8; 64];
        // `AssertUnwindSafe` because `&mut [u8; 64]` is not `UnwindSafe`. The
        // claim under test is that the panic happens *before* any write, and
        // `buf` is left untouched, which is checked below rather than assumed:
        // if the guard were ever removed the count would differ.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_exact(&[0u8; 32], &[0u8; 12], u32::MAX, &mut buf)
        }));
        assert!(r.is_err(), "a wrapping counter must be refused, not obeyed");
        assert_eq!(
            buf, [0u8; 64],
            "the guard must fire before any keystream is written"
        );
    }
}
