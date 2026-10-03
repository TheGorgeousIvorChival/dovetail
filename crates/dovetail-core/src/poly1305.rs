//! `Poly1305`, in five 26-bit limbs, from safe Rust and nothing else.
//!
//! # Why this is here
//!
//! `ChaCha20-Poly1305` is the data cipher `VMess` negotiates, and on `aarch64`
//! the `chacha20poly1305` crate runs it at 0.45 GB/s — because the `chacha20`
//! crate underneath it will not select its own NEON backend, so the keystream
//! half runs one dependent chain at a time. [`crate::aead`] pairs this with the
//! keystream core in [`crate::record`], which does the same twenty rounds at
//! 2.14 GB/s on the same machine.
//!
//! # The arithmetic
//!
//! The accumulator is `h mod (2^130 - 5)`, which is 130 bits and does not fit a
//! `u128`. It is held as five limbs of 26 bits instead, because `2^26` is chosen
//! so that one limb-pair product plus a carried-in value stays under `2^63`:
//! every intermediate is a `u64` and every product is a `u64 * u32`, so the
//! widest value in the loop is far from the point where a machine word wraps.
//!
//! The modulus is not a division. `x * r mod (2^130 - 5)` is computed as
//! `x * r` in 130 bits and then folded: the carry out of the top limb is
//! multiplied by 5 and added back at the bottom, because `2^130 = 5 (mod p)`.
//! That is the whole reduction — one multiply by five and one add per limb per
//! block, which is why the limb width is 26 and not 13: a wider limb means fewer
//! limbs means fewer folds.
//!
//! # What was tried and measured against this
//!
//! Two changes that a careful reader would suggest, both measured on an `M2`
//! and both *not* here, so that they do not get proposed again:
//!
//! * **Fusing the two halves of the `AEAD`** — xoring each chunk of keystream
//!   and absorbing that chunk's ciphertext in one loop, so the two dependency
//!   chains sit in the reorder window together. The chains are independent, so
//!   this ought to turn the sum of the two halves into the larger of them. It
//!   does not: it is 20% *slower* at 256-byte chunks and no different at 512.
//!   Each chunk is a real call into `record::fill_exact`, and the two halves do
//!   not co-issue across it.
//! * **Pairing the five products of each accumulator into a tree** instead of
//!   summing them left to right, to shorten the dependency chain of the
//!   multiply-adds. No measurable difference; the scheduler was already doing
//!   as well as the tree allows.
//!
//! What is left is the loop: twenty-five products, a fourteen-operation fold and
//! a fourteen-operation block decode, in fifty-seven instructions, with the
//! accumulator in registers across the whole message. Going below that means
//! `NEON`, and the twenty-five products are arranged so that four-wide lanes do
//! not fold into them the way they do for the `ChaCha20` core.
//!
//! # What is not claimed
//!
//! That this is faster than every other `Poly1305`. It is faster than the one
//! `VMess` was using, by the margin measured in [`crate::aead`]'s tests, and it
//! is bit-identical to it at every length and every offset — which is the only
//! claim that lets it be swapped in at all.

/// Twenty-six ones: the mask that keeps a limb inside `2^26`.
///
/// One constant for the whole file rather than one per use. The five clamp
/// masks in [`Poly1305::new`] are *not* this value — each clears three bits of a
/// different byte — and spelling those out is the point of that function.
const LIMB_MASK: u64 = 0x03ff_ffff;

/// [`LIMB_MASK`] again, at the width the accumulator is stored in.
const LIMB_MASK_U32: u32 = 0x03ff_ffff;

/// The bit that stands in for `2^128` on every block that is not the last.
///
/// Bit 24 of limb 4, which is bit 128 of the message. `2^128` is the one bit of
/// `h`'s range that does not fit in a limb, so a full block carries it here and
/// a final partial block does not: the `0x01` byte after the last real byte of
/// the message supplies it there instead.
const HIBIT: u32 = 1 << 24;

/// One accumulator plus the key it is keyed with.
///
/// `h` is the running value mod `p`; `r` and `pad` come from the key once and
/// are never touched again, because a data frame is one accumulator over one
/// key and rebuilding either per block would be per-block work for constants.
#[derive(Clone)]
pub struct Poly1305 {
    /// The clamped multiplier, five limbs.
    r: [u32; 5],
    /// The running accumulator, five limbs.
    h: [u32; 5],
    /// The low half of `key[16..32]`, added to the finished accumulator.
    pad: [u32; 4],
    /// Bytes of a block not yet consumed.
    buffer: [u8; 16],
    /// How much of `buffer` is live.
    held: usize,
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The accumulator only, not the key: printing `r` or `pad` would put a
        // one-time secret in a test failure message.
        f.debug_struct("Poly1305")
            .field("h", &self.h)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl Poly1305 {
    /// A fresh accumulator under `key`.
    ///
    /// The five masks are the clamp: `r` is reduced mod `2^124` and then three
    /// bits of each of its top bytes are cleared, which is what makes the
    /// "times 5" reduction above safe. They are spelled out per limb rather than
    /// applied to one 128-bit value because a 128-bit value would need a `u128`
    /// for a constant.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let w = |at: usize| u32::from_le_bytes([key[at], key[at + 1], key[at + 2], key[at + 3]]);
        Self {
            r: [
                w(0) & 0x03ff_ffff,
                (w(3) >> 2) & 0x03ff_ff03,
                (w(6) >> 4) & 0x03ff_c0ff,
                (w(9) >> 6) & 0x03f0_3fff,
                (w(12) >> 8) & 0x000f_ffff,
            ],
            h: [0; 5],
            pad: [w(16), w(20), w(24), w(28)],
            buffer: [0; 16],
            held: 0,
        }
    }

    /// Absorb `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        // A leftover block is completed rather than copied into the new data: the
        // two are one block, and building that block is four loads.
        if self.held > 0 {
            let take = data.len().min(16 - self.held);
            self.buffer[self.held..self.held + take].copy_from_slice(&data[..take]);
            self.held += take;
            data = &data[take..];
            if self.held < 16 {
                return;
            }
            let block = self.buffer;
            self.absorb(&block, HIBIT);
            self.held = 0;
        }
        let whole = data.len() / 16 * 16;
        self.absorb(&data[..whole], HIBIT);
        let rest = &data[whole..];
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.held = rest.len();
    }

    /// The sixteen-byte tag.
    #[must_use]
    pub fn finish(mut self) -> [u8; 16] {
        // A partial block gets a one byte after its last byte and zeros after
        // that — the 2^128 bit is *not* implicit here, because the padding byte
        // supplies it. Getting this backwards is the classic Poly1305 bug, and
        // the differential test covers every length that can reach it.
        if self.held > 0 {
            let n = self.held;
            self.buffer[n] = 1;
            for b in &mut self.buffer[n + 1..] {
                *b = 0;
            }
            let block = self.buffer;
            self.absorb(&block, 0);
        }

        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c;
        c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;

        // `h + 5`, then keep whichever of `h` and `h + 5` is the smaller: `h < p`
        // exactly when `h + 5` overflows 130 bits. Subtracting one makes the
        // mask all-ones in that case and all-zeroes otherwise, which selects in
        // five bitwise ands rather than a branch on a secret-dependent value.
        let mut g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h1 + c;
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h2 + c;
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h3 + c;
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4 = g4 & mask;
        let mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Five 26-bit limbs back to four 32-bit words, which is `h mod 2^128`.
        let f0 = (h0 | (h1 << 26)) as u64;
        let f1 = ((h1 >> 6) | (h2 << 20)) as u64;
        let f2 = ((h2 >> 12) | (h3 << 14)) as u64;
        let f3 = ((h3 >> 18) | (h4 << 8)) as u64;

        // `+ pad`, carried: each step absorbs the previous carry so the sum is
        // the full 128-bit add rather than four truncating ones.
        let mut carry = f0 + u64::from(self.pad[0]);
        let f0 = carry as u32;
        carry = f1 + u64::from(self.pad[1]) + (carry >> 32);
        let f1 = carry as u32;
        carry = f2 + u64::from(self.pad[2]) + (carry >> 32);
        let f2 = carry as u32;
        carry = f3 + u64::from(self.pad[3]) + (carry >> 32);
        let f3 = carry as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&f0.to_le_bytes());
        tag[4..8].copy_from_slice(&f1.to_le_bytes());
        tag[8..12].copy_from_slice(&f2.to_le_bytes());
        tag[12..16].copy_from_slice(&f3.to_le_bytes());
        tag
    }

    /// Every whole sixteen-byte block of `data`, times `r`, folded back mod `p`.
    ///
    /// The loop is here rather than in [`Poly1305::update`] on purpose. With the
    /// multiply in a helper called once per block, that call is per sixteen bytes
    /// and `r` has to be reloaded across it every time; measured on an M2 that is
    /// worth about a tenth of the whole `AEAD` throughput. Here the loop carries
    /// the registers, `r` is widened once for the whole message, and this
    /// function is called once per `update` — so the registers hoist without
    /// anything needing `#[inline(always)]`.
    fn absorb(&mut self, data: &[u8], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r;
        let (r0, r1, r2, r3, r4) = (
            u64::from(r0),
            u64::from(r1),
            u64::from(r2),
            u64::from(r3),
            u64::from(r4),
        );
        // `r` multiplied by five, for the terms that cross the top of the
        // 130-bit product. Per message, not per block.
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
        let hibit = u64::from(hibit);

        let mut rest = data;
        while let Some(m) = rest.first_chunk::<16>() {
            let w = |at: usize| u32::from_le_bytes([m[at], m[at + 1], m[at + 2], m[at + 3]]);

            let h0 = u64::from(self.h[0]) + (u64::from(w(0)) & LIMB_MASK);
            let h1 = u64::from(self.h[1]) + ((u64::from(w(3)) >> 2) & LIMB_MASK);
            let h2 = u64::from(self.h[2]) + ((u64::from(w(6)) >> 4) & LIMB_MASK);
            let h3 = u64::from(self.h[3]) + ((u64::from(w(9)) >> 6) & LIMB_MASK);
            let h4 = u64::from(self.h[4]) + (u64::from(w(12)) >> 8) + hibit;

            // Five accumulators at once, so the twenty-five products are
            // independent and a wide core issues them back to back instead of
            // stalling on limb 0.
            let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
            let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
            let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
            let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

            // The fold. Each carry out of limb `i` is a multiple of `2^26`, and
            // `2^130 = 5 (mod p)`, so the carry off the top limb goes back in at
            // the bottom times five — and then carries again, which is the one
            // extra round this has to make.
            let c = d0 >> 26;
            let o0 = d0 & LIMB_MASK;
            d1 += c;
            let c = d1 >> 26;
            let o1 = d1 & LIMB_MASK;
            d2 += c;
            let c = d2 >> 26;
            let o2 = d2 & LIMB_MASK;
            d3 += c;
            let c = d3 >> 26;
            let o3 = d3 & LIMB_MASK;
            d4 += c;
            let c = d4 >> 26;
            let o4 = d4 & LIMB_MASK;

            // Limb 1 is deliberately left unmasked: its carry out of bit 26 is
            // limb 2's bit 0, so the two are one value counted twice, and masking
            // it here discards `2^52` of accumulator silently — every limb still
            // looks like a limb. The multiply above tolerates a 27-bit limb 1 for
            // exactly this reason, and `finish` is where it gets normalised.
            //
            // Spelled through a named value rather than inline. `>>` binds looser
            // than `+` in Rust, so `o1 + x >> 26` is `(o1 + x) >> 26`: it shifts
            // the whole accumulator and leaves limb 1 holding two. That one
            // missing parenthesis is the difference between a tag and a random
            // one, and a sweep that only tried round lengths would not see it.
            let wrapped = o0 + c * 5;
            self.h = [
                (wrapped as u32) & LIMB_MASK_U32,
                (o1 + (wrapped >> 26)) as u32,
                o2 as u32,
                o3 as u32,
                o4 as u32,
            ];

            rest = &rest[16..];
        }
    }
}

/// The tag over `data` under `key`, in one call.
///
/// The one-shot form, because a data frame is exactly this: one accumulator over
/// one message. [`Poly1305`] exists for a caller that has the pieces already.
#[must_use]
pub fn tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut state = Poly1305::new(key);
    state.update(data);
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-block message: the shape where the implicit 2^128 bit is the only
    /// thing separating a right answer from a right-looking wrong one, and where
    /// a mask that is off by a bit shows up as a tag that is off by one.
    #[test]
    fn one_block_and_one_byte_agree_with_the_split_form() {
        let key = [0x42u8; 32];
        for len in 0..=48usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(29)).collect();
            let one_shot = tag(&key, &data);
            // Fed in awkward pieces, which is what the leftover path is for.
            let mut split = Poly1305::new(&key);
            for chunk in data.chunks(7) {
                split.update(chunk);
            }
            assert_eq!(one_shot, split.finish(), "length {len} fed in sevens");
        }
    }

    /// `h` must be a real accumulator: absorbing in one call and byte by byte
    /// cannot differ, or the leftover path is quietly dropping or doubling data.
    #[test]
    fn byte_at_a_time_matches_one_shot() {
        let key = [0x11u8; 32];
        for len in 0..=80usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(251).wrapping_add(3))
                .collect();
            let mut dribble = Poly1305::new(&key);
            for byte in &data {
                dribble.update(std::slice::from_ref(byte));
            }
            assert_eq!(tag(&key, &data), dribble.finish(), "length {len}");
        }
    }

    /// The clamp is the one part of this that cannot be checked against itself:
    /// every limb's mask is an independent constant, and a mask that is wrong by
    /// one bit still produces a perfectly self-consistent accumulator. So it is
    /// checked against the *unclamped* definition — `r mod 2^124` with the three
    /// high bits of bytes 3, 7, 11 and 15 cleared — which is the specification
    /// rather than this implementation of it.
    #[test]
    fn the_clamp_is_the_specification_and_not_this_implementation() {
        for seed in 0..=255u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(seed));
            let wide = u128::from_le_bytes(key[..16].try_into().expect("16 bytes"));
            let clamped = wide & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;

            let state = Poly1305::new(&key);
            let limbs = [
                u128::from(state.r[0]),
                u128::from(state.r[1]),
                u128::from(state.r[2]),
                u128::from(state.r[3]),
                u128::from(state.r[4]),
            ];
            // Pack the five 26-bit limbs back the way the mask unpacked them.
            let mut packed = 0u128;
            for (i, limb) in limbs.iter().enumerate() {
                packed |= limb << (26 * i);
            }
            assert_eq!(packed, clamped, "clamp for key seed {seed}");
        }
    }

    /// The accumulator, against the crate that ships it.
    ///
    /// The `aead` sweep above already decides the thing that matters — that the
    /// `AEAD` is byte-identical to the one `VMess` was using — but it can only
    /// do that through the `AEAD`'s own framing. This one removes the framing:
    /// the accumulator is compared directly, over every length that reaches the
    /// leftover path, at every split point that reaches the carry-into-the-next-
    /// block path, and against three `r` keys chosen to have limbs that are
    /// large, small and mixed.
    #[test]
    fn the_accumulator_is_the_crate_it_replaces() {
        use poly1305::universal_hash::KeyInit as _;

        fn theirs(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
            let k: &poly1305::Key = poly1305::Key::from_slice(&key[..]);
            poly1305::Poly1305::new(k).compute_unpadded(data).into()
        }

        let mut checked = 0usize;
        for seed in 0..3u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in (0..=48usize).chain([63, 64, 65, 127, 128, 129, 1024, 4097]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                let want = theirs(&key, &data);
                assert_eq!(tag(&key, &data), want, "seed {seed} length {len}");
                // Every split point, so the leftover block is finished the same
                // way whether it arrives one byte early or fifteen.
                for split in 0..=len {
                    let mut state = Poly1305::new(&key);
                    state.update(&data[..split]);
                    state.update(&data[split..]);
                    assert_eq!(
                        state.finish(),
                        want,
                        "seed {seed} length {len} split {split}"
                    );
                }
                checked += 1;
            }
        }
        assert!(checked > 150, "the sweep should be dense, not a sample");
    }
}
