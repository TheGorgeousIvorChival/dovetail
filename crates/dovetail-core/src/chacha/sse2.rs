//! The SSE2 backend: four 128-bit words per register, one state in flight.
//!
//! `SSE2` is part of the `x86_64` baseline — it is not an optional extension — so
//! there is no runtime check here and none is needed, the same argument NEON gets
//! on aarch64.
//!
//! It exists for the *last* block of a tail and nothing else. AVX2 puts two states
//! in one register, so its smallest exact unit is two blocks, and a buffer with an
//! odd number of blocks always has one left over. The only other core for that one
//! block was `portable`, and on `x86_64` LLVM compiles `portable` to scalar `movl`/
//! `roll` rather than to SSE2: the AVX2 runners measured a five-block buffer at
//! 0.86x with it, against 1.9x for the four-block pass in the same call.

use super::Lanes;
// Glob-imported on purpose: the module is a flat list of intrinsics, and
// naming twenty of them by hand to satisfy a lint would be noise that hides
// the ones that matter. Every one used here is a single documented
// instruction; `Lanes` is what a reviewer checks, not this list.
#[allow(clippy::wildcard_imports)]
use core::arch::x86_64::*;

/// An SSE2 vector of four 32-bit words.
#[derive(Clone, Copy)]
pub(crate) struct S4(pub(crate) __m128i);

impl core::fmt::Debug for S4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut v = [0u32; 4];
        // SAFETY: 16 bytes written into a `[u32; 4]`, which is the exact width.
        unsafe { _mm_storeu_si128(v.as_mut_ptr().cast(), self.0) };
        f.debug_tuple("S4").field(&v).finish()
    }
}

impl Lanes for S4 {
    const LANES: usize = 4;

    #[inline]
    fn from_lanes(words: &[u32]) -> Self {
        // SAFETY: `words` is `LANES` long at every call site, which the generic
        // core builds; `_mm_loadu_si128` reads exactly 16 bytes and is unaligned,
        // so no alignment is assumed.
        Self(unsafe { _mm_loadu_si128(words.as_ptr().cast()) })
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        // SAFETY: as above.
        Self(unsafe { _mm_add_epi32(self.0, o.0) })
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        // SAFETY: as above.
        Self(unsafe { _mm_xor_si128(self.0, o.0) })
    }

    #[inline]
    fn rotl16(self) -> Self {
        // A shift pair, not `pshufd`: a 16-bit rotate moves bits *within* each
        // 32-bit word, and `pshufd` permutes whole words — which is what
        // `rot_chunks` does, one instruction away from looking like the same
        // thing. `pshufb` would be one instruction, and it is SSSE3, which is not
        // in the x86_64 baseline.
        //
        // SAFETY: as above; both shift amounts are in range for the intrinsic.
        Self(unsafe { _mm_or_si128(_mm_slli_epi32::<16>(self.0), _mm_srli_epi32::<16>(self.0)) })
    }

    #[inline]
    fn rotl12(self) -> Self {
        // SAFETY: as above; both shift amounts are below 32 and in range.
        Self(unsafe { _mm_or_si128(_mm_slli_epi32::<12>(self.0), _mm_srli_epi32::<20>(self.0)) })
    }

    #[inline]
    fn rotl8(self) -> Self {
        // SAFETY: as above.
        Self(unsafe { _mm_or_si128(_mm_slli_epi32::<8>(self.0), _mm_srli_epi32::<24>(self.0)) })
    }

    #[inline]
    fn rotl7(self) -> Self {
        // SAFETY: as above.
        Self(unsafe { _mm_or_si128(_mm_slli_epi32::<7>(self.0), _mm_srli_epi32::<25>(self.0)) })
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        // `pshufd` takes a compile-time immediate, so the three rotations the round
        // function uses are spelled out; each is constant at every call site, so
        // the match folds away and this is three shuffles with no branch.
        //
        // SAFETY: as above.
        let v = unsafe {
            match n {
                1 => _mm_shuffle_epi32::<0b00_11_10_01>(self.0),
                2 => _mm_shuffle_epi32::<0b01_00_11_10>(self.0),
                _ => _mm_shuffle_epi32::<0b10_01_00_11>(self.0),
            }
        };
        Self(v)
    }

    #[inline]
    fn xor_chunk(self, _c: usize, dst: &mut [u8; 16]) {
        // SAFETY: `dst` is a 16-byte array, so it is 16-byte aligned and exactly
        // the width of an SSE2 load and store. The load and the store cover the
        // same 16 bytes of the caller's buffer, and the caller derived `dst` from
        // an `as_chunks_mut` of that buffer, so it is live and owned here.
        unsafe {
            let cur = _mm_loadu_si128(dst.as_ptr().cast());
            _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm_xor_si128(cur, self.0));
        }
    }
}

/// One block, and the one block it generated; `out` may be shorter than 64 bytes.
///
/// Not `unsafe`: `SSE2` is baseline on `x86_64`, the same argument [`super::neon`]
/// makes for NEON on aarch64.
#[inline]
pub(crate) fn xor_block(key: &[u8; 32], nonce: &[u8; 12], start: u32, out: &mut [u8]) -> u32 {
    super::xor_groups::<S4, 1>(key, nonce, start, out)
}
