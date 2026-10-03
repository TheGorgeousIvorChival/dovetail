# Unsafe policy: only when faster, only when proven harmless

`unsafe` in this workspace is a performance instrument with a proof obligation, not a coding style. It is allowed only on hot paths the benchmark gate covers, and only when the safe form is measured slower at some length. The second half of that rule is **not checked by anything** — no gate, script or test records the measurement it asks for, so it stands on review, not on CI ([`claims.md`](claims.md)). Every `unsafe` block carries a `SAFETY:` comment (enforced by `undocumented_unsafe_blocks`) stating the assumption the compiler cannot check, and every assumption is discharged by one of:

1. **Differential proof.** Byte-identical output vs the pinned reference at every length and every block offset, both sides of every rung and group boundary. A wrong `unsafe` fails here before any timing runs.
2. **Miri** on nightly for every path it can interpret (the portable record path). SIMD intrinsics cannot be interpreted; their contract lives in `chacha::Lanes` and is discharged by (1).
3. **Counting proof.** Allocation and zero-fill counts from the counting allocator: integer facts, identical on every machine, gated outright.

## What this has already bought

- **Fused feed-forward** (`chacha/mod.rs`): the `init` add happens inside the store loop instead of as a separate pass — one full pass over `regs` (16 vector stores + loads per 512 B group) removed, same bytes.
- **Group-major stores**: `block / CHUNKS` and `block % CHUNKS` per block replaced by loop structure (`s` *is* the group, `c` *is* the lane) — the division is gone, the stores are identical.
- **Hoisted AVX2 dispatch**: `is_x86_feature_detected!("avx2")` runs once per `xor_blocks` call, not once per 512-byte group — the CPUID-backed check is outside the loop, and the branch it guards is around the whole ladder.
- **Fused round passes** (`chacha/mod.rs`): one loop per half-round instead of four — 10 passes over `regs` per group instead of 40. States are independent, so per-state order (quarter-round, shuffle, quarter-round, shuffle) is unchanged and the bytes are identical.
- **Direct register build** (`chacha/mod.rs`): `xor_groups` constructs each register once via `from_fn` instead of building a zero array and overwriting every element — `NST * 4` dead vector constructions per group removed, safe Rust, same bytes.
- **Zero-alloc UUID** (`vless.rs`): `uuid_bytes` parses nibbles in place instead of collecting a 32-char `String` and running `from_str_radix` per byte — one heap allocation removed per header encode, same bytes on validated links.
- **Single-parse address family** (`vless.rs`): `':'` membership decides which `IpAddr` parse to attempt (IPv4 literals never contain it, IPv6 literals always do) — one failed parse fewer per `request_header_len`/`encode_into`, same wire bytes on every input including a mistaken `host:port`.

Each carries its proof: the differential sweep (528 shapes in tests, 3504 in the gate) is unchanged and green, because "same bytes, less work" is a fact or the build fails.

## What is still safe (and why it stays that way)

- `record::fill_exact` and the portable ChaCha core: no `unsafe` at all.
- one-block tail: bounds-checked indexing only on aarch64 (`portable`), `unsafe` SSE2 intrinsics on x86_64 (`chacha::sse2`) — the one place `unsafe` reaches past the SIMD modules, and it is there because LLVM compiles the portable core to scalar code on that target.
- PattNG's `unsafe-*` fingerprints and plaintext-to-public: *parsed* always, *enabled* only through `policy::UnsafeOptIn`. The constructors are the audit points, and `grep allow_plaintext_to_public` finds them — it does **not** find the paths: the plaintext decision is `transport::Security::NoneToPublic`, and the two are only connected by a test.

A new `unsafe` needs the same treatment: the measurement showing the safe form regressing, the `SAFETY:` comment naming the assumption, and the green differential. A PR with `unsafe` and without all three is closed.
