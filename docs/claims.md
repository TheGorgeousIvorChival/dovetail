# Claims and their checkers

Every claim this repository makes, the thing that checks it, and what that thing
last said. The rule this file exists to enforce: **a claim with no checker is not
removed, it is marked.** "Not yet proven" is a line in a status table and a useful
one, because it names the next slice.

Nothing here is checked by a run — the verdicts below are transcriptions of named
runs, read on 2026-10-03 at `main` = `94cd774`. A verdict goes stale the way a
benchmark does, and the file that goes stale first is this one. The runs it quotes:

| run | what it decided |
| --- | --- |
| `ci.yml` 37101366003 | eight jobs, all green (test matrix, lint, upstream pins on 3 runners, prompt check at 29 prompts) |
| `bench.yml` 37101083050 | gates 1, 2 and 3 green on all four runners; gate 1 at 3600 shapes, gate 2 at 300 lengths, gate 3 over 235 lengths from 65 B up |
| `conformance.yml` 37101365980 | one upstream suite ran green against a Dovetail binary (`zeronet` raw-`TCP` `VLESS`), six skipped |
| `compare.yml` 37101083068 | success |
| `safety.yml` | **no runs in this repository** — the quoted Miri PASS predates it, so no verdict is transcribed |
| `./scripts/check-upstream-pins.sh`, via `ci.yml` upstream jobs in run 37101366003 | 7 of 7 pins resolve on all three runners |

Verdict vocabulary, and nothing else:

| verdict | meaning |
| --- | --- |
| **green** | a named thing ran and passed |
| **red** | a named thing ran and failed; the claim is not established |
| **no checker** | nothing in this tree checks it |
| **vacuous** | a checker exists but cannot fail on this claim |
| **stale** | the checker, or the code, shows the sentence is no longer true |
| **read** | true by reading the pinned source or this tree; no run checks it |

## The README status table

| claim | checked by | verdict |
| --- | --- | --- |
| `cargo test --workspace` green on linux x86_64, macos aarch64, windows x86_64 | `ci.yml` `test (…)` jobs, run 37101366003 | green, all three |
| `clippy` clean under `pedantic`, `-D warnings` | `ci.yml` `lint and docs`, run 37101366003 | green |
| `record::fill_exact` bit-identical at 3600 shapes on all four runners | `bench.yml` gate 1, run 37101083050 (3600 = 300 lengths x 6 offsets x 2 key pairs) | green |
| `chacha::avx2`, `chacha::sse2` executed, gates 1 and 2 pass on both x86_64 runners | `bench.yml` gate 1 + gate 2 on `linux x86_64`, `windows x86_64`, run 37101083050 | green |
| not slower at any **measured** length from 65 B up | `bench.yml` gate 3, run 37101083050: 235 timed lengths, green on all four runners — worst 1.03x at 320 B on `linux x86_64`, 1.03x at 114 B on `macos aarch64`, 1.02x at 127 B on `linux aarch64`, 1.01x at 256 B on `windows x86_64`, none below the 0.95x bar | green at the bar the gate actually sets, which is 5% below the claim's wording |
| lengths 1-64 B, "a tie by construction and identity-checked only" | gate 1 checks those 64 lengths byte for byte; **gate 3 does not time them** (`TIMING_MIN = 65`) | green for the identity half; the timing half is **not measured anywhere**, by decision, and P17 is the decision's record |
| TLS backend `rustls` "implemented and compiled in `ci.yml`; handshake unproven" | `ci.yml` builds it on three operating systems; `crates/dovetail-core/src/tls/` contains **zero `#[test]`** | green for "compiles"; **no checker** for any handshake property |
| seven sources pinned; every one resolves | `./scripts/check-upstream-pins.sh`, via `ci.yml` `upstream comparison is current` on all three runners, run 37101366003 | green, 7 of 7 |
| seven `upstream/` checkouts at exact revs | nothing — they are `.gitignore`d and re-derived by `fetch-upstream.sh`; presence was verified by hand (`git rev-parse HEAD` equals the pin, empty `git status --porcelain`, all seven) | **no checker**, and the row says so |
| four pins' `path` fields name a directory absent at their rev | P3's fetch, by hand: `xray-core` `crypto/chacha20` → `common/crypto/chacha20.go`; `amneziawg-go` `device/noise` → `device/`; `amnezia-client` `src/crypto` → `common/crypto`; `sing-box` `common/crypto` absent and no `chacha20poly1305` string anywhere in the tree (the cipher is the out-of-tree module `sagernet/sing-shadowsocks2`) | **red**, and left red on purpose — P21 records the repair, this slice does not repin |
| Miri nightly PASS 2026-10-03 | nothing in this repository: `safety.yml` has no completed runs here | **no verdict** — the quoted PASS predates this repo, and the current tree (with `chacha::sse2`) has no Miri verdict yet |
| first green CI run, all six jobs, run 37077244861 | that run, predating this repository; the comparable run here is `ci.yml` 37098689265, six jobs green | green there, **stale** here — the README row quotes a run this repo never produced |

## The README's claim table

| claim | checked by | verdict |
| --- | --- | --- |
| byte-identical output, every length, every device | `bench.yml` gate 1 before any timing, run 37101083050 at 3600 shapes; `core::tests::every_rung_matches_the_reference` at 528 shapes | green |
| not slower at any measured length from 65 B up | `bench.yml` gate 3 over 235 lengths ≥ 65 B, run 37101083050 | **the gate tolerates 5%**: `BAR = 0.95`, so a length at 0.96x passes while this row says "not slower". Two narrowing decisions are now stacked — the band below 65 B is untimed (P17) and the bar is a 5% tolerance — and the claim names neither. |
| no use-after-free, no leak | Miri for the safe-Rust paths, run by `safety.yml`; the differential test for the SIMD paths | **no run here** — `safety.yml` has no completed runs in this repository, so neither the safe paths nor the SIMD gap have a current verdict; a differential test proves the bytes, not the absence of UB |
| no work generated and discarded | `bench.yml` gate 2 at 300 lengths, run 37101083050, over the ladder's own count at every length and 6 block offsets; plus `record::tests::the_ladder_reports_the_blocks_the_caller_asked_for` and `…the_block_count_check_fails_when_the_count_is_wrong` | green, and it can fail: `xor_groups` returns the blocks it generated |
| no heap allocation, no zero-fill | `dovetail-bench`'s counting allocator, gate 2, run 37101083050 | green, and it can fail: it counts `alloc`/`dealloc` and `write_zeroed` deltas |

## The rest of the README

| claim | checked by | verdict |
| --- | --- | --- |
| "One algorithm, three widths", backend table listing three | `chacha/mod.rs`: four `Lanes` impls | **stale**, corrected |
| Miri interprets the ladder, the counter arithmetic, every store offset | `safety.yml` on `x86_64`, where `is_x86_feature_detected!("avx2")` is false under Miri and the portable path is taken | green for `portable`; the one-block tail on that runner is now `sse2`, which a local Miri probe interprets but **no CI run has yet** |
| `chacha20` 0.9.1 selects NEON only behind a cfg nothing sets | `crates/dovetail-core/src/core.rs::backend()`; the pinned crate's `backends.rs`, read | read |
| every report prints both backends | `dovetail-bench`'s `build_report`, in every report | green, by construction |
| `TlsProvider` is `Read + Write` | the trait bound in `tls/mod.rs` | green, by construction |
| no feature selects a TLS stack; no build without TLS | no feature in `crates/dovetail-core/Cargo.toml`; `rustls` is a hard dependency | green, by construction |
| "TLS interface + 2 backends" (Layout) | one `impl TlsProvider`: `RustlsProvider` | **stale**, corrected |
| "the released dovetail-core" (Layout) | every crate is `publish = false` | **stale**, corrected |
| `.github/scripts/` per-OS provisioning (Layout) | the directory does not exist | **stale**, corrected |
| `upstream/<name>/` checkouts are never committed | `.gitignore`: `upstream/*`, `!upstream/pins.toml` | green |
| "Quiche is the default QUIC" | nothing: `quiche` is in no manifest | **no checker** — a decision rule for a rung that does not exist |
| every way PattNG can connect parses | `vless::tests::unknown_transports_parse_but_stay_planned`, plus `support()` for the rows the format can express | green for the rows a link can name; the 10-row matrix exists only in a benchmark report |
| one method dials at a time | `vless::support()` and `dovetail-zeronet run`'s TCP reachability | green |
| upstream suites run against Dovetail binaries | `conformance.yml` via `run-upstream-suite.sh`: 1 of 7 ran green (`zeronet` raw-`TCP` `VLESS`, `trojan` and `shadowsocks` vs `dovetail-zeronet` at `97a99734`), 6 skipped | green for the subset — the other six oracle tests need rungs the binary lacks; the script still refuses a `PASS` naming a binary it did not execute |
| `dovetail-zeronet check` parses offline, `run` dials TCP and sends nothing | the two verbs in `crates/dovetail-zeronet/src/main.rs` | green, by reading; the newer `version`, `x25519` and `run -c` verbs are covered by `proxy::tests` and `json::tests` in the `ci.yml` test matrix |
| every slice in `prompts.md` carries status, leverage, effort, gates, dependencies | `dovetail-prompt check`, run by `ci.yml` `the prompt library is well formed`, run 37101366003 | green, 0 errors, 29 prompts |

## `docs/methodology.md`

| claim | checked by | verdict |
| --- | --- | --- |
| the report is written before the gate is asserted | `dovetail-bench/src/main.rs`; `bench.yml`'s `publish the table` runs `if: always()` | green |
| best of five interleaved rounds per side | `measure_len`, `ROUNDS = 5` | green, by reading |
| a length under the bar is re-measured at 4x the budget | `measure_len`'s re-measure branch | green, by reading |
| gate 2 covers the record layer at every length and the rung-1 header encode across three address families | `gate_deterministic`, over `192.0.2.53`, `2001:db8::1`, `example.com` | green for the counts |
| `check-leak-surface.sh` is the static half: no DNS, no leak primitives, no printing, no wall clock | the script's four `git grep`s, run by `ci.yml` `lint and docs` | green |
| `check-upstream-pins.sh` fails on an unresolvable pin, a missing `rev`, or an unparseable file; each `rev` by depth-1 fetch, not `ls-remote` | the script; 7 of 7 resolve on all three `ci.yml` runners, run 37101366003 | green |
| `update-pins.sh` prints the diff and opens a PR rather than pushing | the script's `gh pr create` | green, imprecise: it does `git push` the branch it opens the PR from |
| every benchmark report ends with the per-method matrix | `methods::table()` appended in `build_report` | green |
| a SIMD backend is measured on one native runner per ISA | `bench.yml`'s four-runner matrix | green |

## `docs/unsafe-policy.md`

| claim | checked by | verdict |
| --- | --- | --- |
| every `unsafe` block carries a `SAFETY:` comment, enforced by `undocumented_unsafe_blocks` | `[workspace.lints.clippy]`, run by `ci.yml` `lint and docs` | green |
| `unsafe` is allowed only where the safe form was **measured** slower | nothing: no gate, script or test records that measurement | **no checker** |
| the seven wins listed under "what this has already bought" | six of the seven are safe-Rust changes; the file lists them under an unsafe policy, and the `unsafe`-surface claim does not follow from them | **no checker** on the framing; each code change is visible in the tree |
| the differential sweep is 528 shapes in tests and 3600 in the gate, unchanged and green | `core::tests` (44 lengths x 6 offsets x 2 pairs) and `bench.yml` gate 1 | green |
| the AVX2 probe leaves the hot loop, which "splits into two branch-free loops" | `xor_blocks` now branches once around the whole ladder | **stale**, corrected |
| "`xor_block` tail: bounds-checked indexing only" | on `x86_64` the one-block tail is `chacha::sse2`, which is `unsafe` intrinsics | **stale**, corrected |
| `grep allow_plaintext_to_public` finds every plaintext path | the grep hits `policy.rs` (the constructor) and `dovetail-bench/src/methods.rs` (a report cell). The plaintext decision lives in `transport::Security::NoneToPublic` and does not mention the opt-in | **red**, corrected |
| no `unsafe` in `record::fill_exact` or `chacha::portable` | one `unsafe` in `chacha/mod.rs` (the AVX2 call), none in either of the two named files | green |

## `docs/arch/overview.md`

| claim | checked by | verdict |
| --- | --- | --- |
| the claim-to-gate map in the diagram, including "no discarded work — `fill_exact`'s own return value" | `bench.yml` gate 2 | **vacuous**, as above |
| `chacha::xor_blocks` is "vector groups, then a scalar tail" | `xor_tail` runs the widest exact width; the single block is scalar only off `x86_64` | **stale**, corrected |
| one generic function instantiated for three backends | four | **stale**, corrected |
| keystream is "XORed in place, never staged" | a partial block's last sub-chunk is materialised in a 16-byte stack scratch and XORed from, in both `xor_groups` and `portable::xor_block` | **stale** — corrected to name the exception |
| the counter advances only by blocks produced | the ladder advances it by what each pass produced; gate 2 cannot confirm it | green by reading, **vacuous** as a gate |
| 528 shapes in tests, 3600 in the gate | as above, run 37101083050 | green |
| the reference is scalar on aarch64, AVX2 on x86_64 with AVX2, SSE2 without | `core::backend()` and the pinned crate's `backends.rs` | read |
| `bench.yml` runs weekly and fails on any single regressing length | `bench.yml`'s cron and gate 3 | green |

## `docs/arch/superset.md`

| claim | checked by | verdict |
| --- | --- | --- |
| every row parses, exactly one dials | `vless::support()`, generated into the report's per-method table; rows 5, 6, 9, 10 are static text in `methods.rs`, not read from the parser | green for the rows a link can express; **no checker** for the static rows |
| `VlessLink::parse` never fails on an unknown transport | `vless::tests::unknown_transports_parse_but_stay_planned` | green |
| the row statuses in the table | rows 1-4, 7, 8 come from `live_support()`; rows 5, 6, 9, 10 are written by hand | partly checked |
| `compare.yml` prints an offline table, and live columns with a secret | the workflow's `vless_link` and `live` inputs; `compare.yml` ran green in 37101083068 | green |
| `UnsafeOptIn` gates plaintext-to-public and unsafe fingerprints | `policy::UnsafeOptIn`; `vless::tests::pattng_plaintext_to_public_needs_opt_in`, `…unsafe_fingerprint_needs_opt_in` | green |

## `docs/conformance.md`

| claim | checked by | verdict |
| --- | --- | --- |
| "running upstream suites **against Dovetail binaries** in CI" | `zeronet` points its suite at `dovetail-zeronet` via `ZRAY_XRAY_BINARY`; six entries are `test_enabled = false` and skip | green for the 2-test subset — the doc says 1 of 7 suites and names the seven excluded oracle tests with what each got instead of a listener |
| `test_enabled = true` means the suite runs on every push | `conformance.yml` → `run-upstream-suite.sh`, run 37101365980: `RUNNING: zeronet …`, then `PASS: zeronet suite green against dovetail-zeronet` | green, and the log line names the binary and the pin |
| `test_enabled = false` means the job is created, skips, and prints the reason | the same log: six `SKIPPED:` lines, each naming the pin | green |
| a suite flips to `true` only when the benchmark gate is green on all four ISA runners | `zeronet` is `true` as the P19 differential subset without a benchmark gate behind it | **exception, named** — P19's own gate authorizes the flip and the pin note says so; the general rule still holds for every other entry |
| the seven revs and enabled bits in the current-state table | `upstream/pins.toml` | green: six `false`, one `true`, all match |

## `docs/function/chacha-xor-blocks.md`

| claim | checked by | verdict |
| --- | --- | --- |
| one `quarter_round`, one `rounds`, generic over `Lanes`; three backends | four `Lanes` impls | **stale**, corrected |
| the group is `GROUP_STATES = 4`, i.e. 8 blocks on AVX2 and 4 on NEON and portable | `chacha/mod.rs` | green |
| the tail's single block goes to the scalar core | true off `x86_64`; on `x86_64` it is `chacha::sse2` | **stale**, corrected |
| Miri covers `portable` in full and `sse2` in full | `safety.yml`'s last completed run predates `chacha::sse2` | green for `portable`; **no CI run yet** for `sse2` |
| `rot_chunks` is `vpshufd` on AVX2 and `vextq_u32` on NEON | also `pshufd` in `sse2.rs` | **stale**, corrected |
| the `vpshufd` immediates are literals proved by `rot_imm` and a `const` assertion | `avx2.rs` | green |
| the differential test catches a lane mix-up at 3600 shapes, run 37101083050 | `bench.yml` gate 1 | green |
| the one-block band is a tie, with the numbers | see the paragraph; the measurement was taken on one contributor's aarch64 machine and no named runner reproduces it | read, and the one claim in this file no CI run checks |

## `docs/function/record-fill-exact.md`

| claim | checked by | verdict |
| --- | --- | --- |
| generating "exactly as many blocks as the buffer needs" | `bench.yml` gate 2 | **vacuous**, as above |
| the counter-advance test calls the core, unlike the version before it | `record::tests::the_counter_advances_only_by_blocks_produced`, 20 lengths | green, and the doc's own sentence about the old test still applies to the return value |
| 2 key pairs x 6 block offsets x **46** lengths | 44 lengths: 528 shapes | **stale**, corrected |
| `blocks_for` compared at 20 lengths | `record::tests` | green |
| no `unsafe` in this function or in `chacha::portable` | true of both | green |
| every store is derived by `chunks_exact_mut` | `as_chunks_mut`, since the partial-block path | **stale**, corrected |
| the counter is checked before any work, and the buffer is untouched when it panics | `record::tests::refuses_a_wrapping_counter` | green |
| Xray-core and sing-box take a four-block refill from an AEAD interface that cannot stream | the `upstream/` checkouts, which are `.gitignore`d and checked by nothing | **no checker** |
| the reference's AVX2 backend computes four blocks per call and uses one when asked for one | read in the pinned `chacha20-0.9.1` source under `~/.cargo/registry`; `chacha20` is a real dependency, so that source is the one that ran | read |
| the reference table by target | `core::backend()` prints the backend that ran, in every report | green |

## `docs/function/tls-provider.md`

| claim | checked by | verdict |
| --- | --- | --- |
| one interface, one backend: `rustls` | one `impl TlsProvider` | green |
| the provider is `Read + Write` | the trait bound | green |
| `suites()` reads `rustls::crypto::ring::ALL_CIPHER_SUITES` at run time | `tls/rustls_backend.rs:107` | green |
| `rustls::Error` needs a trailing `_` arm, so a new variant lands in `Other` | `tls/rustls_backend.rs:201` | green |
| "every variant rustls 0.23 defines is listed explicitly … which is why **this table** lives in a document" | there is no table of variants in this document, and nothing checks the mapping is complete | **no checker**; corrected to say what is actually true |
| "`rustls` compiles here / tested here" | compiles: `ci.yml` test matrix. Tested: **nothing** — there is no `#[test]` in `tls/` | compiles green; "tested" **red**, corrected |

## `docs/function/prompt-next-slice.md`

| claim | checked by | verdict |
| --- | --- | --- |
| every property in its verification table | every test name it names exists in `crates/dovetail-prompt`, and `cargo test --workspace` runs them in `ci.yml` | green, all eight names resolve |
| the library is coherent | `dovetail-prompt check` in `ci.yml`, and `contract::the_live_library_passes_its_own_gate` | green |
| the provenance tag is FNV-1a and is not a checksum | the tag is reported by `--json`; nothing verifies the algorithm | **no checker** for the algorithm, green for its being reported |
| the header and footer are off by default | `render::Options::provenance`, covered by the contract tests | green |
| exit codes 0/1/2 mean what the table says | the binary's own `std::process::exit`; nothing asserts the mapping | **no checker** |
| `.dovetail/slices.log` is not in version control | `.gitignore`; `advisor::tests::a_corrupt_ledger_line_is_counted_not_obeyed` | green |

## What this audit found, and where it went

| finding | recorded as |
| --- | --- |
| gate 2 could not fail on "no work generated and discarded", because `fill_exact` returned the formula | P18, **done**: the count is the ladder's, and a test feeds the comparison a count one block high and one block low and requires it to reject both |
| no upstream suite runs against a Dovetail binary, and `docs/conformance.md` no longer says one does | `docs/conformance.md` states 0 of 7 with the per-pin seam table | **green** — the doc and the mechanism now agree |
| `xray-core` is `test_enabled = true` while the benchmark gate is red on two of four runners, which the doc's own flip rule forbids | `upstream/pins.toml`, `test_enabled = false` | **green** — the entry was disabled; it ran upstream code only |
| the one-block timing band was a tie no bar could certify | P17, now **done**: `TIMING_MIN = 65`, so gate 3 times 227 lengths from 65 B up and gate 1 keeps the 64 short ones byte-for-byte. The consequence to keep in view: no runner now produces a number for 1-64 B, on any architecture. |
| Miri has not run on a tree that contains `chacha::sse2` | the status table names the run and its commit |
| `docs/function/tls-provider.md` claimed handshake tests that do not exist | corrected there; P6 carries the work |
| eight oracle tests fail against `dovetail-zeronet`, by name with expected vs produced | `conformance.yml` run 37100395876 (red): 1 passed, 8 failed | recorded in `docs/conformance.md` — five expect unimplemented protocol listeners, two expect `ws`/`httpupgrade` handshakes, one times out on `grpc`; P24–P28 carry each rung |
| the five seamed-out pins have no socket-taking harness either | read at each pin: no `os/exec`, no tests, or `.so` constants | recorded in `docs/conformance.md`, per pin |
| every quoted run predates the repository it audits | this re-audit on `main` = `94cd774` | re-based above on runs 37101366003, 37101083050, 37101365980 and 37101083068; `safety.yml` has no runs here, so the Miri rows carry no verdict |