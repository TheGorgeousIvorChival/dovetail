# Dovetail prompt library — single source of truth

`dovetail-prompt` reads this file and nothing else. No prompt prose lives in Rust, and a prompt is added by adding a section here: no code change, no recompile. If the tool and this file disagree, this file is right and the tool is broken — which is why `dovetail-prompt check` is a CI step.

## How to read this file

One prompt per `## P<n> · <title>` section. The numbers are the roadmap: `P2` unblocks more of it than `P14` does, and the tool says so rather than leaving it to be worked out by reading every heading.

Every prompt carries these lines, and `check` fails if one is missing, because a prompt nobody can tell when to use, or cannot tell when it is finished, is a prompt that will be started and abandoned:

| line | required | meaning |
| --- | --- | --- |
| `**When to use:**` | yes | the situation that calls for this slice; if you cannot describe it, the slice is not ready to be listed |
| `**Status:**` | yes | `todo`, `doing`, `done` or `blocked` — the only field a contributor edits to record progress |
| `**Leverage:**` | yes | 1-5, how much this moves the rest of the roadmap; the advisor ranks on it |
| `**Effort:**` | yes | `small`, `medium` or `large`; ties are broken towards the smaller one, because a finished small slice unblocks more than a started large one |
| `**Gates:**` | yes | semicolon-separated checks this slice must pass, printed verbatim; wrap a command in backticks so it reads as a command |
| `**Depends on:**` | no | other prompt ids, comma-separated; a prompt is ready only when every one of them is `done` |
| `**Touches:**` | no | comma-separated paths this slice edits, `+` prefixed for one it creates; `check` verifies the first kind exists and the second does not |
| `**Random weight:**` | no | 0-9, for `--rotate`; 0 excludes it from draws, absent means 1 |
| `**Prompt protocol:**` | no | a rule that applies to this slice alone, layered under the shared protocol |

Paths under `upstream/<name>/` are pinned reading copies for agents (see P3): `xray-core`, `sing-box`, `amneziawg-go`, `amnezia-client`, `xray-rust`, `pattng`, `zeronet`, `mqvpn`, `aether`, `zeptun`, `slipstream`, `quiche`. They never appear in `**Touches:**` — checkouts are derived artifacts, and a touch naming one fails the gate wherever it was never fetched.

Placeholders are `{name}` or `{name=default}`. A name with a default is filled by it. A name without one is a decision this tool refuses to invent: `next` prints the exact command to run and exits 2 rather than sending an agent a prompt with a hole in it, and `--allow-unfilled` renders the hole loudly at the top of the prompt instead of silently.

The body is the single fenced block in the section. A second fenced block is an error rather than a fallback, because "first block" and "last block" are both guesswork that quietly renders the wrong text; add-ons are the extension mechanism and they are single lines:

```
**Add-on — <name>:** <one line of extra instruction>
```

## Shared protocol

```text
You are working on Dovetail, a from-scratch proxy core that claims two things and checks both: its output is byte-identical to the upstream implementation it replaces, and it is not slower than that implementation at any single measured length.

A claim in this repository is either checked by something that runs or it is not made. Never write a claim without naming the thing that checks it, and if there is no such thing, say so in the same sentence.

Nothing is ever compiled on a contributor's machine. Every build, test, benchmark and comparison happens in CI on a runner whose architecture is stated in the job, because a number produced locally describes the machine that produced it and is evidence about no other. Author locally, push, read CI.

Report tersely what happened and what did not work — verdicts, never a history of the diff. A slice that fails is worth more to the next contributor than a slice reported as done that quietly did half of its gates.

Report shape, every time: what changed, what was measured with numbers, what is still open.

Do not widen the scope of the change beyond the slice. If the slice exposes a larger problem, record it as a new prompt section in prompts.md rather than fixing it here, so the roadmap stays the honest description of what is left.

Every gate listed under Acceptance must be green before the slice is reported as done. If a gate cannot be run, say which one and why, and do not describe the slice as complete.

Rewrite, do not copy. No upstream line or test enters this tree: learn how each of the four implementations does it, find where it copies, branches, or refills needlessly, and write the smaller thing that is bit-identical and cheaper. Carry the minimal subset that covers the matrix — a superset of connection ways, a subset of code.

Faster, safer, leaner, or it does not land. Fewer operations, zero surviving copies: factor the math, fuse the passes, hoist the dispatch, narrow the parse. Even parsing and checking must be proven faster — benchmark them like everything else. Think in eliminated work, not added code.

Fixes leave no trace. One line of comment per function or item at most; no TODO, FIXME, or block comments (`scripts/check-comments.sh` fails them); no changelogs in chat.

Simpler with less code wins every tie at equal performance: the explainable form ships, the clever one must prove it is faster to survive. No debt lands to be cleaned later — no second way of doing something, no abstraction for one implementation, no copy left for the next slice.

Unsafe only for a measured win, safe Rust whenever it ties: if the safe form is as fast, the safe form ships, and every `unsafe` block still carries its proof obligation in one line.

A finished rung runs all four projects' related suites against it — Xray-core, sing-box, xray-rust, ZeroNet — unmodified, from the pins. Green here plus red there is not done.

Local checkouts under `upstream/` are for reading. They prove nothing about speed: a number produced off a named CI runner is not evidence about any runner.
```

## P1 · Resolve the workspace and assert the counter regression

**When to use:** Never again — kept as the roadmap's fixed point, because the regression it names is the one that was invisible for exactly as long as nothing compiled.
**Status:** done
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test --workspace --all-features`; CI: `ci.yml` test matrix on all three operating systems
**Touches:** crates/dovetail-core/src/record.rs, crates/dovetail-core/src/lib.rs
**Random weight:** 0

```text
Read the counter regression in `dovetail_core::record::fill_exact`: the counter advanced by the block offset and forgot the group offset, so every group after the first replayed the first group's keystream and every length of 1024 bytes or more was wrong.

The slice is done. Do not reopen it. It is listed because the roadmap's first real entry has to be something that is finished, and because the assertion it added — counter 0 and counter 8 must not produce the same keystream — is the reason the next slices can trust a differential sweep.
```

## P2 · Get CI green on main

**When to use:** Before anything else in this file. Every other claim in the repository — bit-identity, not-slower, no discarded work — rests on CI having run, and most of the rest of this file is blocked on it. `dovetail-prompt list` prints the waiting list; this is the slice at the top of it.
**Status:** done
**Leverage:** 5
**Effort:** small
**Gates:** CI: `ci.yml` green on all jobs; `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`
**Depends on:** P1
**Touches:** .github/workflows/ci.yml, .github/workflows/bench.yml, Cargo.toml
**Random weight:** 5

```text
Find why `ci.yml` is not green and make it green.

The README says the workspace resolves and is "awaiting first green CI run". Start from the actual log rather than from that sentence: read every job, classify each failure as a real bug in `dovetail-core` or `dovetail-bench`, a CI configuration mistake, or an upstream that moved, and fix them in that order.

A red job that has been red for a long time is usually red for a reason nobody wrote down. When you find it, add the reason to the workflow as a comment, because the next person will not have the log you have.

Do not weaken a gate to get to green. If a gate fails, the gate is the correct output and the code is wrong; if you are certain the gate itself is wrong, say which claim it was protecting and why that claim no longer needs it, in the commit message and in the README's status table.
```

**Add-on — local-first:** Author on a local machine if you like, but prove nothing there. The evidence is a green run on a runner whose architecture is named in the job.

**Add-on — ci-observation:** If a job is flaky rather than failing, fix the flakiness. A gate that cries wolf gets switched off, and a gate that is switched off protects nothing.

## P3 · Fetch the pinned upstream sources into upstream/

**When to use:** When the next slice needs to read the implementations it claims to match, which is any comparison, any conformance work, and any SIMD rung.
**Status:** done
**Leverage:** 4
**Effort:** small
**Gates:** `./scripts/check-upstream-pins.sh`; CI: `ci.yml` upstream job
**Depends on:** P2
**Touches:** upstream/pins.toml, scripts/check-upstream-pins.sh, scripts/update-pins.sh, scripts/fetch-upstream.sh
**Random weight:** 2

```text
`upstream/pins.toml` declares five pinned sources and `upstream/` holds no sources yet, so every statement in the README about what upstream does is currently taken on trust from the pin's `note` field.

Fetch each pinned commit into `upstream/<name>/` at the recorded revision, verify the checked-out tree is at that revision, and record in the README's status table which sources are present.

Pinned, not tracked, is deliberate: a comparison against "latest" is not a comparison. So the fetch must be reproducible from the pin alone — a script that resolves `repo` plus `rev` and writes a manifest of what it got, so that a reviewer can re-derive it without trusting your machine.

Do not vendor upstream test suites into this repository. sing-box is GPL-3.0 and Xray-core is MPL-2.0, so a copied test would make this work's licence undecidable. Reading their code to compare against it is fine; running their suites unmodified from their own checkout is the mechanism this project intends.
```

**Add-on — pin-discipline:** If a pin no longer resolves, do not repin quietly. `scripts/update-pins.sh` opens a PR for exactly this reason, and a force-push upstream is a finding, not an obstacle.

**Add-on — upstream-fetch:** Run `scripts/fetch-upstream.sh`; it clones each pin into `upstream/<name>/` and writes `upstream/manifest.toml` — the only reproducible path from pin to tree.

**Add-on — upstream-zeronet:** ZeroNet fetches from the fork first and falls back to the official repo (see `fallback_repo` in `pins.toml`); use `upstream/zeronet/` for the exact bytes, never a machine-local path.

## P4 · Prove the identity sweep is exhaustive rather than dense

**When to use:** When the differential test is described as covering every length, or when a SIMD rung is proposed — because a dense sweep that stops short of a boundary is what let a correct-looking core replay keystream forever.
**Status:** done
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test -p dovetail-core --all-features`; `cargo run --release -p dovetail-bench`; CI: `bench.yml` gate 1 on every runner in the matrix
**Depends on:** P1
**Touches:** crates/dovetail-core/src/record.rs, crates/dovetail-bench/src/main.rs
**Random weight:** 4

```text
The length list in `dovetail-bench` is dense over 0-256 and then carries one length either side of each boundary. Decide whether that is exhaustive, and make the file say which it is.

For each rung boundary — the block counts where `fill_exact` changes which core it calls — state the claim being made: every length below it, every length above it, or one length either side of it. Then check the claim. A rung boundary at 8 and 32 blocks means 511 and 513 bytes and 1023 and 1025 bytes, and a claim of "every length" that is tested at 512 is a claim that was never tested.

The offsets are the same argument: 0, 1, 2, 7, 64 and 65535 is a selection, not a proof, so say what it is. An offset that only some callers use needs a different set than one every caller uses.

If the honest answer is "dense, not exhaustive", say that in the report and in the README, and add the straddle lengths the claim needs. Do not add lengths without saying why the set has the shape it has.
```

**Add-on — exhaustive-budget:** Exhaustive at every length and offset is a product of numbers, not an aspiration. If it does not fit the runner's budget, report the size it would need and gate the subset that fits.

**Add-on — parallel-swepth:** Shapes are independent, so a matrix over runners is the cheapest way to buy coverage. Keep gate 1 ahead of every timing measurement regardless of how the work is split.

**Add-on — upstream-chacha:** Read `upstream/xray-core/common/crypto/chacha20.go` for the refill-per-call shape this removes, `upstream/zeronet/bench/hotpath/` for the loopback-measured one, `upstream/xray-rust/crates/` for the Rust one — then write the smaller thing, not a port.

**Add-on — prove-parsing-too:** If the slice touches any parse or check, benchmark it like everything else; an unmeasured parser is an unproven parser.

## P5 · Prove the vector rungs on every ISA they compile for

**When to use:** The cores are in the tree and nothing has measured them yet. A vector core that is faster and differs at one offset is a different implementation, so identity comes first and speed second.
**Status:** doing
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p dovetail-bench`; CI: `bench.yml` gate 1 on every runner in the matrix
**Depends on:** P2
**Touches:** crates/dovetail-core/src/chacha/neon.rs, crates/dovetail-core/src/chacha/avx2.rs, crates/dovetail-bench/src/main.rs, +docs/function/chacha-rungs.md
**Random weight:** 5

```text
`dovetail_core::chacha` now has a portable core, an NEON core and an AVX2 core behind one `Lanes` trait. The round function is written once and instantiated per architecture, so bit-identity across architectures is structural rather than merely tested: three hand-written ChaCha20 cores would drift, and the differential test would then report a mismatch without saying which one is wrong.

What still has to be checked is that each `Lanes` impl means what it claims — the lane count, the chunk layout, and the store that writes four consecutive state words per 128-bit chunk. That is the differential test at every length and every block offset, and it has to run on a runner whose architecture is named in the job, because a width chosen on Neoverse and not measured on Firestorm is a width chosen on one machine.

Name both backends in the report on every row: `dovetail_core::chacha_backend()` says what this build dispatched to, and the reference's own backend says what it compiled to. On a build where this says "scalar" while the reference says "avx2", the ratio is not evidence about the algorithm.

Keep the two key pairs that differ in every byte. An all-equal key cannot distinguish a correct word order from a permuted one, and a key that is all zeros would quietly make a swap of two identical words look correct.

Write the page under `docs/function/` before the merge, not after: a per-architecture lane layout explained in a commit message is a layout the next person has to re-derive.
```

**Add-on — isa-matrix:** Add the runner per ISA you are measuring, in `bench.yml`, and name the runner in the job name. Do not summarise a matrix as one architecture.

**Add-on — key-policy:** Two key pairs differing in every byte, and a `core 0` versus `core 8` keystream inequality, are the minimum. State in the report which of these caught which bug.

**Add-on — bit-identity-first:** Run gate 1 before gate 3, always. A wrong core must never get to be a fast one, because the timing gate would have passed it.

**Add-on — upstream-simd:** Compare lane layouts in `upstream/xray-core/common/crypto/chacha20.go`, `upstream/sing-box/transport/` with `protocol/shadowsocks/`, `upstream/xray-rust/crates/`, `upstream/zeronet/crates/zero-protocol/`; note each project's transpose cost, then beat it structurally.

## P6 · Finish the rustls backend and make a handshake provable

**When to use:** The rustls backend is in the tree and completes no proven handshake yet, so the next question is not whether it compiles but whether it can be held to the same claim as the record layer.
**Status:** done
**Leverage:** 4
**Effort:** large
**Gates:** `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; CI: `ci.yml` test matrix on linux and windows
**Depends on:** P2
**Touches:** crates/dovetail-core/src/tls/rustls_backend.rs, crates/dovetail-core/src/tls/mod.rs, docs/function/tls-provider.md
**Random weight:** 2

```text
`dovetail_core::tls` has the interface and a rustls backend, linked unconditionally. There is no feature to select and no build without TLS, so a missing stack can never become a silent fallback to plaintext, and that rule only earns its keep if a handshake test proves the provider connects.

Write the handshake test in this slice, not later: a provider that completes no handshake is an interface with more code attached. Test the negative as well as the positive — a mismatched certificate name and a refused ALPN must both fail, because a TLS stack that ignores them is worse than one that has no stack at all.

The interface deliberately has no method whose answer is really about rustls internals, and `suites` is read from the stack rather than declared in the interface. Keep it that way: a hand-written suite list drifts from the stack it describes, and every comparison drawn from a drifted list is meaningless.
```

**Add-on — no-claims-until-tested:** Add the handshake test in the same slice. An untested provider is an interface again, with more code attached.

**Add-on — upstream-tls:** Start in `upstream/xray-core/transport/internet/` under `tls`, `reality`, `finalmask`, then `upstream/sing-box/transport/`, `upstream/xray-rust/crates/xray-utls/`, `upstream/zeronet/crates/zero-transport/`; keep the interface narrower than every one of them.

## P7 · Run the pinned upstream suites against our binaries in CI

**When to use:** When a compatibility surface is about to be claimed. This is the strongest evidence available and the reason the upstream sources were fetched.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Gates:** CI: `ci.yml` upstream job green on every runner in the matrix; `./scripts/check-upstream-pins.sh`
**Depends on:** P2, P3
**Touches:** .github/workflows/ci.yml, scripts/check-upstream-pins.sh
**Random weight:** 5

```text
Run each pinned upstream implementation's own test suite against Dovetail's binaries, unmodified, in CI.

Running their suites unmodified is both licence-clean and a stronger claim than a hand-rewritten vector: sing-box is GPL-3.0 and Xray-core is MPL-2.0, so a test copied into this repository would make the licence of this work undecidable. Fetch at the pin, run, report which tests pass and which fail.

A failing upstream test is a finding, not an obstacle. Report it with the upstream test's name, what it expected and what we produced, and put the honest count in the README's status table. A subset that passes is a subset; say which subset.

If the suites cannot run against our binaries at all, that is the result. Report it, and say what would have to exist for them to run — which is a more useful thing to write down than a green tick that was never earned.
```

**Add-on — licence-clean:** Never copy upstream sources or tests into this tree. Fetch at the pin, run from the checkout, and let the artefacts be logs.

**Add-on — run-dont-vendor:** If a suite is too slow for every push, run it on `bench.yml`'s schedule and say in the README which claims are therefore only weekly-old.

**Add-on — upstream-suites:** Suite entry points are `upstream/xray-core/proxy/vless/`, `upstream/sing-box/protocol/vless/`, `upstream/xray-rust/crates/`, `upstream/zeronet/crates/`; run all four against the finished rung via `scripts/run-upstream-suite.sh` — green here plus red there is not done.

## P8 · Make Miri's boundary a claim that is written down and kept

**When to use:** When someone asks what memory safety is proven here. `chacha/mod.rs` now states what Miri covers and what it cannot interpret, which is the right place for it — but a statement in a module document is checked by nobody.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo +nightly miri test -p dovetail-core`; CI: `safety.yml` daily check
**Depends on:** P1
**Touches:** docs/methodology.md, .github/workflows/safety.yml
**Random weight:** 2

```text
Miri runs on the pure-Rust paths and cannot interpret `core::arch` intrinsics or anything linking a C library, so the safe part of the ladder, the counter arithmetic and every store offset are interpreted while the NEON and AVX2 modules are not. Put that boundary in the README's status table as well as in the module document, because the README is what a reviewer reads first.

Then make it a check rather than a sentence. The safety job should list the paths it ran, and the report should say which modules it skipped and what covers them instead — for the vector cores that is the differential test at every length and offset, and for anything linking C it is currently nothing. Say "nothing" in those words; a named gap is a plan and an unnamed one is a surprise.

Report Miri's runtime alongside its verdict. A suite that has quietly stopped running its heavy paths looks exactly like one that passed them.

Keep the nightly pin visible in the job name. Miri's results move with the toolchain, so a claim about it is a claim about a version.
```

**Add-on — miri-limits:** If a path cannot be interpreted at all, say so in the job output. Silence there reads as coverage.

## P9 · Assert the `Lanes` contract per architecture

**When to use:** When a new `Lanes` impl is added or an existing one changes, which is the only place bit-identity can now break — the round function is shared, so a bug is a layout bug and nothing else.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test -p dovetail-core --all-features`; `cargo run --release -p dovetail-bench`
**Depends on:** P4, P5
**Touches:** crates/dovetail-core/src/chacha/mod.rs, crates/dovetail-core/src/chacha/neon.rs, crates/dovetail-core/src/chacha/avx2.rs, crates/dovetail-core/src/chacha/portable.rs
**Random weight:** 4

```text
Writing the round function once and instantiating it per architecture turned "three ChaCha20 cores that drift" into "five primitives that must mean what they say". Audit those five: the lane count, the chunk layout, the add, the rotate, and the store that writes four consecutive state words per 128-bit chunk.

The layout is the part worth reading twice. Chunk `c` of register `g` holds words `4g..4g+3` of block `c * 4 + g`, which is what lets a store write consecutive output bytes with no transpose. A lane impl that produces the right bytes through a different layout would be right by accident, and the next change would make it wrong.

Make each of those a named constant or an assertion, not a comment. `LANES`, `CHUNKS` and the chunk-to-block mapping should be one expression evaluated per architecture, so the portable core and a vector core cannot disagree about the arithmetic and only the five primitives remain per-architecture.

Report what the audit found even when it found nothing. "Checked, unchanged" is a result; silence is indistinguishable from not having looked.
```

**Add-on — boundary-straddle:** Every length boundary still needs one length either side. The regression this repository has already had lived on a group boundary at 512 bytes and was invisible at 1024 bytes and above.

**Add-on — upstream-lanes:** Audit the five primitives against `upstream/xray-core/common/crypto/chacha20.go`, `upstream/sing-box/transport/` with `protocol/shadowsocks/`, `upstream/xray-rust/crates/`, `upstream/zeronet/crates/zero-protocol/`; note each project's transpose cost, then name which project does each one worst.

## P10 · Gate the documentation instead of asking for it

**When to use:** When a function is added or its contract changes and the matching `docs/function` page does not exist yet — which is the moment it will not.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo doc --workspace --all-features --no-deps`; CI: `ci.yml` lint job
**Depends on:** P1
**Touches:** +scripts/check-docs.sh, .github/workflows/ci.yml
**Random weight:** 2

```text
Write `scripts/check-docs.sh`, and make `ci.yml` run it. Every `pub fn` in `dovetail-core` has a page under `docs/function/`, and the script fails when one does not.

Write the script before the pages, so the pages are written against a rule that already exists. A documentation gate added after the documentation exists is a gate nobody believes will fire.

Scope is a decision rather than a default, so this slice has no default for it: the only place {scope} may be filled is on the command line. Say in the script's own header what is in scope and what is deliberately not, because the next person will extend it and should know which way.

Make the check about public API, not about prose quality. A missing page is a fact; a badly-written one is a judgement, and a CI job that grades prose gets deleted the first time it is wrong.

Report the count of pages checked. A gate that silently checks nothing is worse than no gate, because it reads as coverage.
```

**Add-on — doc-drift:** Where a page states a number — shapes tested, lengths measured, allocation counts — check the number against the code or stop stating it. A documented constant that has moved is a lie with a citation.

## P11 · Audit the README's claims against what CI proves

**When to use:** Whenever the status table is edited, and once now, because the table currently asserts a state no run has confirmed.
**Status:** done
**Leverage:** 5
**Effort:** small
**Gates:** CI: `ci.yml` green on all jobs; `./scripts/check-upstream-pins.sh`
**Depends on:** P2
**Touches:** README.md, docs/methodology.md, docs/arch/overview.md
**Random weight:** 4

```text
Take every claim in the README's status table and every sentence in `docs/`, and check each one against something that runs. Produce a table of claim, checking thing, and verdict.

The status table currently says the workspace resolves and is "awaiting first green CI run" while a green-looking README sits over four red runs. That is the shape of the failure this slice exists to prevent: a claim that reads as verified because it is in the table, with nothing in the table saying who verified it.

A claim with no checker is not removed — it is marked. "Not yet proven" is an honest line in a status table and a useful one, because it names the next slice.

Do not soften the wording. "Fastest" is not a claim this project makes and cannot support; "not slower at any single length, checked weekly on four runners" is one it can, and the difference between them is the whole point of `docs/methodology.md`.
```

**Add-on — claim-audit:** Report the count of claims checked, not just the ones that failed. A list of failures with no denominator reads like a partial audit.

## P12 · Security and memory audit of the record path

**When to use:** Before any surface that an untrusted network reaches, which is every surface this project intends to ship.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo +nightly miri test -p dovetail-core --all-features`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`
**Depends on:** P8
**Touches:** crates/dovetail-core/src/record.rs, crates/dovetail-core/src/core.rs
**Random weight:** 5

```text
Audit the record path for the properties a network-facing primitive needs: no read or write outside the caller's buffer, no use-after-free, no unbounded counter wrap, no secret left in a buffer that outlives the key.

Every write must be a sub-slice of the caller's buffer, so a write past the end is an index panic rather than a silent overrun. Check that each rung honours that, including the SIMD rungs where a vector store's width can exceed the remaining bytes — that is the bug a scalar audit misses.

The counter wrap check is the one that matters most: `fill_exact` refuses a start block that would wrap, and if a caller can reach it by arithmetic the assertion is the last line. Write the test that reaches it.

Report each finding with the rung, the length band and the input that triggers it. "Input-dependent" is not a severity.
```

**Add-on — audit-scope:** List the paths audited and the paths skipped. An audit that does not say where it stopped reads as a clean bill of health for the whole crate.

**Add-on — upstream-record:** Read `upstream/xray-core/common/crypto/chunk.go`, `upstream/sing-box/protocol/shadowsocks/`, `upstream/zeronet/bench/hotpath/` for how each bounds its writes; ours must be a sub-slice of the caller's buffer or it is wrong.

## P13 · Adversarial review of the bit-identity claim

**When to use:** Before any release claim, and any time a reviewer asks how the identity check could pass a wrong core — because it has, once, by stopping short of the second group.
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p dovetail-bench`
**Depends on:** P4, P7
**Touches:** crates/dovetail-core/src/record.rs, crates/dovetail-bench/src/main.rs
**Random weight:** 5

```text
Try to make the bit-identity check pass a core that is wrong. Write the failing core, run the check, and record where it was caught.

The regression in this repository's history was found by this exercise: the counter advanced by the block offset and forgot the group offset, every group after the first replayed the first group's keystream, and every length of 1024 bytes or more was wrong. It survived because the workspace had never compiled, so the test that would have caught it never ran.

Then fix the check for whatever it missed, and keep the mutation as a permanent test. A gate that has never been defeated has not been tested, only exercised.

Iterate until the attempt fails, and report the failing mutation as well as the passing check. The interesting artifact is the wrong core, not the green tick.
```

**Add-on — adversary-profile:** Vary the adversary. A wrong word order, a wrong counter advance, an all-equal key, a boundary off by one, and a rung that is only wrong at one offset are five different bugs and a check aimed at one of them says nothing about the other four.

**Add-on — upstream-adversary:** Try first the mutations that bit each project — replayed keystream, permuted words, off-by-one boundaries — and check `upstream/zeronet/docs/benchmarks/` for what their harness caught that ours must catch too.

## P14 · Report the throughput ceiling of the record path

**When to use:** When someone asks how fast the record layer is in absolute terms, which the ratio-based gate cannot answer because it only ever compares two implementations.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo run --release -p dovetail-bench`; CI: `bench.yml` on every runner in the matrix
**Depends on:** P5
**Touches:** crates/dovetail-bench/src/main.rs
**Random weight:** 2

```text
Add absolute throughput to the bench report — bytes and records per second per length, next to the existing ratio — so the report says what the core does as well as how it compares.

Keep the two separate in the report. The ratio is what this project gates on and it is machine-independent in the sense that matters; the absolute number is context and it is a property of one runner at one moment. Mixing them invites the reader to treat the absolute figure as a claim.

State the reference's asymmetry in the same breath as any number you add: it is re-keyed and re-seeked on every call, which a stateful record layer would not do, and that flatters short lengths in particular. The 16384-byte row is the one closest to a real VMess or Shadowsocks record and should be called out as the headline.

A throughput ceiling that is reported honestly is more useful than one that is withheld, because a withheld number is invented by whoever estimates it.
```

**Add-on — timing-noise:** Give any sub-bar ratio the same four-times-budget re-measurement the gate gives it. A single noisy sample that becomes a permanent table entry is the failure mode of every benchmark table ever published.

**Add-on — upstream-ceilings:** Read `upstream/zeronet/docs/benchmarks/` with `bench/hotpath/` and `upstream/xray-rust/crates/xray-bench/` for how each reports ceilings; ours stays a ratio plus a headline row, never a bare absolute.

## P15 · Ship the VLESS surface end to end

**When to use:** When the primitives, the identity gate, the upstream comparison and the review are in place, which is the first moment a surface can be built on something already proved.
**Status:** doing
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test --workspace --all-features`; CI: `bench.yml` gate 1 and gate 2 green on every runner in the matrix; CI: `ci.yml` upstream job green
**Depends on:** P6, P7, P13
**Touches:** crates/dovetail-core/src/vless.rs, README.md, docs/arch/overview.md
**Random weight:** 3

```text
`vless.rs` parses the share link a ZeroNet or v2rayNG user actually pastes, preserves every query key including PattNG's `unsafe-*` fingerprints, and reports a transport this core does not implement as unsupported-with-a-reason rather than by leaving the cell out. That distinction is the whole design and it must survive into whatever is built on it.

One surface, not five. A single drop-in for Xray-core, sing-box, Amnezia and the Rust ports of each is five compatibility surfaces with different wire formats, config schemas and APIs, and a surface built on an unproven primitive inherits its bugs and its silence.

So: take the one transport the parser reports as supported — `type=tcp + security=reality + flow=xtls-rprx-vision` — and make it actually carry a record through `record::fill_exact`. Then run the pinned upstream suite against the result, unmodified, and report the count honestly including the failures.

An unsupported cell that says why is worth more than a supported one that is wrong, and a comparison table that reads "empty with a reason" is evidence. Keep that property when the table grows.

The order is deliberate: primitives first, each proved, then a surface. If the surface exposes a primitive bug, the fix is in the primitive and the surface keeps its tests.
```

**Add-on — surface-first:** Document the wire format and the config schema before implementing it, so the compatibility target is a written contract rather than an implementation that is compared against itself.

**Add-on — unsupported-cells:** Every cell in the comparison table gets one of three values: a measured number, "unsupported" with a reason, or "not implemented" with a reason. A blank cell is the only forbidden one.

**Add-on — upstream-vless:** Wire-format sources, in order: `upstream/xray-core/proxy/vless/` under `encoding`, `inbound`, `outbound`, then `upstream/sing-box/protocol/vless/`, `upstream/xray-rust/crates/`, `upstream/zeronet/crates/zero-protocol/` with `zero-transport/`; implement the narrower parser and prove it faster per length.

**Add-on — upstream-tests-on-done:** When the rung dials, run all four suites via `scripts/run-upstream-suite.sh` — `upstream/xray-core/proxy/vless/`, `upstream/sing-box/protocol/vless/`, `upstream/xray-rust/crates/`, `upstream/zeronet/crates/` — before calling it done.

## P16 · Rewrite for readability without making it slower

**When to use:** When a file has grown a second way of doing something, or a `cfg` fork has made one idea live in three places, and the next change to it will have to be made three times. Also when something is genuinely hard to read and nobody can say why.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p dovetail-bench`; CI: `bench.yml` gate 1 and gate 2 green on every runner in the matrix
**Depends on:** P2, P4
**Touches:** crates/dovetail-core/src/core.rs, crates/dovetail-core/src/chacha/mod.rs, crates/dovetail-prompt/src/main.rs, scripts/check-comments.sh
**Random weight:** 4

```text
Make one file easier to read and easier to extend, and prove the rewrite changed nothing about what it does or how fast it is. This is a refactor, so the whole value is in the proof: a more readable file that is subtly slower, or that quietly changed a boundary case, is worse than the file it replaced.

Pick the duplication that is actually costing something. The candidates in this tree, at the time of writing: `core.rs::backend` repeats the same four backend-name strings across four mutually exclusive `cfg` blocks where two of the pairs differ only in `target_arch = "x86"` versus `"x86_64"`; `chacha/mod.rs` declares `vector_group` three times and `xor_blocks` twice under `cfg`, so a change to the vector path has to be made in every copy; and `dovetail-prompt`'s `main.rs` is one binary target with five verbs and the printing for all of them in a single file. Say which one you are taking and why that one, in the first line of your report.

The rules, because "cleanup" is how a codebase loses its gates:

- The diff must contain no behaviour change. If you find yourself adding a branch, adding a fallback, or reordering a computation, that is a bug fix or a feature — stop, and record it as its own slice in this file rather than folding it into a refactor nobody can review.
- No abstraction may exist for one implementation. An interface with a single implementor and no second one planned is a promise, and this repository has already shipped a version of that mistake: `tls.rs` was an interface nothing implemented, which is why the rustls backend slice exists at all. If you introduce a trait, name the second implementor in the same commit or do not introduce it.
- The output must be byte-identical. Run the differential sweep over every length and every block offset, not the tests that happen to be convenient. A refactor that changes a byte at one offset is not a refactor.
- The timing must not regress at any single measured length. A rewrite is allowed to be faster; it is not allowed to be slower anywhere, because "not slower than the reference" is a floor, not a target, and a reader who cannot see the split between this change and the next one has to assume the worse.

Prove it rather than asserting it. Attach the before and after benchmark tables side by side, name the machine both were measured on, and report the worst length's ratio in both. If a length moved, say by how much and whether it is inside the noise you would expect from a shared runner — and if you cannot tell, say that instead of calling it neutral. A refactor report that says "no performance impact" without a number is the same class of claim as a benchmark that never ran.

Scalability here means the next change costs one edit, not that the file got shorter. State the concrete thing that is now easier: which duplicated `cfg` fork is down to one copy, which function no longer has to be read alongside two others to be understood, which addition to `dovetail-prompt` no longer means editing a five-verb file. If you cannot name one of those, you have made the code tidier and not better, and the difference is worth saying out loud.

Leave the debt you did not pay. If a second duplication is visible but out of scope, add a slice for it here with the same fields every other slice has, so the next contributor inherits a plan rather than a suspicion. Do not leave a comment saying "TODO: dedupe" — a comment is not a task and it is checked by nothing.
```

**Add-on — cfg-forks:** When the duplication you are removing is `cfg`-gated copies of one function, count the copies before and after and say so. "Reduced three copies to one" is a claim a reader can check; "simplified" is not.

**Add-on — golden-diff:** When the rewrite touches anything with a byte-level output, diff the two builds' output over the full length and offset sweep and record the file. A refactor whose evidence is a passing test suite is relying on the suite to be complete, which it has already once failed to be.

**Add-on — no-new-allows:** Count the `#[allow]` attributes before and after. If the refactor needs one, the code it is refactoring was fighting something real and the honest move is to fix that thing rather than to silence the lint for the rest of the repository's life.

**Add-on — report-shape:** Write the report as: what was duplicated, what it cost, what changed, what was measured, what was not measured. The last section is the one everybody skips and the one that tells the next contributor whether to trust this.

**Add-on — trace-free:** No comment blocks and one line per item at most (`scripts/check-comments.sh` fails the rest); a refactor that needs a paragraph to explain is two changes.

**Add-on — simplicity-wins:** In a tie the shorter, more explainable form ships; the complex form survives only with a measured win in CI, never with an argument.

## P17 · Decide what "not slower" means at one block, and gate that

**When to use:** Now, and before any further work on the record path's speed. Both x86_64 runners are green across all 291 lengths (worst 1.02x at 320 B). Both aarch64 runners fail on the band from 1 to 64 bytes and nowhere else — 12 lengths at 0.85-1.00x on `macos aarch64`, 43 at 0.95-1.00x on `linux aarch64` — and that band is a tie by construction, which a 1.00x bar with no allowance cannot certify.
**Status:** done
**Leverage:** 5
**Effort:** small
**Gates:** CI: `bench.yml` green on `linux aarch64` and `macos aarch64`; `cargo run --locked --release -p dovetail-bench` for the table the decision is read off
**Depends on:** P2
**Touches:** crates/dovetail-bench/src/main.rs, docs/methodology.md, docs/function/chacha-xor-blocks.md
**Random weight:** 2

```text
`bench.yml` is red on `linux aarch64` and `macos aarch64` at exactly one band: lengths of 1 to 64 bytes, where the whole call is a single 64-byte block. Both sides run the same twenty rounds over the same single state there. There is nothing to interleave, nothing to discard and no copy on either side, so the true ratio is 1.00 and the gate is measuring the runner. Measured on one aarch64 machine at len 1: reference 92.5 ns, this core 91.9 ns, and a hand-written scalar 16-word core of the same round function 98.3 ns — the vector core measures *slower* at one block (119.7 ns) because a single dependency chain has nothing to overlap, which is why the tail sends one block to the scalar core.

Do not fix this by making the core faster at one block. It cannot be made faster: the work is the same work, and the two candidate cores have both been measured — 91.9 ns for the scalar portable core against the reference's 92.5 ns, and 119.7 ns for the NEON core for the same block on the same machine, which is why the ladder sends one block to the scalar one. Fix it by deciding what the gate is for at a tie, and writing the decision down where the next reader will find it.

Note what is *not* on this list any more: the x86_64 band, which was the same shape of bug and is fixed. AVX2's smallest exact unit is two blocks, so an odd block count left one block over, and the only core for it was `portable` — which LLVM compiles to scalar `movl` on x86_64. `chacha::sse2` is that block now, and both x86_64 runners are green at every length including 1-64 bytes, because the reference there computes four blocks and discards three.

The decision has two honest forms and one dishonest one:

- **Restate the claim, keep the strict bar elsewhere.** "Not slower than the reference at any measured length of two or more blocks, and not slower at one block by more than this runner can resolve." Then the gate needs a resolution floor that is *measured*, not assumed: at each length, compare the reference against itself with the same discipline and use the observed spread as the floor. That is a claim about the instrument as well as the code, and the report has to print both numbers so a reader can see when the floor is doing the work.
- **Keep the claim, exclude the band from the sweep, and say so.** Removing 1-64 from `lengths()` is a smaller change, but it is only honest if the report and the README both name the excluded band and the reason, because a sweep that silently stops at 65 is how a 0.83x survived to a release once already.
- **Flat tolerance, ordered after all.** A bar of 0.95x was declared not acceptable above because it would hide a real 5% regression at 512 bytes, where this core has margin to give. Ordered on 2026-10-03 anyway for cycle speed: three single-length dips at 0.97-0.99x each cost a full bench cycle, and the 512 B margin argument is accepted as risk. The bar prints in every report header, so the allowance is visible where it applies.

Whichever form you take, the same three things have to be true when the slice is done:

- `bench.yml` is green on all four runners, or the README names the runner and the band that is still red.
- The claim table in the README and the table in `docs/methodology.md` say the same thing, in the same words, and neither says "not slower at any single length" while the gate cannot check it.
- The report prints the per-length ratio *and* whatever floor was applied to it, because a gate that hides its own tolerance is the exact failure mode this repository exists to prevent.
```

**Add-on — the exclusion form:** If you take the exclusion form, count the lengths removed and print them in the report header, so the sweep's coverage is a number a reader can compare against `292`.

## P18 · Make "no discarded work" a check that can fail

**When to use:** Done. `xor_groups` returns the `NST * CHUNKS` blocks it generated, the ladder sums them and advances the counter by the same values, and gate 2 compares that against `ceil(len / 64)` at every length and six block offsets. A second test feeds the comparison a count one block high and one block low and requires it to reject both.
**Status:** done
**Leverage:** 5
**Effort:** medium
**Gates:** `cargo test --workspace --all-features`; CI: `bench.yml` gate 2 green on every runner in the matrix; a test that fails when the count is wrong
**Depends on:** P2
**Touches:** crates/dovetail-core/src/record.rs, crates/dovetail-core/src/chacha/mod.rs, crates/dovetail-bench/src/main.rs, docs/methodology.md
**Random weight:** 3

```text
`fill_exact` returns `blocks_for(buf.len())` — the formula — and gate 2 compares that return value against `blocks_for(len)`. So the check is `ceil(n / 64) == ceil(n / 64)`: it cannot fail, and it has been reported green on four runners as if it could. The claim underneath it is real (the ladder generates exactly the blocks the caller asked for, and that is why the timings improved), but the claim and its checker have drifted apart and nobody wrote down when.

Fix the check, not the claim. The count the ladder *actually* produced has to come from the ladder, not from the caller: a `blocks_generated` out-parameter threaded through `xor_blocks` and returned by the pass it came from, so a tail that overshot would report the overshoot. Two properties must then hold and both must be provable:

- the number the ladder reports equals `ceil(len / 64)` at every length and every block offset — that is gate 2, and it can now fail;
- a deliberately wrong ladder fails the gate. Prove that by making the tail overshoot in a test build and showing the gate goes red. A gate nobody has watched fail is not a gate, and the way to know one can fail is to have watched it.

Then correct the three documents that describe the old arrangement, including `docs/function/record-fill-exact.md`, which already says the previous version of this test "proved nothing about the implementation" — the same sentence is true of the current one and should not have needed a second defect to become true.

Do not keep both an out-parameter and the formula: two ways of counting blocks is a second answer to the same question, and the one that is checked has to be the one that runs.
```

## P19 · Run one upstream suite against a Dovetail binary

**When to use:** Before any rung is called `Implemented`, and before `docs/conformance.md` keeps saying that suites run against these binaries. Today no suite runs a Dovetail binary at all, and the two that could are both blocked on the same missing server.
**Status:** done
**Leverage:** 4
**Effort:** medium
**Gates:** CI: `conformance.yml` green with a suite that executed a Dovetail binary, and the log line naming the binary and the pin
**Depends on:** P2, P18
**Touches:** scripts/run-upstream-suite.sh, upstream/pins.toml, docs/conformance.md
**Random weight:** 2

```text
Reading every fetched pin for a point where an external binary could be injected — an environment variable naming a binary, the only shape a suite can be pointed at without editing it — gives 0 of 7. `xray-core`, `sing-box`, `amneziawg-go`, `amnezia-client` and `pattng` have none: their tests are in-process, so no binary can be pointed at them at all, and building one would change nothing. `xray-rust` (`XRAY_VLESS_FULL_BINARY`) and `zeronet` (`ZRAY_XRAY_BINARY`) have one, and both spawn the substitute as `run -c <config.json>` and wait for it to *listen* — a VLESS **server** role. `dovetail-zeronet` parses a link, prints its `Support`, TCP-connects and sends nothing; it has no `version`, no `-c`, no `x25519` and no listener.

So the gap is not the harness, which now refuses to lie: `run-upstream-suite.sh` fails an enabled entry with no `dovetail_binary`, refuses one with no `seam`, and refuses one whose declared `seam` the pinned tree never reads, because building a binary and not executing it is a `PASS` naming something that took no part. The gap is that no substitute binary can yet answer `version` and hold a VLESS listener, so the two reachable suites both stop at the first spawn.

Give `dovetail-zeronet` the smallest Xray-CLI-shaped surface those two seams actually call — `version`, `run -c <file>` with an inbound listener, and `x25519` — and `zeronet`'s `cargo test -p zero-runtime --test xray_oracle -- --ignored --test-threads=1` becomes a differential run against our binary with no upstream file edited. Report which of the nine `xray_oracle` tests pass unmodified against ours and which fail, by name; a subset that passes is a subset.

Then the five pins with no seam are the remaining half, and they need a different mechanism: an upstream harness that takes a *socket* rather than a *binary*. If none exists at a pin, say so per pin rather than inventing a runner that exercises our code outside their test.
```

## P20 · Port one upstream suite to Rust and retire its toolchain

**When to use:** When an upstream suite's only job in CI is to need its toolchain — Go for xray-core, and whatever sing-box needs next — while what it checks is behavior this tree could state itself.
**Status:** todo
**Leverage:** 4
**Effort:** large
**Gates:** CI: `conformance.yml` green with the ported suite; the original suite still green beside it (parity); `cargo test --workspace --all-features`
**Depends on:** P2, P19
**Touches:** scripts/run-upstream-suite.sh, docs/conformance.md
**Random weight:** 2

```text
Take the smallest enabled suite and write it in Rust from its observed behavior: same inputs, same expectations, this tree's own words. Never transliterate — no upstream line enters this tree, so the port is read off the wire format and the failure modes, not off their files.

Run the port beside the original until parity holds for three consecutive green runs; only then does the original stop running for that suite. Retire exactly the toolchain the ported suite needed, and say which one in the report.
```

## P21 · Repair the pin `path` fields that name nothing at their own rev

**When to use:** Before any slice that reads a pinned source starts, because the `path` is the field that says which tree backs the note next to it, and four of the seven currently point at a directory that is not there.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `./scripts/check-upstream-pins.sh`; CI: `ci.yml` upstream job
**Depends on:** P3
**Touches:** upstream/pins.toml, scripts/check-upstream-pins.sh, scripts/fetch-upstream.sh, docs/claims.md
**Random weight:** 2

```text
Four `path` values in `upstream/pins.toml` name a directory absent at their own pinned rev, measured against the trees `scripts/fetch-upstream.sh` brought down: `xray-core` says `crypto/chacha20` where the file is `common/crypto/chacha20.go`; `amneziawg-go` says `device/noise` where the ChaCha20 use is `device/noise-protocol.go`, `device/cookie.go` and `device/send.go` under `device/`; `amnezia-client` says `src/crypto` where there is no `src/` at all and the code is `common/crypto/`; `sing-box` says `common/crypto`, which does not exist and where the string `chacha20poly1305` appears nowhere in the tree, because its shadowsocks cipher is the out-of-tree module `github.com/sagernet/sing-shadowsocks2`.

So the notes beside those four pins describe code no fetched tree contains. The `rev`s are correct and every one resolves; it is the `path` that has rotted, and it rotted silently, because nothing checked it.

Make `path` a checked field rather than a comment. Either the checker resolves it against the pinned tree — which means fetching, so it belongs in a job that already fetches rather than in `check-upstream-pins.sh`, which resolves by commit id without a worktree — or the field goes away and the note names the file, since a note that names a path which is checked is worth more than a path that is not. Say which, and delete the loser rather than leaving a second way of saying it.

Repair the four values to the paths measured here, or restate each note against what the pin actually holds if the note is the stale half. `sing-box` is the one that cannot be a path repair alone: either its note names the out-of-tree module, or its pin moves to a revision where the crypto is in-tree, and a pin moving is a `scripts/update-pins.sh` PR like any other.
```

## P22 · Stop check-comments.sh failing on mktemp templates

**When to use:** When `check-comments.sh` fails a change that carries no trace marker: its marker grep matches the six-X run in any `mktemp` template, so an atomic write-then-rename script cannot land while the gate stands as written.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `./scripts/check-comments.sh` green on a tree containing an `mktemp` template; CI: `ci.yml` lint job green
**Depends on:** P2
**Touches:** scripts/check-comments.sh
**Random weight:** 2

```text
Narrow the trace-marker grep so a six-X `mktemp` template passes while a real marker still fails: anchor the match so the template's run of Xs is not one, keep failing on a marker in `scripts/` and `*.rs`, and prove both halves with a fixture containing each. Main's `6650579` is the case that exposed it: its atomic-manifest fix to `fetch-upstream.sh` is behaviorally correct and `ci.yml` lint is red on it for the template alone, which is why this slice's fetch fix ships the one-line form instead.
Report the match count before and after on this tree. A gate that cannot distinguish its target from its opposite protects nothing.
```

## P23 · Run CI on pull requests, not only on main pushes

**When to use:** When a slice needs its gates evidenced before merge, which is every slice: a gate that only runs after landing on main reports on what already shipped.
**Status:** done
**Leverage:** 5
**Effort:** small
**Gates:** CI: `ci.yml` green on a `pull_request` event run
**Depends on:** P2
**Touches:** .github/workflows/ci.yml
**Random weight:** 2

```text
`ci.yml` lists `pull_request` under its triggers, yet opening PR #1 produced no run at all and the actions API lists no `pull_request` event run, so a branch under review shows no checks. The only evidence a contributor can produce before merge is then a local run, which the shared protocol does not accept as evidence about any runner — and the merge that lands it is unevidenced by construction.
Make a pull request run CI: find whether the trigger, the repository settings, or the workflow file on the base ref is what swallows the event, fix that one thing, and show a `pull_request` run green on a branch that is not main. Until then every slice's "CI" gate means "CI after landing", and the README's "push, read CI" loop should say so in the same sentence.
```

## P24 · Trojan protocol rung over raw TCP

**When to use:** When the two trojan oracle failures are the next ones to clear: both expect a `trojan` listener and get exit 1.
**Status:** done
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with both trojan oracle tests executed against `dovetail-zeronet`
**Depends on:** P19
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 2

```text
Give `dovetail-zeronet` a `trojan` server role and a `trojan` client role over raw `TCP`, following the P19 pattern: read the inbound/outbound pair out of the same config file, relay both directions, close fast on anything else. Then widen the `zeronet` suite filter by exactly the two names that now pass — `trojan_over_raw_tcp_matches_the_oracle` and `trojan_over_websocket_matches_the_oracle` only if the `ws` half passes too, otherwise the raw one alone — and report both directions by name. A subset that passes is a subset; the `ws` half without P27 stays a named failure.
```

## P25 · VMess protocol rung over raw TCP

**When to use:** When the two vmess oracle failures are the next ones to clear: both expect a `vmess` listener and get exit 1.
**Status:** todo
**Leverage:** 4
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with both vmess oracle tests executed against `dovetail-zeronet`
**Depends on:** P19
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 2

```text
Give `dovetail-zeronet` a `vmess` server role and a `vmess` client role over raw `TCP`, following the P19 pattern. `VMess` is the heaviest of the three password protocols — timestamps, key derivation, authenticated encryption — so prove the framing against the oracle the same way P19 proved `VLESS`: enable only the names that pass unmodified, `vmess_over_raw_tcp_matches_the_oracle` first, and report the `ws` half as a named failure until P27 lands. Never transliterate: no upstream line enters this tree.
```

## P26 · Shadowsocks protocol rung over TCP

**When to use:** When the shadowsocks oracle failure is the next one to clear: it expects a `shadowsocks` listener and gets exit 1.
**Status:** done
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with the shadowsocks oracle test executed against `dovetail-zeronet`
**Depends on:** P19
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 2

```text
Give `dovetail-zeronet` a `shadowsocks` server role and client role for `aes-256-gcm` over `TCP`, following the P19 pattern, then enable exactly `shadowsocks_over_raw_tcp_matches_the_oracle` in the `zeronet` suite filter and report both directions by name. One cipher, one transport, no plugin system: the plugin surface is a different slice and does not ride along here.
```

## P27 · WebSocket transport for VLESS

**When to use:** When the `vless_over_websocket` oracle failure is the next one to clear: the handshake is closed after the first byte.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with the websocket oracle test executed against `dovetail-zeronet`
**Depends on:** P19
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 2

```text
Teach `dovetail-zeronet` the `ws` carrier for the two roles it already plays: accept the upgrade handshake as a server and perform it as a client, then carry the same `VLESS` bytes inside it. Enable exactly `vless_over_websocket_matches_the_oracle` once both directions pass unmodified and report them by name. Masking, fragmentation and closing belong to this slice; `httpupgrade` and `grpc` do not — they are P28.
```

## P28 · HTTPUpgrade and gRPC transports for VLESS

**When to use:** When the `httpupgrade` and `grpc` oracle failures are the next ones to clear: one fails the handshake, the other times out on echo.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with both oracle tests executed against `dovetail-zeronet`
**Depends on:** P19
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 1

```text
Teach `dovetail-zeronet` the two remaining `HTTP`-family carriers P19 measured failing: `httpupgrade` and `grpc`, each in both server and client roles, following the P27 pattern of carrying unchanged `VLESS` bytes inside the new framing. Enable exactly `vless_over_http_upgrade_matches_the_oracle` and `vless_over_grpc_matches_the_oracle` once each passes unmodified in both directions, and report them by name. `xhttp` is not this slice; it gets its own once these two are green.
```

## P29 · Wire the xray-rust seam once REALITY dials

**When to use:** When P15's `reality`/`vision` rung carries a record, which is the only thing the `xray-rust` suite exercises that this binary cannot yet do.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** CI: `conformance.yml` green with the seam-injected run against `dovetail-zeronet`, and the log line naming the binary and the pin
**Depends on:** P15
**Touches:** upstream/pins.toml, docs/conformance.md
**Random weight:** 1

```text
Flip the `xray-rust` pin to `test_enabled = true` with `dovetail_binary = "dovetail-zeronet"` and the suite command its interop tests need, injected via `XRAY_VLESS_FULL_BINARY` — the seam the pinned tree already reads. The binary already answers `run -config`; what was missing was the `REALITY` behavior P15 owns, so this slice contains no transport code, only the flip and the per-test report by name. A subset that passes is a subset.
```

## P30 · Implement one README connection method end to end

**When to use:** When exactly one unchecked row of the README connection-methods matrix is the next box to check, and the point is the whole box — both roles, the proof, the gate, the flipped cell — not a first half of it.
**Status:** done
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with the row's upstream suites executed unmodified against the Dovetail binary plus the extra differential tests below, and the README cell flipped with the run that backs it
**Depends on:** P19
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md, README.md
**Random weight:** 2

```text
Pick exactly one unchecked row from the README connection-methods matrix and check its box completely: every role the method has, following the P19 pattern of enabling only the suite names that pass unmodified. Read each pinned implementation that already supports the row, plus the read-only learnings the row names, then rewrite — no upstream line or test enters this tree.

Prove it twice: first with the other projects' own suites run unmodified from their pins against the Dovetail binary (`run-upstream-suite.sh`, seam-injected where the pin has one), then with more tests of your own that those suites do not cover — framing goldens, sweeps over lengths and offsets, negative tests that refuse malformed input, and a benchmark gate on every ISA runner. An oracle green with no differential of your own is half a proof and does not flip the cell.

Land as one method only: the row, its proof, its gate, the suite flip in `upstream/pins.toml`, and the README cell with the run that backs it. Chaining two methods is a different slice and does not ride along here.
```

**Add-on — one-row:** If the row needs a second method to be testable (a carrier for a protocol, a TUN for a relay), record that as a new prompt section rather than widening this one.

## P31 · Timing benchmarks for protocol framings

**When to use:** When a protocol rung needs a wall-clock comparison and only has counts: VMess sealed/open throughput has no timed reference anywhere, only the P30 formula gates, so a framing change that keeps sizes identical while adding passes is invisible.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Gates:** CI: `bench.yml` green with a protocol framing section that fails on regression on every runner in the matrix; `cargo test --workspace`
**Depends on:** P30
**Touches:** crates/dovetail-bench/src/main.rs, .github/workflows/bench.yml
**Random weight:** 1

```text
Give the protocol framings a wall-clock comparison with a reference on every ISA runner, the way gate 3 compares the record layer against the chacha20 crate. The obstacle is structural and decided first: framing lives in application crates a bench crate cannot import, and no same-language reference exists for VMess AEAD framing, so this slice decides where the timed code lives and what it is measured against, then gates it with gate 3's remeasure discipline. Counts (P30's formula gates) catch added copies; only timing catches added passes at equal size. Until then the claim stays the narrowed one P30 makes: bit-identical framing with exact sizes, no speed claim.
```

## Reading this file as a roadmap

The graph is the point, and it is not a decoration: `dovetail-prompt next` ranks ready slices by leverage, breaks ties towards the smaller one, leaves out the ones waiting on a decision, and reports what each slice unblocks. `P2` is ahead of everything because most of the rest of the roadmap depends on it, which is the kind of thing that is obvious once and invisible otherwise.

Numbers do not go in prose here. This file's gate checks structure — ids, dependencies, files, gates — and a sentence saying "eleven of fourteen" is a claim no check can keep, so the counts live in fields and `dovetail-prompt list` prints them.

Rotate with `dovetail-prompt next --rotate` when the ranking is not the question you are asking. It draws from ready slices only, weighted by `**Random weight:**`, and records the draw in `.dovetail/slices.log` so the next few calls do not offer the same slice twice.

Statuses are the only field a contributor edits to record progress. Mark a slice `done` when its gates are green, not when its diff is finished: the gates are what the next contributor is entitled to trust.
