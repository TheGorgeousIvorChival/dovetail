# Dovetail prompt library — single source of truth

`dovetail-prompt` reads this file and nothing else. No prompt prose lives in Rust, and a prompt is added by adding a section here: no code change, no recompile. If the tool and this file disagree, this file is right and the tool is broken — which is why `dovetail-prompt check` is a CI step.

## How to read this file

One prompt per `## P<n> · <title>` section. The numbers are the roadmap: the tool counts what each one unblocks and says so rather than leaving it to be worked out by reading every heading.

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

Paths under `upstream/<name>/` are pinned reading copies for agents, fetched by `scripts/fetch-upstream.sh`: `xray-core`, `sing-box`, `amneziawg-go`, `amnezia-client`, `xray-rust`, `pattng`, `zeronet`, `mqvpn`, `aether`, `zeptun`, `slipstream`, `quiche`. They never appear in `**Touches:**` — checkouts are derived artifacts, and a touch naming one fails the gate wherever it was never fetched.

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

## P1 · Prove the vector rungs on every ISA they compile for

**When to use:** The cores are in the tree and nothing has measured them yet. A vector core that is faster and differs at one offset is a different implementation, so identity comes first and speed second.
**Status:** doing
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p dovetail-bench`; CI: `bench.yml` gate 1 on every runner in the matrix
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

## P2 · Run the pinned upstream suites against our binaries in CI

**When to use:** When a compatibility surface is about to be claimed. This is the strongest evidence available and the reason the upstream sources were fetched.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Gates:** CI: `ci.yml` upstream job green on every runner in the matrix; `./scripts/check-upstream-pins.sh`
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

## P3 · Make Miri's boundary a claim that is written down and kept

**When to use:** When someone asks what memory safety is proven here. `chacha/mod.rs` now states what Miri covers and what it cannot interpret, which is the right place for it — but a statement in a module document is checked by nobody.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo +nightly miri test -p dovetail-core`; CI: `safety.yml` daily check
**Touches:** docs/methodology.md, .github/workflows/safety.yml
**Random weight:** 2

```text
Miri runs on the pure-Rust paths and cannot interpret `core::arch` intrinsics or anything linking a C library, so the safe part of the ladder, the counter arithmetic and every store offset are interpreted while the NEON and AVX2 modules are not. Put that boundary in the README's status table as well as in the module document, because the README is what a reviewer reads first.

Then make it a check rather than a sentence. The safety job should list the paths it ran, and the report should say which modules it skipped and what covers them instead — for the vector cores that is the differential test at every length and offset, and for anything linking C it is currently nothing. Say "nothing" in those words; a named gap is a plan and an unnamed one is a surprise.

Report Miri's runtime alongside its verdict. A suite that has quietly stopped running its heavy paths looks exactly like one that passed them.

Keep the nightly pin visible in the job name. Miri's results move with the toolchain, so a claim about it is a claim about a version.
```

**Add-on — miri-limits:** If a path cannot be interpreted at all, say so in the job output. Silence there reads as coverage.

## P4 · Assert the `Lanes` contract per architecture

**When to use:** When a new `Lanes` impl is added or an existing one changes, which is the only place bit-identity can now break — the round function is shared, so a bug is a layout bug and nothing else.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test -p dovetail-core --all-features`; `cargo run --release -p dovetail-bench`
**Depends on:** P1
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

## P5 · Gate the documentation instead of asking for it

**When to use:** When a function is added or its contract changes and the matching `docs/function` page does not exist yet — which is the moment it will not.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo doc --workspace --all-features --no-deps`; CI: `ci.yml` lint job
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

## P6 · Security and memory audit of the record path

**When to use:** Before any surface that an untrusted network reaches, which is every surface this project intends to ship.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo +nightly miri test -p dovetail-core --all-features`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`
**Depends on:** P3
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

## P7 · Adversarial review of the bit-identity claim

**When to use:** Before any release claim, and any time a reviewer asks how the identity check could pass a wrong core — because it has, once, by stopping short of the second group.
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p dovetail-bench`
**Depends on:** P2
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

## P8 · Report the throughput ceiling of the record path

**When to use:** When someone asks how fast the record layer is in absolute terms, which the ratio-based gate cannot answer because it only ever compares two implementations.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo run --release -p dovetail-bench`; CI: `bench.yml` on every runner in the matrix
**Depends on:** P1
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

## P9 · Ship the VLESS surface end to end

**When to use:** When the primitives, the identity gate, the upstream comparison and the review are in place, which is the first moment a surface can be built on something already proved.
**Status:** doing
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test --workspace --all-features`; CI: `bench.yml` gate 1 and gate 2 green on every runner in the matrix; CI: `ci.yml` upstream job green
**Depends on:** P2, P7
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

## P10 · Rewrite for readability without making it slower

**When to use:** When a file has grown a second way of doing something, or a `cfg` fork has made one idea live in three places, and the next change to it will have to be made three times. Also when something is genuinely hard to read and nobody can say why.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p dovetail-bench`; CI: `bench.yml` gate 1 and gate 2 green on every runner in the matrix
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

## P11 · Port one upstream suite to Rust and retire its toolchain

**When to use:** When an upstream suite's only job in CI is to need its toolchain — Go for xray-core, and whatever sing-box needs next — while what it checks is behavior this tree could state itself.
**Status:** todo
**Leverage:** 4
**Effort:** large
**Gates:** CI: `conformance.yml` green with the ported suite; the original suite still green beside it (parity); `cargo test --workspace --all-features`
**Touches:** scripts/run-upstream-suite.sh, docs/conformance.md
**Random weight:** 2

```text
Take the smallest enabled suite and write it in Rust from its observed behavior: same inputs, same expectations, this tree's own words. Never transliterate — no upstream line enters this tree, so the port is read off the wire format and the failure modes, not off their files.

Run the port beside the original until parity holds for three consecutive green runs; only then does the original stop running for that suite. Retire exactly the toolchain the ported suite needed, and say which one in the report.
```

## P12 · Repair the pin `path` fields that name nothing at their own rev

**When to use:** Before any slice that reads a pinned source starts, because the `path` is the field that says which tree backs the note next to it, and four of the seven currently point at a directory that is not there.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `./scripts/check-upstream-pins.sh`; CI: `ci.yml` upstream job
**Touches:** upstream/pins.toml, scripts/check-upstream-pins.sh, scripts/fetch-upstream.sh, docs/claims.md
**Random weight:** 2

```text
Four `path` values in `upstream/pins.toml` name a directory absent at their own pinned rev, measured against the trees `scripts/fetch-upstream.sh` brought down: `xray-core` says `crypto/chacha20` where the file is `common/crypto/chacha20.go`; `amneziawg-go` says `device/noise` where the ChaCha20 use is `device/noise-protocol.go`, `device/cookie.go` and `device/send.go` under `device/`; `amnezia-client` says `src/crypto` where there is no `src/` at all and the code is `common/crypto/`; `sing-box` says `common/crypto`, which does not exist and where the string `chacha20poly1305` appears nowhere in the tree, because its shadowsocks cipher is the out-of-tree module `github.com/sagernet/sing-shadowsocks2`.

So the notes beside those four pins describe code no fetched tree contains. The `rev`s are correct and every one resolves; it is the `path` that has rotted, and it rotted silently, because nothing checked it.

Make `path` a checked field rather than a comment. Either the checker resolves it against the pinned tree — which means fetching, so it belongs in a job that already fetches rather than in `check-upstream-pins.sh`, which resolves by commit id without a worktree — or the field goes away and the note names the file, since a note that names a path which is checked is worth more than a path that is not. Say which, and delete the loser rather than leaving a second way of saying it.

Repair the four values to the paths measured here, or restate each note against what the pin actually holds if the note is the stale half. `sing-box` is the one that cannot be a path repair alone: either its note names the out-of-tree module, or its pin moves to a revision where the crypto is in-tree, and a pin moving is a `scripts/update-pins.sh` PR like any other.
```

## P13 · Stop check-comments.sh failing on mktemp templates

**When to use:** When `check-comments.sh` fails a change that carries no trace marker: its marker grep matches the six-X run in any `mktemp` template, so an atomic write-then-rename script cannot land while the gate stands as written.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `./scripts/check-comments.sh` green on a tree containing an `mktemp` template; CI: `ci.yml` lint job green
**Touches:** scripts/check-comments.sh
**Random weight:** 2

```text
Narrow the trace-marker grep so a six-X `mktemp` template passes while a real marker still fails: anchor the match so the template's run of Xs is not one, keep failing on a marker in `scripts/` and `*.rs`, and prove both halves with a fixture containing each. Main's `6650579` is the case that exposed it: its atomic-manifest fix to `fetch-upstream.sh` is behaviorally correct and `ci.yml` lint is red on it for the template alone, which is why this slice's fetch fix ships the one-line form instead.
Report the match count before and after on this tree. A gate that cannot distinguish its target from its opposite protects nothing.
```

## P14 · WebSocket transport for VLESS

**When to use:** When the `vless_over_websocket` oracle failure is the next one to clear: the handshake is closed after the first byte.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with the websocket oracle test executed against `dovetail-zeronet`
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 2

```text
Teach `dovetail-zeronet` the `ws` carrier for the two roles it already plays: accept the upgrade handshake as a server and perform it as a client, then carry the same `VLESS` bytes inside it. Enable exactly `vless_over_websocket_matches_the_oracle` once both directions pass unmodified and report them by name. Masking, fragmentation and closing belong to this slice; `httpupgrade` and `grpc` do not — they are P15.
```

## P15 · HTTPUpgrade and gRPC transports for VLESS

**When to use:** When the `httpupgrade` and `grpc` oracle failures are the next ones to clear: one fails the handshake, the other times out on echo.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with both oracle tests executed against `dovetail-zeronet`
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 1

```text
Teach `dovetail-zeronet` the two remaining `HTTP`-family carriers the `xray_oracle` subset measured failing: `httpupgrade` and `grpc`, each in both server and client roles, following the P14 pattern of carrying unchanged `VLESS` bytes inside the new framing. Enable exactly `vless_over_http_upgrade_matches_the_oracle` and `vless_over_grpc_matches_the_oracle` once each passes unmodified in both directions, and report them by name. `xhttp` is not this slice; it gets its own once these two are green.
```

## P16 · Wire the xray-rust seam once REALITY dials

**When to use:** When P9's `reality`/`vision` rung carries a record. Measured in `conformance.yml` run `37125321800`: 5 of the 23 `#[ignore]`d tests in `local_xray_interop_tests` pass unmodified against `dovetail-zeronet` and 18 do not, of which 11 are `TLS`/`REALITY` rows that need P9 and 7 belong to P22 (`gRPC` framing), P23 (`ws`/`httpupgrade` early data) and P24 (`xhttp`). The pin is already `test_enabled = true` with the five that pass, so what this slice has left is re-running the command as each of those three clears its rows.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** CI: `conformance.yml` green with the seam-injected run against `dovetail-zeronet`, and the log line naming the binary and the pin
**Depends on:** P9
**Touches:** upstream/pins.toml, docs/conformance.md
**Random weight:** 1

```text
Flip the `xray-rust` pin to `test_enabled = true` with `dovetail_binary = "dovetail-zeronet"` and the suite command its interop tests need, injected via `XRAY_VLESS_FULL_BINARY` — the seam the pinned tree already reads. The binary already answers `run -config`; what was missing was the `REALITY` behavior P9 owns, so this slice contains no transport code, only the flip and the per-test report by name. A subset that passes is a subset.
```

## P17 · Timing benchmarks for protocol framings

**When to use:** When a protocol rung needs a wall-clock comparison and only has counts: VMess sealed/open throughput has no timed reference anywhere, only the exact-size assertions in `crates/dovetail-zeronet/src/vmess.rs` (`frames_seal_to_stable_bytes`, `seal_open_round_trips_every_length_and_cipher`), so a framing change that keeps sizes identical while adding passes is invisible.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Gates:** CI: `bench.yml` green with a protocol framing section that fails on regression on every runner in the matrix; `cargo test --workspace`
**Touches:** crates/dovetail-bench/src/main.rs, .github/workflows/bench.yml
**Random weight:** 1

```text
Give the protocol framings a wall-clock comparison with a reference on every ISA runner, the way gate 3 compares the record layer against the chacha20 crate. The obstacle is structural and decided first: framing lives in application crates a bench crate cannot import, and no same-language reference exists for VMess AEAD framing, so this slice decides where the timed code lives and what it is measured against, then gates it with gate 3's remeasure discipline. Counts (the exact-size assertions in `crates/dovetail-zeronet/src/vmess.rs`) catch added copies; only timing catches added passes at equal size. Until then the claim stays the narrowed one `docs/claims.md` makes: bit-identical framing with exact sizes, no speed claim.
```

## P18 · VMess over the ws carrier

**When to use:** When `vmess_over_websocket` is the last `xray_oracle` failure against this binary: it expects a `vmess` listener behind a `ws` carrier and gets a connection closed after the first byte.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with `vmess_over_websocket_matches_the_oracle` executed against `dovetail-zeronet`
**Touches:** crates/dovetail-zeronet/src/vmess.rs, crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 2

```text
Carry `VMess` inside the `ws` carrier P14 already built, in both roles, rather than a second carrier: the handshake and the framing are `crate::ws`'s, and the bytes inside them are `crate::vmess`'s, unchanged. Then every `xray_oracle` test is either enabled or named, and the sentence in `docs/conformance.md` that lists the failures can go rather than be maintained.

The `VMess` header is a hundred bytes of sealed material behind a timestamp, so this is also the first carrier that carries a header rather than a fixed-size prologue: read it to the byte, never to the packet. A carrier that hands the protocol a short read is a hang wearing a successful handshake.
```

## P19 · Name the two matrix rows the serving roles already earned

**When to use:** Whenever a protocol role lands and the README connection-methods matrix still describes it as planned: rows 5 and 7 still read `planned` while the raw-`TCP` `trojan` and `shadowsocks` rungs are green in `conformance.yml`. Row 6 was flipped against run `37122185418`, which is the shape to copy.
**Status:** done
**Leverage:** 2
**Effort:** small
**Gates:** CI: `ci.yml` green; `conformance.yml` green with `trojan_over_raw_tcp_matches_the_oracle` and `shadowsocks_over_raw_tcp_matches_the_oracle` executed against `dovetail-zeronet`
**Touches:** README.md, docs/arch/superset.md
**Random weight:** 1

```text
Flip rows 5 and 7, and put the run that proves each one in the cell rather than the word `implemented`. A cell that says `implemented` names no run and is checked by nobody; a cell that says `implemented (conformance 37122185418)` is a claim with a citation, and the citation is the thing that goes red when the claim stops being true.

Name the limit in the cell too, the way row 6 does: both of these are raw `TCP` with one cipher each and no `UDP`, so a reader who needs the `2022` or the `UDP` half knows from the table rather than from the source.
```

## P20 · Make the gRPC loopback test stop failing one run in nine

**When to use:** Now, and before the next slice reads a red `cargo test --workspace` as its own: `grpc::tests::tunnel_carries_an_echo_over_loopback` failed 23 times in 200 runs of that one test with nothing else running, measured on a tree whose `grpc.rs` no slice in flight had touched. `grpc.rs` is not the next slice's business; the measurement is.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace` green on three consecutive runs; a loop of the single test over 200 runs with zero failures, printed by the test or the script rather than remembered
**Touches:** crates/dovetail-zeronet/src/grpc.rs
**Random weight:** 2

```text
Find it with the trace rather than by reading, because reading says nothing about which of the two ends loses the frame. Instrument `read_head`, `read_body`, `emit` and `write_frame` with the peer's address, then loop the test until it fails. A failing run prints this, and the last two lines are the whole bug: the client reads the nine header bytes of the `pong` `DATA` frame and then `read_body` sees end of stream, so a frame header arrived without its body. That is a torn write or a reset with data in the receive queue, not a framing error, and the fix is whichever of the two it turns out to be.

Then make the test able to fail *deterministically*, because a test that fails one run in nine teaches the next contributor to re-run CI instead of reading it. A loopback test that needs a real socket to lose a race is testing the scheduler; the same assertion over an in-memory stream or a frame buffer fails every time it is wrong and never flakes.

Report the before and after as a rate over a stated number of runs. "Fixed" is not a rate.
```

## P21 · Take the third copy of the config and address walks out of `proxy.rs`

**When to use:** When the next slice touches a protocol role: `find_vless_outbound` (`crates/dovetail-zeronet/src/proxy.rs:801`) and `find_vmess_outbound` (`:839`) walk the same `outbounds` → `settings.vnext[0]` → `users[0]` shape in two nearly identical loops, `shadowsocks::parse_addr_header` (`shadowsocks.rs:251`) and `vmess::decode_target` (`vmess.rs:592`) parse the same address triple in two orders, and `inbound_id` (`:672`) and `inbound_password` (`:717`) each walk `settings.clients[0]` themselves.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with the enabled `zeronet` subset executed against `dovetail-zeronet`
**Touches:** crates/dovetail-zeronet/src/proxy.rs, crates/dovetail-zeronet/src/shadowsocks.rs, crates/dovetail-zeronet/src/vmess.rs
**Random weight:** 2

```text
One `vnext` walker, one inbound-client reader, one in-memory address parser with each caller reading the port where its own wire format puts it — `shadowsocks` after the address, `VMess` before it — and nothing else changes. The proof is the enabled suite plus the workspace tests: a refactor that alters a byte on any wire is not a refactor, and `conformance.yml` is what says so.

Do not take the opportunity to shrink `vmess.rs` itself. It is 1,014 lines of code against a from-scratch equivalent written to this same prompt at 880, but it carries all four data ciphers where that one carried one, and a slice that trades capability for lines is a different slice with its own differential proof. If the smaller form is wanted, it is its own PR against the oracle, not a line count argued here.
```

## P22 · Make the gRPC carrier agree with both oracles

**When to use:** When the measurement in `docs/conformance.md` is the reason a `gRPC` row is red: `vless_over_grpc_matches_the_oracle` is green against `ZeroNet`'s `xray_oracle` and `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc` fails against `xray-rust`, so one carrier has two verdicts and P15 called it done on the first one.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc`, `rust_socks_client_reads_a_server_greeting_through_local_xray_vless_grpc` and `rust_socks_client_streams_bulk_echo_through_local_xray_vless_grpc_multi_mode` added to the enabled `xray-rust` suite command and executed unmodified
**Depends on:** P15
**Touches:** crates/dovetail-zeronet/src/grpc.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 2

```text
`grpc.rs` currently answers `ZeroNet`'s oracle and not `xray-rust`'s, both measured in `conformance.yml` run `37125321800`: the plain-`gRPC` row fails with `read echo failed: early eof`, the server-speaks-first row with `read greeting: early eof`, and the multi-mode bulk row with `Connection reset by peer`. Three failures, one carrier, two oracles — so the framing is narrower than both rather than wrong, and the narrower half is whatever `ZeroNet`'s oracle does not send.

Read both pinned implementations for what the other one sends: `upstream/xray-core/transport/internet/grpc/` and `upstream/xray-rust/crates/xray-transport/src/stream/grpc/`, then `upstream/zeronet/crates/zero-transport/src/grpc.rs`. The three named tests are the specification; add each to the `xray-rust` suite command in `upstream/pins.toml` only as it goes green, and keep `vless_over_grpc_matches_the_oracle` in the `zeronet` command so a fix that breaks the other oracle is caught by the same run. A carrier that passes one suite because the other was never run is the failure this slice exists to end.
```

## P23 · Serve the early-data rows the two `ws` oracles never asked for

**When to use:** When `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_early_data` and `rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade_early_data` are red while their non-early-data twins went green in P14 and P15: neither of the two enabled oracles sends early data, so two rows shipped with no suite behind them.
**Status:** todo
**Leverage:** 2
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with both early-data tests added to the enabled `xray-rust` suite command and executed unmodified
**Depends on:** P15
**Touches:** crates/dovetail-zeronet/src/ws.rs, crates/dovetail-zeronet/src/httpupgrade.rs, upstream/pins.toml
**Random weight:** 1

```text
Early data is the payload that arrives in the same write as the upgrade request, before the `101`. `ws.rs` reads it out of `sec-websocket-protocol` on accept and `httpupgrade.rs` does not carry it at all; measured in `conformance.yml` run `37125321800`, the `ws` row fails with `read echo failed: early eof` and the `httpupgrade` row with `socks connect rejected: [5, 1, 0, 1]`. The two fail differently, so they are two halves of one missing behaviour rather than one bug seen twice.

Read how each implementation carries it before writing it: `upstream/xray-core/transport/internet/websocket/` and `httpupgrade/` in the same tree, `upstream/xray-rust/crates/xray-transport/src/stream/` under `websocket.rs` and `httpupgrade.rs`, then `upstream/zeronet/crates/zero-transport/src/ws/` and `httpupgrade.rs`. Where the four disagree on who masks, who chunks, or who closes, say which you followed and why — an early-data carrier that works against one client and silently truncates against another is worse than one that refuses it.
```

## P24 · Answer the xhttp rows, including the one that needs a file it is not given

**When to use:** When `rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases` and `rust_socks_client_reaches_target_through_remote_xhttp_profile` are the last two red rows in the `xray-rust` table and the second of them fails before it connects, on `XRAY_REMOTE_XHTTP_CONFIG must name an owner-only file`.
**Status:** todo
**Leverage:** 2
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with `rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases` added to the enabled `xray-rust` suite command and executed unmodified
**Depends on:** P15
**Touches:** crates/dovetail-zeronet/src/proxy.rs, upstream/pins.toml, docs/conformance.md
**Random weight:** 1

```text
`xhttp` is the one carrier in this tree with no implementation at all, so `dovetail-zeronet` serves a `network: xhttp` inbound as raw `TCP` and the bulk flow dies with `Connection reset by peer` — measured in `conformance.yml` run `37125321800`. P15 named it as out of scope and said it gets its own; this is that.

The second row is a different kind of problem and must be settled before the first is claimed. `rust_socks_client_reaches_target_through_remote_xhttp_profile` reads its profile through `read_owner_only_text_from_env`, which panics unless `XRAY_REMOTE_XHTTP_CONFIG` names a regular file with no group or other bits — so a suite command that runs it has to write that file and set its mode, and `scripts/check-fixture-safety.sh` governs the committed tree, not a file the harness writes at run time. Answer that first: if the fixture cannot be produced from the harness without weakening the mode assertion the pinned tree ships, say so and leave the row named here rather than editing their test.

Read `upstream/xray-core/transport/internet/splithttp/` and `upstream/xray-rust/crates/xray-transport/src/stream/xhttp/`, then `upstream/zeronet/crates/zero-transport/src/xhttp.rs` and `xhttp_request.rs`, and implement the narrowest form that carries one `VLESS` request and one response. `xhttp` moves the payload across several HTTP requests with padding and placement rules per mode; a slice that implements one mode and names it is further along than a slice that stubs the carrier and reports the row green.
```

## Reading this file as a roadmap

The graph is the point, and it is not a decoration: `dovetail-prompt next` ranks ready slices by leverage, breaks ties towards the smaller one, leaves out the ones waiting on a decision, and reports what each slice unblocks. `P15` is ahead of everything because three of the remaining slices wait on it, which is the kind of thing that is obvious once and invisible otherwise.

Numbers do not go in prose here. This file's gate checks structure — ids, dependencies, files, gates — and a sentence saying "eleven of fourteen" is a claim no check can keep, so the counts live in fields and `dovetail-prompt list` prints them.

Rotate with `dovetail-prompt next --rotate` when the ranking is not the question you are asking. It draws from ready slices only, weighted by `**Random weight:**`, and records the draw in `.dovetail/slices.log` so the next few calls do not offer the same slice twice.

Statuses are the only field a contributor edits to record progress. Mark a slice `done` when its gates are green, not when its diff is finished: the gates are what the next contributor is entitled to trust.
