# Conformance: all of their tests, enabled gradually

This project becomes a drop-in replacement (Goal 2) by running upstream suites *against* Dovetail binaries in CI — never by copying them here. sing-box is GPL-3.0 and Xray-core / xray-rust are MPL-2.0; copying their tests would make this work's licence undecidable. Running them unmodified is both licence-clean and a stronger claim than a hand-rewritten vector. **No suite does that against this workspace yet**: all seven entries skip — each would run upstream's own tests in a clone, which checks the pin rather than these binaries, and none wires a Dovetail binary. The first wiring is P19, still `todo`; what would have to exist is a `dovetail-zeronet` VLESS listener plus a fixture driving one upstream VLESS case against it over loopback.

## The rule

Each source in `upstream/pins.toml` carries `test_enabled`:

- `true` — its suite runs in CI on every push (`ci.yml` / `conformance.yml`).
- `false` — the CI job is created, skips, and prints the reason (unimplemented rung). Skipped is visible; absent would be silent.

A suite flips to `true` only when:

1. its transport rung reports `Support::Implemented`,
2. the differential proof for that rung is green at every length and offset,
3. the benchmark gate for that rung is green on all four ISA runners.

All seven entries are currently disabled, so the rule holds vacuously: `xray-core` stays disabled because its suite runs upstream code only with no Dovetail binary wired yet, and `run-upstream-suite.sh` fails an enabled entry with none rather than printing PASS.

## What each suite is missing, measured

The honest count is **0 of 7 suites run against a Dovetail binary**. Reading the fetched trees at each pin for a point where an external binary could be injected — an environment variable naming a binary, which is the only shape a suite can be pointed at without editing it — gives:

| suite | pin | seam at that rev | what the seam demands of our binary |
| ----- | --- | --------------- | ------------------------------------ |
| xray-core | `b26a91de` | none | `./proxy/vless/...` is in-process Go; 0 `os/exec` in the package |
| sing-box | `c9922979` | none | no `*_test.go` under `protocol/shadowsocks` or `protocol/vless`; crypto is the out-of-tree `sagernet/sing-shadowsocks2` |
| amneziawg-go | `b5928efb` | none | `device/*_test.go` are in-process; the TUN path needs root |
| amnezia-client | `94b51df2` | none | C++/Qt; test material is Conan-installed, no binary harness |
| xray-rust | `7a4fb2dd` | `XRAY_VLESS_FULL_BINARY` | `run -config <file>`, `x25519`, and a VLESS **server** that listens |
| pattng | `ad6f747c` | none | Android/Gradle; the binary name is a `.so` constant, not an injection point |
| zeronet | `97a99734` | `ZRAY_XRAY_BINARY` | `version`, `run -c <file>`, `x25519`, `vlessenc`, and a VLESS **server** |

Two of seven have a seam. Both require a **server** role — `zray_client_to_xray_server` and `xray_client_to_zray_server` each spawn the binary as `run -c <config>` and wait for it to listen — where `dovetail-zeronet` today parses a `vless://` link, prints its `Support`, TCP-connects, and sends nothing (`crates/dovetail-zeronet/src/main.rs`). It answers no `version`, no `-c`, and no `x25519`, so there is no subcommand to point a seam at yet.

`run-upstream-suite.sh` checks this rather than trusting the pin: it refuses a `PASS` for a suite with no `dovetail_binary`, refuses one whose `seam` is absent, and refuses one whose declared `seam` the pinned tree never reads. Building a binary and not executing it is the failure mode those three checks exist to catch.

## Current state

| suite | pin | enabled | reason |
| ----- | --- | ------- | ------ |
| xray-core record/crypto | `b26a91de` | ❌ false | no seam at that rev: the suite is in-process Go, so no binary can be injected |
| sing-box crypto | `c9922979` | ❌ false | no seam; and no `_test.go` under `protocol/shadowsocks` or `protocol/vless` to run |
| amneziawg-go noise | `b5928efb` | ❌ false | no seam; `device/*_test.go` are in-process and the TUN path needs root |
| amnezia-client crypto | `94b51df2` | ❌ false | no seam; C++/Qt, test material is Conan-installed |
| xray-rust | `7a4fb2dd` | ❌ false | seam `XRAY_VLESS_FULL_BINARY` exists; needs a VLESS **server** subcommand and `x25519` |
| PattNG (v2rayNG fork) | `ad6f747c` | ❌ false | no seam; Android/Gradle, and the unsafe rows need `UnsafeOptIn` first |
| ZeroNet / Zray | `97a99734` | ❌ false | seam `ZRAY_XRAY_BINARY` exists; needs `version`, `run -c`, `x25519`, `vlessenc` and a VLESS **server** |

## Adding a suite

Add the pin with `test_enabled = false`, add the CI job that skips with the rung reason, and open the flip to `true` as its own PR with the differential proof attached. A conformance PR without the proof is closed — same as an `unsafe` PR without one. The flip must also set `dovetail_binary` to a binary the suite command executes; `run-upstream-suite.sh` fails the job otherwise, checked by `conformance.yml`.
