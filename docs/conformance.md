# Conformance: all of their tests, enabled gradually

This project becomes a drop-in replacement (Goal 2) by running upstream suites *against* Dovetail binaries in CI — never by copying them here. sing-box is GPL-3.0 and Xray-core / xray-rust are MPL-2.0; copying their tests would make this work's licence undecidable. Running them unmodified is both licence-clean and a stronger claim than a hand-rewritten vector. **One suite does that against this workspace**: `zeronet` runs its `xray_oracle` raw-`TCP` `VLESS` differential against `dovetail-zeronet`, checked by `conformance.yml`; the other eight oracle tests and the other six pins do not, each for the named reason below.

## The rule

Each source in `upstream/pins.toml` carries `test_enabled`:

- `true` — its suite runs in CI on every push (`ci.yml` / `conformance.yml`).
- `false` — the CI job is created, skips, and prints the reason (unimplemented rung). Skipped is visible; absent would be silent.

A suite flips to `true` only when:

1. its transport rung reports `Support::Implemented`,
2. the differential proof for that rung is green at every length and offset,
3. the benchmark gate for that rung is green on all four ISA runners.

Six entries are disabled and one (`zeronet`, raw-`TCP` `VLESS` only) is enabled: `xray-core` stays disabled because its suite runs upstream code only with no Dovetail binary wired yet, and `run-upstream-suite.sh` fails an enabled entry with none rather than printing PASS.

## What each suite is missing, measured

The honest count is **1 of 7 suites run against a Dovetail binary**, checked by `conformance.yml`. Reading the fetched trees at each pin for a point where an external binary could be injected — an environment variable naming a binary, which is the only shape a suite can be pointed at without editing it — gives:

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
| ZeroNet / Zray | `97a99734` | ✅ true | seam `ZRAY_XRAY_BINARY` exists; runs the raw-`TCP` `VLESS` plus `trojan` subset against `dovetail-zeronet`, checked by `conformance.yml` |

The other seven `xray_oracle` tests fail against this binary, each measured in `conformance.yml` run `37100395876` with no file edited: `trojan_over_websocket`, `vmess_over_raw_tcp`, `vmess_over_websocket` and `shadowsocks_over_raw_tcp` expect a `vmess`/`shadowsocks` listener and get none — the binary exits 1 on the unknown inbound; `vless_over_websocket` and `vless_over_http_upgrade` expect a `WS`/`HTTPUpgrade` handshake and get the connection closed after the first byte; `vless_over_grpc_matches_the_oracle` expects `gRPC` framing and times out waiting for the echo. Those seven stay out of the enabled suite command until their rung lands; a subset that passes is a subset.

The five pins with no seam were each read for a socket-taking harness instead — a test that dials an address the suite takes from the environment, which is the only shape usable without editing it — and none has one, measured against the fetched trees: `xray-core` `proxy/vless` tests never call `os/exec` or read the environment for a binary; `sing-box` has no `_test.go` under `protocol/shadowsocks` or `protocol/vless` at all; `amneziawg-go` `device` tests are in-process with no `os/exec`; `amnezia-client` tests are `C++`/`Qt` model tests with no proxy harness; `pattng` names its core as `.so` constants (`libaether.so`), not an injectable path. Driving any of them would mean editing their tests, which is inventing a runner outside their test rather than running it.

## Adding a suite

Add the pin with `test_enabled = false`, add the CI job that skips with the rung reason, and open the flip to `true` as its own PR with the differential proof attached. A conformance PR without the proof is closed — same as an `unsafe` PR without one. The flip must also set `dovetail_binary` to a binary the suite command executes; `run-upstream-suite.sh` fails the job otherwise, checked by `conformance.yml`.
