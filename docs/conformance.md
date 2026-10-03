# Conformance: all of their tests, enabled gradually

This project becomes a drop-in replacement (Goal 2) by running upstream suites *against* Dovetail binaries in CI — never by copying them here. sing-box is GPL-3.0, Xray-core / xray-rust are MPL-2.0 and PattNG / Aether are GPL-3.0 / AGPL-3.0; copying their tests would make this work's licence undecidable. Running them unmodified is both licence-clean and a stronger claim than a hand-rewritten vector. **Two of the twelve do that against this workspace**, both against `dovetail-zeronet` through their own seam: `zeronet` runs 7 of the 17 `#[ignore]`d tests in `xray_oracle`, `xray-rust` runs 5 of the 23 in `local_xray_interop_tests`, checked by `conformance.yml`. The ten pins with no seam do not, each for the named reason below.

## The rule

Each source in `upstream/pins.toml` carries `test_enabled`:

- `true` — its suite runs in CI on every push (`ci.yml` / `conformance.yml`).
- `false` — the CI job is created, skips, and prints the reason (unimplemented rung). Skipped is visible; absent would be silent.

A suite flips to `true` only when:

1. its transport rung reports `Support::Implemented`,
2. the differential proof for that rung is green at every length and offset,
3. the benchmark gate for that rung is green on all four ISA runners.

Ten entries are disabled and two (`zeronet`, `xray-rust`) are enabled: `xray-core` stays disabled because its suite runs upstream code only with no Dovetail binary wired yet, and `run-upstream-suite.sh` fails an enabled entry with none rather than printing PASS.

## What each suite is missing, measured

The honest count is **2 of 12 suites run against a Dovetail binary**, checked by `conformance.yml`. Reading the fetched trees at each pin for a point where an external binary could be injected — an environment variable naming a binary, which is the only shape a suite can be pointed at without editing it — gives:

| suite | pin | seam at that rev | what the seam demands of our binary |
| ----- | --- | --------------- | ------------------------------------ |
| xray-core | `b26a91de` | none | `./proxy/vless/...` is in-process Go; 0 `os/exec` in the package |
| sing-box | `c9922979` | none | no `*_test.go` under `protocol/shadowsocks` or `protocol/vless`; crypto is the out-of-tree `sagernet/sing-shadowsocks2` |
| amneziawg-go | `b5928efb` | none | `device/*_test.go` are in-process; the TUN path needs root |
| amnezia-client | `94b51df2` | none | C++/Qt; test material is Conan-installed, no binary harness |
| xray-rust | `7a4fb2dd` | `XRAY_VLESS_FULL_BINARY` | `run -config <file>`, `x25519`, and a VLESS **server** that listens |
| pattng | `ad6f747c` | none | Android/Gradle; the binary name is a `.so` constant, not an injection point |
| zeronet | `97a99734` | `ZRAY_XRAY_BINARY` | `version`, `run -c <file>`, `x25519`, `vlessenc`, and a VLESS **server** |
| mqvpn | `b11a2f69` | none | C `ctest` plus netns E2E; no env binary seam |
| aether | `21e7150a` | none | Rust CLI (`--masque` / `--wg` / `--gool` / `--mim`); no env binary seam — pinned directly, not via PattNG's `.so` |
| zeptun | `5620e57c` | none | `zig build test` plus netns integration; no env binary seam |
| slipstream | `397850b1` | none | client/server CLIs over DNS; no env binary seam |
| quiche | `3fc9bc1c` | none | library (QUIC + HTTP/3); no suite to inject into — the stack the rungs dial through |

Two of twelve have a seam, and both are the same shape: each spawns the binary as `run -config <file>` and waits for it to listen, so `dovetail-zeronet` needs a **server** role. It has one now — `version`, `x25519`, and `run -c` serving `vless`, `trojan`, `vmess`, `shadowsocks` and `socks` inbounds over raw `TCP`, `ws`, `httpupgrade` and `grpc` (`crates/dovetail-zeronet/src/proxy.rs`). What it does not yet read is `streamSettings.security`, so a `tls` or `reality` inbound is served in the clear: that one missing lookup is why 11 of the 18 failures below are `TLS`/`REALITY` rows.

`run-upstream-suite.sh` checks this rather than trusting the pin: it refuses a `PASS` for a suite with no `dovetail_binary`, refuses one whose `seam` is absent, and refuses one whose declared `seam` the pinned tree never reads. Building a binary and not executing it is the failure mode those three checks exist to catch.

## Current state

| suite | pin | enabled | reason |
| ----- | --- | ------- | ------ |
| xray-core record/crypto | `b26a91de` | ❌ false | no seam at that rev: the suite is in-process Go, so no binary can be injected |
| sing-box crypto | `c9922979` | ❌ false | no seam; and no `_test.go` under `protocol/shadowsocks` or `protocol/vless` to run |
| amneziawg-go noise | `b5928efb` | ❌ false | no seam; `device/*_test.go` are in-process and the TUN path needs root |
| amnezia-client crypto | `94b51df2` | ❌ false | no seam; C++/Qt, test material is Conan-installed |
| xray-rust | `7a4fb2dd` | ✅ true | seam `XRAY_VLESS_FULL_BINARY` exists; runs 5 of the 23 `#[ignore]`d tests in `local_xray_interop_tests` that pass unmodified against `dovetail-zeronet` — the plain-`TCP` `VLESS` server trio plus the `ws` and `httpupgrade` carriers — checked by `conformance.yml`; the other 18 are named with their measured failure below |
| PattNG (v2rayNG fork) | `ad6f747c` | ❌ false | no seam; Android/Gradle, and the unsafe rows need `UnsafeOptIn` first |
| ZeroNet / Zray | `97a99734` | ✅ true | seam `ZRAY_XRAY_BINARY` exists; runs the raw-`TCP` `VLESS`, `trojan`, `shadowsocks` and `vmess` plus `VLESS`-over-`WebSocket`, `HTTPUpgrade` and `gRPC` subset against `dovetail-zeronet`, checked by `conformance.yml` |
| mqvpn MASQUE/MP-QUIC | `b11a2f69` | ❌ false | no seam; `ctest` plus netns E2E need root and a live server pair |
| Aether WARP core | `21e7150a` | ❌ false | no seam; open-source Rust core pinned directly — PattNG's `.so` is that core vendored, this pin is the source |
| zeptun tun2socks | `5620e57c` | ❌ false | no seam; `zig build test` plus TUN/netns integration, no proxy harness to inject |
| slipstream DNS tunnel | `397850b1` | ❌ false | no seam; client/server over DNS need a domain delegation, not a binary swap |
| quiche QUIC/H3 | `3fc9bc1c` | ❌ false | no seam; library only — compared by differential benchmark once a QUIC rung dials |

The other two `xray_oracle` tests fail against this binary, each measured in `conformance.yml` run `37100395876` with no file edited: `trojan_over_websocket` and `vmess_over_websocket` expect a `WS` carrier for their protocol and get none — the binary serves those protocols over raw `TCP` only. Those two stay out of the enabled suite command until their rung lands; a subset that passes is a subset.

## Every `xray-rust` interop test, by name

`local_xray_interop_tests` at `7a4fb2dd` holds 23 `#[ignore]`d tests; all 23 use the `XRAY_VLESS_FULL_BINARY` seam to run `dovetail-zeronet` as the `VLESS` **server**, and the `Rust` core or the pinned `Xray-core` build as the client. Widening the pin's `suite` to all 23 measured the rest in `conformance.yml` run `37125321800` on `ubuntu-latest`: **5 passed, 18 failed**, 41.6s. The five that pass are the enabled suite command; the eighteen are named here with the assertion each one died on, so the gap is a list rather than a shrug. None of the eighteen was fixed by this slice.

| test | verdict | measured failure | owner |
| ---- | ------- | ----------------- | ----- |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp` | ✅ | — | P19 |
| `rust_round_robin_balancer_uses_each_local_xray_vless_member` | ✅ | — | P29 |
| `rust_two_hop_proxy_chain_reaches_echo_through_local_xray_vless_servers` | ✅ | — | P29 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws` | ✅ | — | P27 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade` | ✅ | — | P28 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_tls` | ❌ | `socks connect rejected: [5, 1, 0, 1]` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_tls_vision` | ❌ | `socks connect rejected: [5, 1, 0, 1]` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision_selected_fingerprints` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P15 |
| `inner_tls_session_survives_vision_direct_switch_through_local_xray_reality_vision` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P15 |
| `rust_socks_clients_open_parallel_echo_flows_through_local_xray_vless_reality_vision_selected_fingerprints` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P15 |
| `xray_core_socks_clients_open_parallel_echo_flows_through_local_xray_vless_reality_vision_selected_fingerprints` | ❌ | `Xray-core client REALITY warmup probe failed: … Connection reset by peer` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_tls` | ❌ | `socks connect timeout: deadline has elapsed` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade_tls` | ❌ | `socks connect timeout: deadline has elapsed` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc_tls` | ❌ | `socks connect rejected: [5, 1, 0, 1]` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc_reality` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_early_data` | ❌ | `read echo failed: early eof` | P37 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade_early_data` | ❌ | `socks connect rejected: [5, 1, 0, 1]` | P37 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc` | ❌ | `read echo failed: early eof` | P36 |
| `rust_socks_client_reads_a_server_greeting_through_local_xray_vless_grpc` | ❌ | `read greeting: early eof` | P36 |
| `rust_socks_client_streams_bulk_echo_through_local_xray_vless_grpc_multi_mode` | ❌ | `bulk echo failed: read bulk echo: Connection reset by peer` | P36 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases` | ❌ | `XHTTP bulk flow failed: read XHTTP bulk echo: Connection reset by peer` | P38 |
| `rust_socks_client_reaches_target_through_remote_xhttp_profile` | ❌ | `XRAY_REMOTE_XHTTP_CONFIG must name an owner-only file` | P38 |

Three readings the table supports and a "TLS and `REALITY` are missing" summary does not:

- **`gRPC` passes one oracle and fails the other.** `vless_over_grpc_matches_the_oracle` is green against `ZeroNet`'s `xray_oracle`, and `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc` fails here with `early eof`. Two oracles, one carrier, two verdicts: the framing agrees with `ZeroNet` and not with `xray-rust`, so the carrier is not wrong, it is narrower than both. P36.
- **`ws` and `httpupgrade` without `TLS` are green; their early-data rows are not.** No oracle here exercises early data, so P27 and P28 shipped rows no suite tested. P37.
- **One failure is a harness requirement, not a transport gap.** `rust_socks_client_reaches_target_through_remote_xhttp_profile` asserts before it connects: it wants `XRAY_REMOTE_XHTTP_CONFIG` to name an owner-only file, which the suite command does not and should not write. P38 has to answer that before the row means anything.

### `--exact` is load-bearing, and CI is what notices

Narrowing this pin's `suite` from all 23 names to the 5 that pass still ran 9 tests, because `libtest` filters by substring: naming `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws` also runs `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_tls` and `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_early_data`, and naming `..._httpupgrade` also runs its `_tls` and `_early_data` siblings (run `37126222488`: `5 passed; 4 failed; 21 filtered out`, where 4 rows failed that the pin never named). `--exact` makes each filter an exact match, and the run now reports `5 passed; 0 failed`.

The trap waits for any pin whose enabled names are prefixes of disabled ones, so the check is a count, not a word: a suite command that names `N` tests is only doing what it says if the `running N tests` line above it says `N` too. The `zeronet` command's seven names happen not to prefix each other, and every conformance run prints `running 7 tests` beside them — that is the check on it, and it is the check a future row must satisfy before it joins either command.

The ten pins with no seam were each read for a socket-taking harness instead — a test that dials an address the suite takes from the environment, which is the only shape usable without editing it — and none has one, measured against the fetched trees: `xray-core` `proxy/vless` tests never call `os/exec` or read the environment for a binary; `sing-box` has no `_test.go` under `protocol/shadowsocks` or `protocol/vless` at all; `amneziawg-go` `device` tests are in-process with no `os/exec`; `amnezia-client` tests are `C++`/`Qt` model tests with no proxy harness; `pattng` names its core as `.so` constants (`libaether.so`), not an injectable path — but that core is open source and is now pinned directly as `aether`, so its transports are covered there rather than through PattNG; `mqvpn` tests are `ctest` plus netns E2E with no env address harness; `aether` is a CLI without a socket-taking test harness; `zeptun` tests are unit plus TUN/netns integration with no proxy harness; `slipstream` client/server need a DNS delegation, not a dial address; `quiche` is a library with no suite to inject into. Driving any of them without its rung would mean editing their tests, which is inventing a runner outside their test rather than running it.

## Adding a suite

Add the pin with `test_enabled = false`, add the CI job that skips with the rung reason, and open the flip to `true` as its own PR with the differential proof attached. A conformance PR without the proof is closed — same as an `unsafe` PR without one. The flip must also set `dovetail_binary` to a binary the suite command executes; `run-upstream-suite.sh` fails the job otherwise, checked by `conformance.yml`.
