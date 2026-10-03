# Conformance: all of their tests, enabled gradually

This project becomes a drop-in replacement (Goal 2) by running upstream suites *against* Dovetail binaries in CI — never by copying them here. sing-box is GPL-3.0 and Xray-core / xray-rust are MPL-2.0; copying their tests would make this work's licence undecidable. Running them unmodified is both licence-clean and a stronger claim than a hand-rewritten vector. **One suite does that against this workspace**: `zeronet` runs all seventeen of its `xray_oracle` tests, unedited, against `dovetail-zeronet`; **two pass and fifteen fail, each named below**, measured by `conformance.yml` run `37101909935`. The other six pins run no Dovetail binary at all, each for the reason its own pin carries.

## The rule

Each source in `upstream/pins.toml` carries `test_enabled`:

- `true` — its suite runs in CI on every push (`ci.yml` / `conformance.yml`).
- `false` — the CI job is created, skips, and prints the reason (unimplemented rung). Skipped is visible; absent would be silent.

An enabled entry therefore carries two things, not one. `suite` is the whole unmodified upstream command and it runs in full — every test, no name filter. `gate_tests` names the subset allowed to be red while the job stays green, because a rung that has not landed cannot pass a differential it does not implement. `run-upstream-suite.sh` prints every verdict, fails when a gate test did not pass, and fails when a test passed that the gate does not name, so the count in the table below cannot drift without a commit that says so. A run that printed no per-test verdict at all fails closed: nothing measured is nothing proven.

A suite flips to `true` only when:

1. its transport rung reports `Support::Implemented`,
2. the differential proof for that rung is green at every length and offset,
3. the benchmark gate for that rung is green on all four ISA runners.

Six entries are disabled and one (`zeronet`, whose gate is the two tests named in its table) is enabled: `xray-core` stays disabled because its suite runs upstream code only with no Dovetail binary wired yet, and `run-upstream-suite.sh` fails an enabled entry with none rather than printing PASS.

## What each suite is missing, measured

The honest count is **1 of 7 suites run against a Dovetail binary**, checked by `conformance.yml`. Reading the fetched trees at each pin for a point where an external binary could be injected — an environment variable naming a binary, which is the only shape a suite can be pointed at without editing it — gives:

| suite | pin | seam at that rev | what the seam demands of our binary |
| ----- | --- | --------------- | ------------------------------------ |
| xray-core | `b26a91de` | none | `./proxy/vless/...` is in-process Go; 0 `os/exec` in the package |
| sing-box | `c9922979` | none | no `*_test.go` under `protocol/shadowsocks` or `protocol/vless`; crypto is the out-of-tree `sagernet/sing-shadowsocks2` |
| amneziawg-go | `b5928efb` | none | `device/*_test.go` are in-process; the TUN path needs root |
| amnezia-client | `94b51df2` | none | C++/Qt; test material is Conan-installed, no binary harness |
| xray-rust | `7a4fb2dd` | `XRAY_VLESS_FULL_BINARY` | `run -config <file>` and `x25519`, for the **server** half of each interop test — its client half always `go build`s the checkout and never reads the variable |
| pattng | `ad6f747c` | none | Android/Gradle; the binary name is a `.so` constant, not an injection point |
| zeronet | `97a99734` | `ZRAY_XRAY_BINARY` | `version`, `run -c <file>`, `x25519`, `vlessenc`, and a VLESS **server** |

Two of seven have a seam, and both spawn the substitute as `run -c <config.json>` and wait for it to *listen*. `dovetail-zeronet` answers all four calls (`crates/dovetail-zeronet/src/proxy.rs`): `version`, `x25519` in the labels the oracle parses, and `run -c <file>` binding each `vless` and `socks` inbound, serving `VLESS`/`TCP`, relaying both ways and answering `[0, 0]`. It does not answer `vlessenc`, which is one of the failures named below.

`run-upstream-suite.sh` checks this rather than trusting the pin: it refuses a `PASS` for a suite with no `dovetail_binary`, refuses one whose `seam` is absent, and refuses one whose declared `seam` the pinned tree never reads. Building a binary and not executing it is the failure mode those three checks exist to catch.

## What the zeronet oracle measures, by name

`crates/zero-runtime/tests/xray_oracle.rs` at `97a99734` holds **seventeen** `#[ignore]`d differential tests — nine written by one macro invocation, eight written out longhand. All seventeen run in `conformance.yml` run `37101909935` against `dovetail-zeronet` through `ZRAY_XRAY_BINARY`, with no upstream file edited. Before that run the suite command was narrowed to one test name, so the eight longhand tests had never been executed and the count was reported as nine; run `37100395876` shows the narrowing's own arithmetic, `1 passed; 8 failed; 8 filtered out`.

| test at `97a99734` | verdict | why, from that run's log |
| -------------------- | ------- | ------------------------- |
| `vless_over_raw_tcp_matches_the_oracle` | **pass** | both directions of raw-`TCP` `VLESS` round trip through our listener |
| `a_wrong_reality_public_key_is_refused_rather_than_silently_relayed` | **pass** | our server closes instead of relaying, which is what the test demands; it can also pass for the wrong reason, since a binary that speaks no `REALITY` at all satisfies it trivially |
| `vless_over_reality_raw_tcp_matches_the_oracle` | fail | `socks_connect` returns `Err`: we serve plain `VLESS` where a `REALITY` server is expected |
| `vless_vision_over_reality_matches_the_oracle` | fail | the same, with `Vision` on top |
| `vless_over_websocket_matches_the_oracle` | fail | `early eof` at the `WebSocket` handshake |
| `vless_over_http_upgrade_matches_the_oracle` | fail | `early eof` at the `HTTPUpgrade` handshake |
| `vless_over_grpc_matches_the_oracle` | fail | `early eof` waiting for the echo |
| `xhttp_requests_match_the_oracle` | fail | `early eof` waiting for the echo, first of seven cases |
| `trojan_over_raw_tcp_matches_the_oracle` | fail | no listener: the binary exits 1 on an inbound protocol it does not serve |
| `trojan_over_websocket_matches_the_oracle` | fail | the same, on a `ws` inbound |
| `vmess_over_raw_tcp_matches_the_oracle` | fail | the same, on `vmess` |
| `vmess_over_websocket_matches_the_oracle` | fail | the same, on `vmess` over `ws` |
| `shadowsocks_over_raw_tcp_matches_the_oracle` | fail | the same, on `shadowsocks` |
| `vless_xudp_matches_the_oracle` | fail | `UDP echo timed out` after 15 s: no `XUDP`/`UDP` listener |
| `vless_encryption_matches_the_oracle` | fail | `xray vlessenc` is not a subcommand we answer, so its two key pairs are never printed |
| `an_idle_reality_flow_with_keepalive_probes_survives_the_servers_empty_record_limit` | fail | `socks_connect` returns `Err` on the `REALITY` hop, before the keepalive shape is reached |
| `a_plain_http_request_through_vision_reads_a_clean_status_line` | fail | `connect failed: TCP_RST` against our `Vision` inbound |

Two of seventeen, then. A subset that passes is a subset, and the fifteen above stay named failures until their rung lands: `trojan`, `vmess`, `shadowsocks`, `ws`, `httpupgrade`, `grpc`, `xhttp`, `XUDP`, `vlessenc` and `REALITY`/`Vision` are the shortfalls, each one a slice of its own.

## The five pins with no seam

The remaining half needs a different mechanism: an upstream harness that takes a *socket* rather than a *binary*. Each of the five was read at its pin for one — a test that dials an address the suite takes from the environment, which is the only shape usable without editing it — and none has one:

| pin | what the trees hold at that rev |
| --- | ------------------------------ |
| `xray-core` `b26a91de` | `testing/scenarios` *is* a subprocess harness — `BuildXray` compiles its own tree into a fresh `os.MkdirTemp` path and `RunXrayProtobuf` spawns it as `xray.test -config=stdin: -format=pb`. The path is generated, not read from the environment; the only variable there is `XRAY_COV`, a coverage output directory. `proxy/vless`, the pinned suite, has no `os/exec` at all |
| `sing-box` `c9922979` | no `*_test.go` under `protocol/shadowsocks` or `protocol/vless`; the four tests that read the environment read `DOCKER_HOST`, `NETNS_TEST_HOLDER`, an mDNS responder socket path and an OpenConnect interop flag — none a proxy socket |
| `amneziawg-go` `b5928efb` | no `os/exec` and no `Getenv` in any of its 21 test files; the `device` tests are two in-process peers over a loopback `UDP` socket |
| `amnezia-client` `94b51df2` | C++/Qt model tests with a real environment helper, but the keys it reads are `THIRD_PARTY_*_VPN_KEY` and `BACKUP_PATH` — subscription credentials and a file, never a binary or a socket |
| `pattng` `ad6f747c` | the core is the string constant `/data/app/lib/libaether.so` inside argv the tests assemble themselves; the one `Process` subclass in the tests is a fake, and nothing is ever spawned |

Driving any of them would mean editing their tests, which is inventing a runner outside their test rather than running it. That stays true until one of those pins grows a socket-taking harness of its own.

## Current state

| suite | pin | enabled | reason |
| ----- | --- | ------- | ------ |
| xray-core record/crypto | `b26a91de` | ❌ false | no seam at that rev: the suite is in-process Go, so no binary can be injected |
| sing-box crypto | `c9922979` | ❌ false | no seam; and no `_test.go` under `protocol/shadowsocks` or `protocol/vless` to run |
| amneziawg-go noise | `b5928efb` | ❌ false | no seam; `device/*_test.go` are in-process and the TUN path needs root |
| amnezia-client crypto | `94b51df2` | ❌ false | no seam; C++/Qt, test material is Conan-installed |
| xray-rust | `7a4fb2dd` | ❌ false | seam `XRAY_VLESS_FULL_BINARY` exists and our `run -config` answers it, but every one of its interop configs names `REALITY`, `Vision` or `TLS` inbounds, none of which this binary serves |
| PattNG (v2rayNG fork) | `ad6f747c` | ❌ false | no seam; Android/Gradle, and the unsafe rows need `UnsafeOptIn` first |
| ZeroNet / Zray | `97a99734` | ✅ true | seam `ZRAY_XRAY_BINARY` exists; all 17 `xray_oracle` tests run unmodified against `dovetail-zeronet`, two pass and are the gate, fifteen fail by name, checked by `conformance.yml` |

## Adding a suite

Add the pin with `test_enabled = false`, add the CI job that skips with the rung reason, and open the flip to `true` as its own PR with the differential proof attached. A conformance PR without the proof is closed — same as an `unsafe` PR without one. The flip must also set `dovetail_binary` to a binary the suite command executes, `seam` to a variable the pinned tree reads, and `gate_tests` to the names of the tests that pass — `run-upstream-suite.sh` fails the job on any of the three missing, and again if a test passes that the gate does not name. A suite command must not be narrowed to the tests that happen to pass: the whole command runs, and the count of what passes is the claim.