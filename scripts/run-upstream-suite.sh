#!/usr/bin/env bash
# Runs one upstream suite against a Dovetail binary at the pinned commit, or skips
# it with the rung reason when no binary is wired yet.
#
# Upstream suites are NEVER copied into this repository (sing-box is GPL-3.0,
# Xray-core/xray-rust are MPL-2.0, PattNG is GPL-3.0): they run unmodified from
# the pinned commit. Each source in upstream/pins.toml carries `test_enabled`,
# a `suite` command run with the clone as its working directory, `gate_tests`
# naming which of that suite's tests may be red for the job to stay green, and
# `dovetail_binary` naming the Dovetail binary the suite executes. An enabled entry
# with no binary fails here instead of printing PASS, because a suite that ran no
# Dovetail binary proves nothing about this workspace. Usage: run-upstream-suite.sh
# [name] (default: every source).
set -euo pipefail

cd "$(dirname "$0")/.."

name_filter="${1:-}"
pins_file="upstream/pins.toml"

# name<TAB>repo<TAB>rev<TAB>enabled<TAB>suite<TAB>binary<TAB>seam<TAB>gate — same TOML
# subset the pin checker reads, plus the four conformance fields.
parse_pins() {
  awk '
    function f(v) { return v == "" ? "-" : v }
    /^\[sources\./ {
      if (name != "") print name "\t" repo "\t" rev "\t" enabled "\t" f(suite) "\t" f(binary) "\t" f(seam) "\t" f(gate)
      name = $0; sub(/^\[sources\./, "", name); sub(/\]$/, "", name)
      repo = ""; rev = ""; enabled = ""; suite = ""; binary = ""; seam = ""; gate = ""
      next
    }
    /^repo[[:space:]]*=/ { repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next }
    /^rev[[:space:]]*=/ { rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next }
    /^test_enabled[[:space:]]*=/ { enabled = $0; sub(/^[^=]*=[[:space:]]*/, "", enabled); next }
    /^suite[[:space:]]*=/ { suite = $0; sub(/^[^=]*=[[:space:]]*"/, "", suite); sub(/"[[:space:]]*$/, "", suite); next }
    /^dovetail_binary[[:space:]]*=/ { binary = $0; sub(/^[^=]*=[[:space:]]*"/, "", binary); sub(/"[[:space:]]*$/, "", binary); next }
    /^seam[[:space:]]*=/ { seam = $0; sub(/^[^=]*=[[:space:]]*"/, "", seam); sub(/"[[:space:]]*$/, "", seam); next }
    /^gate_tests[[:space:]]*=/ { gate = $0; sub(/^[^=]*=[[:space:]]*"/, "", gate); sub(/"[[:space:]]*$/, "", gate); next }
    END { if (name != "") print name "\t" repo "\t" rev "\t" enabled "\t" f(suite) "\t" f(binary) "\t" f(seam) "\t" f(gate) }
  ' "$pins_file"
}

# Compare one suite run against its `gate_tests` and print what it measured.
#
# The whole `suite` command has already run and printed its own per-test lines, so
# this reads the same verdicts out of the log instead of trusting the exit status:
# a command that ran a suite and failed the tests whose rungs have not landed is
# not a command that proved nothing, and treating it as one would be as dishonest
# as printing PASS for a binary that was never executed. What the gate decides is
# which of those verdicts the job is entitled to call green.
judge() {
  local name=$1 rev=$2 binary=$3 seam=$4 gate=$5 log=$6
  local line test passed="" gate_ok=0 stale_ok=0 passed_count=0 failed_count=0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    test="${line%|*}"
    case "${line##*|}" in
      ok) passed="$passed $test"; passed_count=$((passed_count + 1)) ;;
      *) failed_count=$((failed_count + 1)) ;;
    esac
  done < <(sed -n -E 's/^test (.+) \.\.\. (ok|FAILED)$/\1|\2/p' "$log")
  if [[ "$passed_count" -eq 0 && "$failed_count" -eq 0 ]]; then
    echo "::error::$name printed no per-test result at $rev: nothing was measured, so nothing passes"
    return 1
  fi
  for test in $gate; do
    if [[ " $passed " != *" $test "* ]]; then
      echo "::error::$name: gate test $test did not pass against $binary at $rev"
      gate_ok=1
    fi
  done
  for test in $passed; do
    if [[ " $gate " != *" $test "* ]]; then
      echo "::error::$name: $test passes against $binary at $rev but no gate test names it; name it and update the count in docs/conformance.md"
      stale_ok=1
    fi
  done
  echo "MEASURED: $name at $rev against Dovetail binary $binary via $seam — $passed_count of $((passed_count + failed_count)) tests pass, $failed_count fail; gate: ${gate:-none}"
  [[ "$gate_ok" -eq 0 && "$stale_ok" -eq 0 ]]
}

status=0
ran=0
workspace="$PWD"
while IFS=$'\t' read -r name repo rev enabled suite binary seam gate; do
  [[ "$suite" == "-" ]] && suite=""
  [[ "$binary" == "-" ]] && binary=""
  [[ "$seam" == "-" ]] && seam=""
  [[ "$gate" == "-" ]] && gate=""
  [[ -n "$name" ]] || continue
  if [[ -n "$name_filter" && "$name" != "$name_filter" ]]; then
    continue
  fi
  if [[ "$enabled" != "true" ]]; then
    echo "SKIPPED: $name @ ${rev:0:7} — no Dovetail binary wired yet (would need ${binary:-nothing exists for this rung yet}); rung not implemented (see docs/conformance.md)"
    continue
  fi
  if [[ -z "${binary:-}" ]]; then
    # Fail closed: an enabled suite with no binary would PASS on upstream code alone.
    echo "::error::$name is enabled with no dovetail_binary: refusing a PASS that ran no Dovetail binary"
    status=1
    continue
  fi
  if [[ -z "$suite" ]]; then
    # Enabled with no runnable suite: covered by the build matrix itself.
    echo "COVERED-BY-BUILD: $name @ ${rev:0:7} — no upstream suite; build matrix is the check"
    continue
  fi
  # Building the binary is not running it. Without a seam the suite has no way
  # to execute it, so a PASS here would name a binary that took no part in the
  # comparison — the exact claim this script exists to refuse.
  if [[ -z "$seam" ]]; then
    echo "::error::$name has no seam: its suite at $rev cannot execute $binary, so a PASS would name a binary that never ran"
    status=1
    continue
  fi
  echo "RUNNING: $name @ $rev against Dovetail binary $binary via $seam"
  echo "  suite: $suite"
  # The named binary must exist in this workspace, or the PASS below names nothing.
  if ! cargo build --locked -q -p "$binary" 2>/dev/null; then
    echo "::error::$name: Dovetail binary $binary does not build in this workspace"
    status=1
    continue
  fi
  dir="$(mktemp -d)"
  if ! git clone --quiet --no-checkout "$repo" "$dir" 2>/dev/null; then
    echo "::error::$name: could not clone $repo"
    rm -rf "$dir"
    status=1
    continue
  fi
  if ! git -C "$dir" checkout --quiet "$rev" 2>/dev/null; then
    echo "::error::$name: rev $rev does not resolve"
    rm -rf "$dir"
    status=1
    continue
  fi
  # A declared seam is still only a claim until the pinned tree reads it, so
  # check the variable is actually referenced at that rev before injecting it.
  if ! git -C "$dir" grep -qI -e "$seam" -- . 2>/dev/null; then
    echo "::error::$name declares seam $seam but $rev never reads it: nothing would execute $binary"
    rm -rf "$dir"
    status=1
    continue
  fi
  # The suite reads the binary out of the environment, so the seam carries the
  # absolute path: the clone runs from a temp directory, and a relative path
  # there would name a different binary than the one just built. The run is
  # streamed and teed to a log because the gate below reads the verdicts out of
  # it, and because a differential failure is only readable if the upstream
  # suite's own output reaches the log.
  log="$(mktemp)"
  (cd "$dir" && env "$seam=$workspace/target/debug/$binary" bash -c "$suite") 2>&1 | tee "$log" || true
  if judge "$name" "$rev" "$binary" "$seam" "$gate" "$log"; then
    echo "PASS: $name gate green against $binary at $rev (injected via $seam)"
    ran=$((ran + 1))
  else
    status=1
  fi
  rm -f "$log"
  rm -rf "$dir"
done < <(parse_pins)

echo "upstream suites: $ran ran green against Dovetail binaries (the rest skipped with reasons above)"
exit "$status"
