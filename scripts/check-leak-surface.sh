#!/usr/bin/env bash
# Fails on leak-prone surface inside `dovetail-core`.
#
# Three things have no legitimate spelling in the core, and each one has caused
# a real incident in one of the projects this replaces:
#
# 1. DNS resolution. The parser splits `None` from `NoneToPublic` *without* a
#    resolver (the dial path re-checks), so a name that reaches a resolver from
#    inside the core is a DNS leak around the proxy, not a convenience.
# 2. Memory-leak primitives. `Box::leak`, `mem::forget`, `ManuallyDrop` and
#    `into_raw` have no use in a core whose allocation gate is zero: anything
#    reaching for them is laundering a lifetime the borrow checker refused.
# 3. Printing and wall-clock reads. The core is a library: `println!`/`dbg!`
#    in it is noise on every caller's stdout, and `Instant::now` in it makes a
#    supposedly deterministic function timing-dependent. Both live in
#    `dovetail-bench` and `dovetail-zeronet`, never here.
#
# `git grep` over tracked files only, so untracked scratch never fails the job.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

if git grep -I -n -E 'to_socket_addrs|lookup_host|getaddrinfo|hickory|trust-dns' -- crates/dovetail-core/src; then
  echo "::error::dovetail-core must not resolve DNS — the parser decides without a resolver (see transport.rs)"
  status=1
fi

if git grep -I -n -E 'Box::leak|mem::forget|::forget\(|ManuallyDrop|into_raw' -- crates/dovetail-core/src; then
  echo "::error::dovetail-core must not launder lifetimes — the allocation gate is zero, use borrows"
  status=1
fi

if git grep -I -n -E 'println!|print!|eprintln!|eprint!|dbg!' -- crates/dovetail-core/src; then
  echo "::error::dovetail-core is a library — printing lives in dovetail-bench/dovetail-zeronet"
  status=1
fi

if git grep -I -n -E 'Instant::now|SystemTime::now' -- crates/dovetail-core/src; then
  echo "::error::dovetail-core must stay deterministic — wall-clock reads live in dovetail-bench"
  status=1
fi

exit "$status"
