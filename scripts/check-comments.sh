#!/usr/bin/env bash
# Fails on comment traces; reports comment weight.
#
# Fixes leave no trace: no TODO, FIXME, XXX or HACK markers anywhere they would
# outlive the diff, and no `/* */` blocks (docs are `///` and `//!`, one line
# per item at most). A marker is how a fix advertises itself instead of being
# one; the roadmap lives in `prompts.md`, not in the code.
#
# Long `//` runs are reported, not failed: the tree predates the one-line rule,
# and a gate that fails on every file it ever passes gets deleted the first
# time it is wrong. Watch the count go down instead.
#
# `git grep` sees tracked files only, so the untracked reading copies under
# `upstream/` can carry whatever their authors wrote.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

# This file defines the pattern it searches for, so it excludes itself: without
# the exclusion the grep below matches lines 4 and 21 here and the gate never passes.
if git grep -I -n -E 'TODO|FIXME|XXX|HACK' -- '*.rs' 'scripts/*' '.github/**/*' ':!crates/dovetail-prompt/prompts.md' ':!scripts/check-comments.sh'; then
  echo "::error::trace markers do not land in this tree; the roadmap lives in prompts.md"
  status=1
fi

if git grep -I -n -E '^[[:space:]]*/\*' -- '*.rs'; then
  echo "::error::no /* */ blocks; docs are /// and //!, one line per item at most"
  status=1
fi

# Advisory: the longest `//` run per file. Doc comments (`///`, `//!`) and
# shell `#` headers are not counted; only inline explanation runs.
git ls-files '*.rs' | while IFS= read -r file; do
  longest="$(awk '/^[[:space:]]*\/\/[^!\/]/ {n++; if (n>m) m=n} !/^[[:space:]]*\/\/[^!\/]/ {n=0} END {print m+0}' "$file")"
  if [[ "$longest" -gt 1 ]]; then
    echo "note: $file longest // run is $longest line(s)"
  fi
done

exit "$status"
