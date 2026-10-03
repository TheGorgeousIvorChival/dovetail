#!/usr/bin/env bash
# Fails if any pinned upstream commit no longer resolves, or is unpinned.
#
# Without this, a force-push or a deleted branch upstream leaves the pins
# pointing at nothing and every comparison built on them quietly becomes a
# comparison against nothing. Cheap to check, expensive to discover later.
#
# A source with no `rev` is a hard error, not a skip. A pin check that tolerates
# the entries it exists to enforce reads as coverage while providing none.
#
# The commit is verified with a depth-1 fetch of the exact object, not with
# `ls-remote`: `ls-remote` only lists what refs point at, so a force-pushed
# branch whose old commit is now unreachable upstream would still "resolve" by
# name and the pin would be checked against nothing. GitHub serves any reachable
# object by id, so fetching the id is the check that means what it says.
set -euo pipefail

cd "$(dirname "$0")/.."

# Set CHECK_PINS=0 to make this a no-op, for a fork that mirrors the upstream
# repositories and cannot reach them. Unset means check; only an explicit 0
# skips, so the common mistake of forgetting to enable it fails closed.
if [[ "${CHECK_PINS:-1}" == "0" ]]; then
  echo "note: CHECK_PINS=0, upstream pins not verified"
  exit 0
fi

pins_file="upstream/pins.toml"
if [[ ! -f "$pins_file" ]]; then
  echo "::error::$pins_file is missing; nothing to verify"
  exit 1
fi

# Parse [sources.X] blocks into "name<TAB>repo<TAB>rev<TAB>branch" lines. This is
# a TOML subset, so it is read with awk rather than pulling in a TOML parser the
# runner may not have.
parsed="$(awk '
  /^\[sources\./ {
    name = $0
    sub(/^\[sources\./, "", name)
    sub(/\]$/, "", name)
    repo = ""; rev = ""; branch = ""
    next
  }
  /^repo[[:space:]]*=/ {
    repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next
  }
  /^rev[[:space:]]*=/ {
    rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next
  }
  /^default_branch[[:space:]]*=/ {
    branch = $0; sub(/^[^=]*=[[:space:]]*"/, "", branch); sub(/"[[:space:]]*$/, "", branch); next
  }
  /^$/ {
    if (name != "") print name "\t" repo "\t" rev "\t" branch
    name = ""
  }
  END { if (name != "") print name "\t" repo "\t" rev "\t" branch }
' "$pins_file")"

if [[ -z "$parsed" ]]; then
  echo "::error::no [sources.*] entries parsed from $pins_file; the checker is broken, not clean"
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

status=0
checked=0

while IFS=$'\t' read -r name repo rev branch; do
  [[ -n "$name" ]] || continue

  if [[ -z "$repo" ]]; then
    echo "::error::$name has no repo"
    status=1
    continue
  fi

  if [[ -z "$rev" ]]; then
    # Not a warning. An unpinned source is exactly the failure this job exists
    # to catch, so it fails the job.
    echo "::error::$name ($repo) is not pinned: no rev. A comparison against 'latest' is not a comparison."
    status=1
    continue
  fi

  if [[ ! "$rev" =~ ^[0-9a-f]{7,40}$ ]]; then
    echo "::error::$name rev '$rev' is not a commit id"
    status=1
    continue
  fi

  dir="$tmp/$name"
  if ! git init --quiet --bare "$dir" 2>/dev/null; then
    echo "::error::could not create a scratch repo for $name"
    status=1
    continue
  fi

  if git -C "$dir" remote add origin "$repo" >/dev/null 2>&1 &&
     git -C "$dir" fetch --quiet --depth 1 origin "$rev" >/dev/null 2>&1; then
    echo "ok: $name $rev resolves on $repo"
    checked=$((checked + 1))

    if [[ -n "$branch" ]]; then
      # A pin can resolve and still be stale, which is fine — stale is a
      # deliberate, visible choice made by update-pins.sh. It is only worth
      # reporting, so this never fails the job.
      head="$(git ls-remote "$repo" "refs/heads/$branch" 2>/dev/null | cut -f1 || true)"
      if [[ -n "$head" && "$head" != "$rev" ]]; then
        echo "note: $name is pinned behind $branch ($head is the tip); refresh with scripts/update-pins.sh"
      fi
    fi
  else
    echo "::error::$name rev $rev does not resolve on $repo (deleted, force-pushed, or the repo moved)"
    status=1
  fi
done <<< "$parsed"

if [[ "$checked" -eq 0 && "$status" -eq 0 ]]; then
  # Reaching here means the loop matched nothing, which means the parser and the
  # file disagree. Reporting "all good" would be a lie produced by a bug.
  echo "::error::parsed zero sources from $pins_file; refusing to report success"
  exit 1
fi

echo "verified $checked pinned upstream source(s)"
exit "$status"