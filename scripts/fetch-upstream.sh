#!/usr/bin/env bash
# Fetch every pinned upstream source into `upstream/<name>/` at its exact rev.
#
# Pinned, not tracked, is deliberate: a comparison against "latest" is not a
# comparison. So this script resolves `repo` plus `rev` from `upstream/pins.toml`
# and nothing else, checks out exactly that commit, verifies the checkout is at
# that commit, and writes `upstream/manifest.toml` saying what it got — so a
# reviewer re-derives the tree without trusting this machine.
#
# Rerunnable: an existing checkout that is already at its pin is left alone; one
# that drifted is rebuilt from scratch, because a checkout that disagrees with
# its pin is worse than no checkout.
#
# Never copies anything into this repository. The checkouts are reading copies
# for agents (see P3); suites run from them unmodified, and `upstream/*` stays
# out of version control — see `.gitignore`.
set -euo pipefail

cd "$(dirname "$0")/.."

pins_file="upstream/pins.toml"
if [[ ! -f "$pins_file" ]]; then
  echo "::error::$pins_file is missing; nothing to fetch"
  exit 1
fi

# Same TOML subset `check-upstream-pins.sh` reads, plus `fallback_repo`: a
# second URL tried when the first answers nothing (ZeroNet's fork, then the
# official repo). A pin that resolves nowhere fails loudly below.
parsed="$(awk '
  /^\[sources\./ {
    name = $0
    sub(/^\[sources\./, "", name)
    sub(/\]$/, "", name)
    repo = ""; rev = ""; fallback = ""
    next
  }
  /^repo[[:space:]]*=/ {
    repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next
  }
  /^fallback_repo[[:space:]]*=/ {
    fallback = $0; sub(/^[^=]*=[[:space:]]*"/, "", fallback); sub(/"[[:space:]]*$/, "", fallback); next
  }
  /^rev[[:space:]]*=/ {
    rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next
  }
  /^$/ {
    if (name != "") print name "\t" repo "\t" rev "\t" fallback
    name = ""
  }
  END { if (name != "") print name "\t" repo "\t" rev "\t" fallback }
' "$pins_file")"

if [[ -z "$parsed" ]]; then
  echo "::error::no [sources.*] entries parsed from $pins_file"
  exit 1
fi

fetched=0
manifest="upstream/manifest.toml"
# Built aside and moved into place, so a run that dies partway leaves the
# previous manifest rather than a shorter one: a manifest that lists two of
# seven pins and stops reads as a complete account of what is on disk.
manifest_tmp="$manifest.part"
trap 'rm -f "$manifest_tmp"' EXIT
{
  echo "# Derived artifact. Do not edit: rerun scripts/fetch-upstream.sh."
  echo "# Each entry is the exact commit the named checkout holds."
} > "$manifest_tmp"

while IFS=$'\t' read -r name repo rev fallback; do
  [[ -n "$name" ]] || continue
  if [[ -z "$repo" || -z "$rev" ]]; then
    echo "::error::$name is missing repo or rev; pin it before fetching"
    exit 1
  fi

  dir="upstream/$name"
  fetched_from="cached (already at pin)"
  if [[ -d "$dir/.git" ]] && [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$rev" ]]; then
    echo "ok: $name already at $rev"
  else
    rm -rf "$dir"
    git init --quiet "$dir"
    fetched_from=""
    for candidate in "$repo" "$fallback"; do
      [[ -n "$candidate" ]] || continue
      git -C "$dir" remote add origin "$candidate" 2>/dev/null || git -C "$dir" remote set-url origin "$candidate"
      if git -C "$dir" fetch --quiet --depth 1 origin "$rev"; then
        fetched_from="$candidate"
        break
      fi
    done
    if [[ -z "$fetched_from" ]]; then
      echo "::error::$name rev $rev resolves nowhere (tried primary and fallback)"
      exit 1
    fi
    git -C "$dir" checkout --quiet FETCH_HEAD
    echo "fetched: $name at $rev from $fetched_from"
  fi

  head="$(git -C "$dir" rev-parse HEAD)"
  if [[ "$head" != "$rev" ]]; then
    echo "::error::$name holds $head, not its pin $rev"
    exit 1
  fi
  {
    echo ""
    echo "[checkout.$name]"
    echo "repo = \"$repo\""
    echo "rev  = \"$rev\""
    echo "fetched_from = \"$fetched_from\""
  } >> "$manifest_tmp"
  fetched=$((fetched + 1))
done <<< "$parsed"

mv "$manifest_tmp" "$manifest"
echo "fetched $fetched pinned upstream source(s); manifest in $manifest"
