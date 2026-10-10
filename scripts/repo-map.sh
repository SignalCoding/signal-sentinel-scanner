#!/usr/bin/env bash
# repo-map.sh (v3.0.0) - refreshes the generated block of _docs/ai/repo-map.md: every tracked
# top-level and second-level directory with its file count, so "where does X live" is a lookup.
# The hand-written sections above the block are never touched. Run at Gate 5 and whenever a
# task group adds or moves a directory of consequence; commit the result with that change.
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAP="$PROJECT_ROOT/_docs/ai/repo-map.md"
[[ -f "$MAP" ]] || { echo "repo-map: $MAP not found (bootstrap delivers it)." >&2; exit 1; }
cd "$PROJECT_ROOT"
if git rev-parse --git-dir >/dev/null 2>&1; then
  LIST="$(git ls-files --cached --others --exclude-standard)"
else
  LIST="$(find . -name .git -prune -o -type f -print | sed 's|^\./||')"
fi
GEN="$(printf '%s\n' "$LIST" | awk -F/ '
  NF>1 { d1=$1"/"; c1[d1]++; if (NF>2) { d2=$1"/"$2"/"; c2[d2]++ } }
  END {
    n=asorti(c1, k1); for (i=1;i<=n;i++) { d=k1[i]; printf("- `%s` (%d files)\n", d, c1[d]);
      m=asorti(c2, k2); for (j=1;j<=m;j++) { s=k2[j]; if (index(s, d)==1) printf("  - `%s` (%d)\n", s, c2[s]) } }
  }' 2>/dev/null || true)"
if [[ -z "$GEN" ]]; then
  # awk without asorti (mawk): unsorted fallback through sort
  GEN="$(printf '%s\n' "$LIST" | awk -F/ 'NF>1 {print $1"/"} NF>2 {print $1"/"$2"/"}' | sort | uniq -c | awk '{ ind=(gsub(/\//,"/",$2)>1)?"  ":""; printf("%s- `%s` (%d files)\n", ind, $2, $1) }')"
fi
TMP="$(mktemp)"
awk -v gen="$GEN" -v ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  /<!-- REPO-MAP:GENERATED:BEGIN -->/ { print; print "Generated " ts " by scripts/repo-map.sh - do not edit by hand."; print ""; print gen; skip=1; next }
  /<!-- REPO-MAP:GENERATED:END -->/ { skip=0 }
  !skip { print }
' "$MAP" > "$TMP" && mv "$TMP" "$MAP"
echo "repo-map: generated block refreshed in _docs/ai/repo-map.md"
