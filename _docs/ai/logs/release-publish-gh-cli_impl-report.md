# Implementation Report: release-publish-gh-cli

**Date:** 2026-09-25
**Status:** GREEN
**Spec:** _docs/ai/specs/release-publish-gh-cli.md

## Files Changed

- `.github/workflows/release.yml`

## What Was Modified

| File | What Changed | Rationale |
| ---- | ------------ | --------- |
| `.github/workflows/release.yml` | Replaced `softprops/action-gh-release` step in `create-release` with a `gh`-CLI `run:` step | softprops/action-gh-release#836: "Resource not accessible by integration" with `GITHUB_TOKEN`; `gh` works with the same token |

## Final Step (verbatim)

```
      - name: Create Release
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail

          VERSION="${{ needs.resolve.outputs.version }}"
          TAG="${{ needs.resolve.outputs.tag }}"

          cat > notes-install.md <<'EOF'
          ## Signal Sentinel Scanner v$VERSION
          ...(install block, verbatim text, "$VERSION" placeholder)...
          EOF
          sed -i "s/\$VERSION/$VERSION/g" notes-install.md

          if gh release view "$TAG" >/dev/null 2>&1; then
            gh release view "$TAG" --json body --jq .body > notes.md
            if ! grep -qF "## Signal Sentinel Scanner v$VERSION" notes.md; then
              printf '\n' >> notes.md
              cat notes-install.md >> notes.md
            fi
            gh release upload "$TAG" ./artifacts/*.nupkg --clobber
            gh release edit "$TAG" --title "Signal Sentinel v$VERSION" --notes-file notes.md --draft=false --latest
          else
            gh release create "$TAG" ./artifacts/*.nupkg --title "Signal Sentinel v$VERSION" --notes-file notes-install.md --latest
          fi

          echo "Release published: $(gh release view "$TAG" --json url --jq .url)"
```

## Files Intentionally Not Touched

- All other jobs/steps in `.github/workflows/release.yml` - unrelated to the spec
- Everything else in the repo - out of scope

## Validation

| Command | Result |
| ------- | ------ |
| `python -c "import yaml;yaml.safe_load(...)"` | `yaml ok` |
| `bash -n` on extracted `run` script | syntax OK |
| `grep -n "softprops" .github/workflows/release.yml` | no match (exit 1) |
| CRLF check (every line ends `\r\n`) | 0 LF-only lines in 301-line file |

## Dependencies Added (if any)

- none

## Follow-Up Needed

- none

## Risks and Notes

- The install block is written with a quoted heredoc (`<<'EOF'`) so the Markdown code
  fences (```` ```bash ````) are never subject to bash command/backtick substitution; the
  `$VERSION` placeholder is therefore left literal inside the heredoc and substituted
  afterwards with `sed`, keeping the visible install-block text identical to the original
  `body:` text apart from the placeholder syntax change.
- Not independently verified against a live `gh` CLI run (spec marks this optional); logic
  mirrors the hand-run commands that completed the 3.0.3 release per the spec's "Why".

## Open Questions Raised During Work

- none
