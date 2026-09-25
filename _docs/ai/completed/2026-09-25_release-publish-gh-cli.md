# Spec: publish the GitHub Release with the gh CLI instead of softprops/action-gh-release

**Status:** approved (owner: "proceed with the rest", 2026-09-25). **Branch:** `fix/release-publish-with-gh-cli` from `main` @ `e09dcf1`.
**Why:** the first bot-driven release (3.0.3) failed at `Create GitHub Release`: `softprops/action-gh-release` v3.0.3
returned "Resource not accessible by integration" (update-a-release) when updating the draft release-please had
created, both under `workflow_call` and `workflow_dispatch`. Upstream softprops/action-gh-release#836 (open, bug)
reports the same regression since v3.0.2 with `GITHUB_TOKEN`; the suggested workaround is a PAT, which this project
does not use. The 3.0.3 release was completed by hand with `gh release upload` + `gh release edit`, which works with
a plain token holding `contents: write`. Make that the workflow.

## Change (`.github/workflows/release.yml`, job `create-release` only)
Replace the `Create Release` step (`softprops/action-gh-release@efb3536...`) with one `run:` step using the
preinstalled `gh` CLI and `env: GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}`:

1. Write the install block (the existing `body: |` text, with `${{ needs.resolve.outputs.version }}` substituted)
   to `notes-install.md`.
2. If `gh release view "$TAG"` succeeds (release-please path: draft exists with the changelog body):
   `gh release view "$TAG" --json body --jq .body > notes.md`, append a blank line and `notes-install.md`,
   then `gh release upload "$TAG" ./artifacts/*.nupkg --clobber` and
   `gh release edit "$TAG" --title "Signal Sentinel v$VERSION" --notes-file notes.md --draft=false --latest`.
3. Else (human tag path, no release yet): `gh release create "$TAG" ./artifacts/*.nupkg --title "Signal Sentinel v$VERSION" --notes-file notes-install.md --latest`.
4. Idempotent: re-running on an already published release must not duplicate the install block (guard: only
   append if `notes.md` does not already contain the line `## Signal Sentinel Scanner v$VERSION`).
5. `set -euo pipefail`; print the final release URL. Job permissions stay `contents: write`. Remove the
   `softprops/action-gh-release` pin from the file (it is the only use). Keep the `Download NuGet artifacts` step.

## Acceptance
- `python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"` ok; `actionlint` if available.
- `bash -n` on the extracted script; a local dry run of the script logic against a temp directory with
  `gh` stubbed is optional.
- CHANGELOG: nothing (release-please generates it from the `fix(release):` PR title).
- After merge: the bot refreshes #81 (`chore(main): release 3.0.4`); merging #81 must complete end to end with no
  manual step: tag, NuGet, GHCR `:3.0.4`, published release with both `.nupkg` and the appended install block.

## As implemented (2026-09-25)

- Step replaced as specified; quoted heredoc + `sed` substitution for the version placeholder; idempotent append guard; `gh release create` fallback for the human-tag path. YAML and `bash -n` clean; CRLF preserved. Verified live on the next bot release (3.0.4).
