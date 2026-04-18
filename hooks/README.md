# Signal Sentinel pre-commit hooks

Drop-in integrations for the three most common Git hook frameworks.

| Framework | File | Install |
|---|---|---|
| [pre-commit.com](https://pre-commit.com) | `.pre-commit-hooks.yaml` | Add the `signal-sentinel` hook id to your consumer repo's `.pre-commit-config.yaml` |
| [lefthook](https://github.com/evilmartians/lefthook) | `lefthook.yml` | Copy or merge into your consumer repo |
| [husky](https://typicode.github.io/husky/) | `husky/pre-commit` | Copy to `.husky/pre-commit` or reference via `bash hooks/husky/pre-commit` |

All three run the scanner with:

```
sentinel-scan --skills --format sarif --min-confidence 0.75 --fail-on high
```

- `--min-confidence 0.75` suppresses weak-signal findings at edit time so authors
  aren't blocked by triage-grade hits.
- `--fail-on high` exits non-zero only on High or Critical — tune down to `medium`
  or `critical` as your policy requires.
- Add `--save-history` to persist runs under `.sentinel/history/` for diff-mode
  comparisons later.

## Prerequisite

```
dotnet tool install -g SignalSentinel.Scanner
```

## Troubleshooting

- Hook hangs: most likely the scanner is waiting on an MCP server. Add
  `--offline` to hook args to eliminate any network I/O.
- Hook too noisy: add a `.sentinel-suppressions.json` with justified
  acceptances; the hook will honour them automatically.
