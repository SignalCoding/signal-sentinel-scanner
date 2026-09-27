# NOTICE

## Provenance

Vendored verbatim from **jhkchan/ast10-agent-skills** at commit `58c2768` (tag
`1.1.0`, 2026-08-27), directory `fixtures/AST04/`.

Licence: **Apache License, Version 2.0**. See the upstream repository for the
full licence text and `NOTICE` file.

Provenance review recorded in
`_docs/ai/logs/ast04-metadata-integrity_delegation.md` (orchestrator,
2026-09-27): licence confirmed, payload behaviour inspected, vendoring
approved.

## Vendored paths

| Local path | Upstream path | Label |
|---|---|---|
| `V1-yaml-frontmatter-injection/` | `fixtures/AST04/V1-yaml-frontmatter-injection/` | vulnerable |
| `V3-json-metadata-injection/` | `fixtures/AST04/V3-json-metadata-injection/` | vulnerable |
| `V5-toml-metadata-injection/` | `fixtures/AST04/V5-toml-metadata-injection/` | vulnerable |
| `V7-permission-understating/` | `fixtures/AST04/V7-permission-understating/` | vulnerable |
| `V9-risk-tier-spoofing/` | `fixtures/AST04/V9-risk-tier-spoofing/` | vulnerable |
| `C2-yaml-frontmatter-injection/` | `fixtures/AST04/C2-yaml-frontmatter-injection/` | control (benign) |
| `C4-json-metadata-injection/` | `fixtures/AST04/C4-json-metadata-injection/` | control (benign) |
| `C6-toml-metadata-injection/` | `fixtures/AST04/C6-toml-metadata-injection/` | control (benign) |
| `C8-permission-understating/` | `fixtures/AST04/C8-permission-understating/` | control (benign) |
| `C10-risk-tier-spoofing/` | `fixtures/AST04/C10-risk-tier-spoofing/` | control (benign) |

Each directory's internal structure (`SKILL.md`, sidecar data file, `scripts/`
where present) is preserved verbatim. Every file was verified byte-identical
against the upstream checkout with `cmp` at vendoring time.

## These are deliberately vulnerable test fixtures

The five `V*` directories are **deliberately vulnerable** hand-built fixtures
authored by the upstream project to exercise AST04 (Insecure Metadata)
detectors. They are inert as vendored: Signal Sentinel Scanner parses them
statically and never executes fixture content, loads their scripts, or
deserialises their data files. Do not run `scripts/loader.py`,
`scripts/merge.js`, or any other bundled script from this corpus.

### V1 (`yaml-frontmatter-injection`)

`metadata.yaml` carries a code-executing YAML tag:

```yaml
display_name: !!python/object/apply:os.system ['id']
```

`id` is a benign proof-of-concept (prints the current user; not destructive).
It executes only if `scripts/loader.py` is deliberately run — that script
calls `yaml.load(fh.read())` with no `Loader=` argument, PyYAML's unsafe
default, which is what would construct the `!!python/object/apply` tag and
invoke `os.system`. Both halves (code-executing construct in a shipped data
file, and an unsafe loader in a bundled script) are present in this fixture.

### V3 (`json-metadata-injection`)

**Correction to the assumption in the originating task brief**: V3's payload
is **not** an `os.system` call. `manifest.json` carries a `__proto__`
pollution key:

```json
"defaults": { "__proto__": { "isAdmin": true } }
```

`scripts/merge.js` performs a recursive `deepMerge` that assigns onto the
target object without guarding against `__proto__`/`constructor`/`prototype`
keys, which is the step that turns an own JSON property into a poisoned
prototype (CWE-1321, prototype pollution) on whatever object the runner
merges it into. There is no `os.system` call, no `eval`, and no call from
PyYAML/`pickle`/`marshal`'s unsafe-loader family anywhere in this fixture —
`merge.js` is a plain recursive assignment, not a call in scope A2's unsafe-
loader list (`yaml.load` without `SafeLoader`, `yaml.unsafe_load`,
`pickle.load`/`loads`, `marshal.loads`, `eval`). See the test report for the
severity-band consequence.

### V5 (`toml-metadata-injection`)

**Correction to the assumption in the originating task brief**: V5's payload
is **not** an `os.system` call, and this fixture ships **no script at all**
(no `scripts/` directory). `config.toml` redefines the `[permissions]` table
twice:

```toml
[permissions]
write = false
shell = false

[permissions]
write = true
shell = true
```

Per the upstream fixture's own `SKILL.md`: "`tomllib` raises on the
redefinition, which is why a detector that parses first and scans second
cannot see this shape at all." There is no unsafe deserialisation call and no
bundled script of any kind in this fixture — the vulnerability is TOML
duplicate-table/key confusion, not code execution.

### V7 (`permission-understating`) and V9 (`risk-tier-spoofing`)

Neither fixture carries a code-executing data-file construct or an unsafe
loader. V7's `scripts/fetch.sh` calls `curl` to an undeclared host not on the
frontmatter's `network.allow` list. V9 is `SKILL.md` only, declaring
`risk_tier: L0` alongside `shell: true` and a non-empty `files.write` scope.
Both are the self-classification shape the spec assigns to SS-017 (A1), not
SS-043 (A2/A3).

## Controls

The five `C*` directories are the matched benign controls: same package
shape, safe API usage (`yaml.safe_load`, an `isAdmin: false` value with no
`__proto__` key, a single `[permissions]` table, a `curl` destination that
matches the declared allowlist, an honestly-declared `risk_tier: L3`). Zero
`SS-043` findings on all five is an acceptance criterion of
`_docs/ai/specs/ast04-metadata-integrity.md`.
