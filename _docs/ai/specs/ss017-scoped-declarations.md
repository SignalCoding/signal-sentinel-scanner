# Spec: SS-017 must not punish honest, scoped declarations

**Status:** approved (arises from the live accuracy run, 2026-09-27). **Branch:** `fix/ss017-scoped-declarations`.
**Origin:** re-running the labelled adversarial benchmark on `main` @ `99940f3` showed SS-017 as the top
false-positive driver with five hits on benign controls. It was absent from that list before #92, so this is a
regression introduced by that branch's A1 change.

## The defect

A1 made SS-017 derive the implied risk-tier floor from **declared** permissions, which was right. It derives the
floor from the *presence* of a declaration rather than its *breadth*, which is wrong. Probed directly:

| Declaration with `risk_tier: L1` | Result | Correct? |
|---|---|---|
| `shell: false` alone | silent | yes |
| `shell: true` | fires | yes, this is the spoofing case |
| `network.allow: [api.example.com]` | **fires** | **no** |
| `network.allow: ['*']` | fires | yes |
| no permissions block | silent | yes |

A single enumerated host is a narrow, scoped grant. Treating it the same as a wildcard penalises precisely the
practice the scanner should encourage.

It is also internally inconsistent. #92's D1 made a declared allowlist **suppress** an SS-012 finding, while A1
made the same declaration **raise** the SS-017 floor. An author who declares honestly is rewarded by one rule and
punished by another for the same line.

## Requirements

### R1 - the floor rises for unbounded capability, not for any capability
- `shell: true` raises the floor. `shell: false` or absent does not. (Already correct; keep.)
- `network.allow` raises the floor only when **unbounded**: containing `*`, `0.0.0.0/0`, `::/0`, a bare scheme
  such as `http://*`, or an entry that is a wildcard domain (`*.example.com` counts as unbounded for this purpose;
  document the choice). An enumerated list of concrete hosts does **not** raise it.
- `files.write` raises the floor only when unbounded: containing `*`, `/`, `~`, `..`, or an entry that resolves
  outside the skill directory. An enumerated list of concrete relative paths does **not**.
- An empty list continues to declare nothing, as #92 established.

### R2 - negation blindness in the prose detector *(pre-existing, same class as the 3.0.1 work)*
The AST03 control draws `Unrestricted Shell Access` because its description reads "shell is an explicit closed
declaration". The word is present; the meaning is the opposite. Apply the sentence-scope and negation discipline
already used by SS-008 and the v3.0.2 SS-012 shapes: a capability word inside a negated or closing clause
(`no`, `not`, `never`, `closed`, `disabled`, `false`, `denied`, `without`) does not count as requesting it.
This is pre-existing rather than a regression, but it is the same failure class and it is cheap here.

### R3 - consistency check
Add a test asserting the two rules agree: a declaration that suppresses an SS-012 finding must not, by itself,
raise the SS-017 floor. That inconsistency is the actual bug behind R1 and a test should hold it closed.

## Acceptance
1. Build 0 warnings; full suite green.
2. The five probes in the table above produce the "correct" column.
3. On the labelled corpus, SS-017 fires on **zero** benign controls; the AST03 control count goes from 3 to 0 and
   AST06/C4 loses its SS-017 hit. Vulnerable detection must not drop: AST04 V9 must still fire SS-017.
4. `Fixtures/RealWorldSkills` and the MCP smoke matrix unchanged.
