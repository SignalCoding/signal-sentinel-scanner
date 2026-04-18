# Confidence Rubric (v1.0)

Every Signal Sentinel finding carries a numeric `confidence` value between 0.0
and 1.0. The scanner computes confidence from the properties of the match itself
(pattern specificity, corroborating signals, size of the matched surface) and
uses it to drive triage-mode demotion and `--min-confidence` filtering. This
document defines the buckets so that consumers can tune CI gates predictably.

## Buckets

| Bucket     | Confidence  | Meaning                                                                                                                                          | UI label   |
|------------|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| High       | >= 0.90     | Strong, corroborated signal. Likely true positive. Safe to treat as blocking.                                                                    | `high`     |
| Medium     | 0.70 - 0.89 | Clear pattern match but lacking corroborating context (e.g., intent phrases). Block in prod, warn in dev.                                        | `medium`   |
| Candidate  | 0.50 - 0.69 | Heuristic match. Worth reviewing but likely needs a human to confirm. Demoted to Low when `--triage` is enabled.                                 | `candidate`|
| Weak       | < 0.50      | Speculative — kept for completeness. Filtered out by default with `--min-confidence 0.5`.                                                        | `weak`     |

## CLI interaction

- `--min-confidence <float>` (default `0.0`): hard filter — findings below the
  threshold are dropped from the report and never influence the score or grade.
- `--triage`: findings below `0.75` are kept but demoted to `Severity.Low`.
  Useful when you want visibility without blocking CI.
- `--fail-on <severity>` (default `high`): gates on the *surviving* severity
  after the above two filters run.

## How confidence is computed

Confidence is set by each rule at finding time. The typical contributions are:

- **Pattern precision** (+0.2 for a named regex with boundary anchors, +0.05 for
  a substring fallback).
- **Context corroboration** (+0.1 when surrounding text contains intent
  markers, e.g. `export`, `send`, `reveal`).
- **Source trust** (+0.1 for a code block inside a SKILL.md body vs prose).
- **Size of the match** (+0.05 for matches >= 8 chars).
- **Baseline ceilings** - authentication/transport rules cap confidence at 0.85
  because they're inferred from config, not exercised.

All contributions are clamped into [0.0, 1.0] before the finding is emitted.

## Forward compatibility

The rubric is versioned. Each scan result now includes:

```
"rubricVersion": "1.0"
```

If the computation changes materially (e.g. v2.0 in SS 3.0.0) you can continue
to compare runs under the previous rubric by filtering to runs with the same
`rubricVersion`. Mixed-rubric comparisons are explicitly disallowed by the diff
command.
