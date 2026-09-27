# Delegation log: ast04-metadata-integrity

Owner approved the spec 2026-09-27 ("approved. Lets get this fixed!").

## Provenance review of the vendored fixtures (orchestrator, before delegating)
Required by spec section 5 before any of `jhkchan/ast10-agent-skills` is committed.
- Licence Apache-2.0; upstream commit `58c2768`.
- V1 payload is `display_name: !!python/object/apply:os.system ['id']`. `id` prints the current user and is a
  benign proof-of-concept, not a destructive command. It executes only if `loader.py` is deliberately run;
  Sentinel parses statically and never executes fixture content.
- The vulnerable loader is `yaml.load(...)` with no SafeLoader; the control is `yaml.safe_load(...)` with an
  explanatory comment. The pair is exactly the two-part shape the spec describes.
- **Verdict: safe to vendor.** Attribution and the payload's behaviour must be recorded in the fixture NOTICE.

## 2026-09-27 (test)
- **Phase:** test - **Agent:** test-writer - **Model:** Sonnet 5 - **Response:** auto
- **Classification:** new detection with new file ingestion; medium risk; novel-ish (two-part shape, new file class);
  large diff. Posture RESTRICTED / governance ENHANCED.
- **Reason:** the labelled corpus is the oracle and the acceptance is two-sided (5/5 detect, 0/5 controls). Designing
  that harness is the substance of the phase. Routing default applies.
- **Correction count:** 0 - **Outcome:** dispatched

## 2026-09-27 (implement)
- **Phase:** implement - **Agent:** coding-agent - **Model:** Sonnet 5 - **Response:** auto
- **Classification:** new rule over three construct families + a frontmatter parser change with wide blast radius +
  an existing-rule extension. Medium-high risk (the parser feeds SS-012, SS-017 and SS-028); novel; large diff.
- **Reason:** spec section 6 fully enumerates the corrected design; the two-sided corpus harness is the oracle.
- **Correction count:** 0 (section 6 is a spec amendment from the red phase, not an agent error)
- **Outcome:** dispatched

### Red baseline
Failed 39, Passed 1784, Total 1823. Ten vendored AST04 fixtures (Apache-2.0, provenance-reviewed above).

## 2026-09-27 (correction round 1)
- **Agents:** coding-agent (D1, SS-012 declarations) and test-writer (D3, harness split), both Sonnet 5, auto.
- **Issue:** not agent error. Implementation is spec-faithful; the harness encodes the superseded instruction, and
  verification surfaced a pre-existing SS-012 false positive on the C8 control that the new nested parsing makes
  fixable. D2 (egress allowlist vs actual destinations) is deferred to its own spec.
- **Correction count:** 1 each - **Outcome:** dispatched
