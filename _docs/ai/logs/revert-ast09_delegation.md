# Delegation log: revert SS-024 -> AST09

Owner instruction "go with your recommendation" (2026-09-27), answering the open decision in
`_docs/ai/completed/2026-09-27_ast-benchmark-and-ast10-decision.md` section 4.

## 2026-09-27 (implement)
- **Phase:** implement - **Agent:** coding-agent - **Model:** Sonnet 5 - **Response:** auto
- **Classification:** four-file mapping revert; no detection logic; low risk; small diff. It changes a public
  governance claim, so Sonnet rather than Haiku despite being mechanical.
- **Reason:** decision is made and fully specified; execution is mechanical but touches a claim, so precision matters.
- **No red phase:** the existing coverage guard is the oracle. It must go from passing with one exception to passing
  with two, and must still fail for any third category.
- **Correction count:** 0 - **Outcome:** dispatched
