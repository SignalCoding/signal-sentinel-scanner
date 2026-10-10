---
paths: ["**/*Prompt*", "**/*Llm*", "**/*LLM*", "**/*Sanitiz*", "**/*ModelClient*", "**/Ai/**", "**/AI/**", "**/*OpenAi*", "**/*Anthropic*", "**/*Completion*"]
---
# Scoped Rule: Untrusted Input To LLMs (CONSTITUTION #8)

Applies to any code that sends external or user-supplied data to a language model (CV text,
scraped content, uploaded documents, form free-text, third-party API responses) or acts on what
the model returns. The model is an untrusted boundary in both directions.

## Prompt construction
- Task instructions go in the system field only; never in the same field as untrusted content.
- Untrusted input is wrapped in explicit data delimiters (`<cv_text>...</cv_text>`) and the model is
  told that everything inside is data, never instructions.
- Sanitise before inclusion at the single `SanitizeAiInput()` chokepoint, never per call site.
- Validate every value the model returns that is used programmatically (codes, enums, IDs,
  categories) against the authoritative catalogue before use; a value outside it is a rejection,
  never a default.
- Never log raw model responses for inputs that may carry sensitive or injected content; log token
  counts and metadata.

## The pipeline shape (one implementation of each stage)
- `ISanitizeAiInput`: one registered implementation; `SanitizeAiInput(text, purpose)` is the only
  entry point. It strips control, zero-width and bidi characters, neutralises delimiter tokens,
  NFKC-normalises, enforces the documented length cap, and returns a value type that says it has
  been sanitised.
- Delimiter wrap: one prompt-builder helper places the sanitised value inside the data tags and the
  instructions in the system field; feature code never string-concatenates a prompt.
- Model call: one typed client over one `HttpClient`, behind the outbound allow-list
  (`.claude/rules/azure.md`).
- Output validation: one validator per output shape, checking against `Permissions.*`, the EF
  lookup table or the enum.
- The Architecture tests assert the shape: no type outside the pipeline assembly references the
  model client, and every call site takes the sanitised value type, not `string`. A second
  `SanitizeAiInput` anywhere is the copy-paste finding of CONSTITUTION #25.

## Routing and tests
- Any service that sends external data to a model routes to `coding-agent-security` and gets a
  `security-reviewer` pass before merge.
- Every task group that adds or changes a model call, prompt template, sanitiser or validator
  carries the adversarial-corpus test category of `.claude/rules/testing.md` in its red phase.
