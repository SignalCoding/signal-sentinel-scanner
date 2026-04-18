# Signal Sentinel Scanner - v3.0.0 Roadmap

Status: Draft. Positioning pivot document. Quarter-scale bets, not sprint items.

## Why v3.0.0 and not v2.x

Three changes in this roadmap individually satisfy the SemVer MAJOR threshold; any
one of them alone would justify a major bump, and shipping them under a single major
version is both cleaner and better marketing:

1. **Monotonic scoring contract.** We publish a versioned rubric and commit that
   applying any of our recommended remediations cannot worsen the user's grade.
   Introducing a versioned contract is a canonical MAJOR moment even when no output
   schema changes.
2. **Behavioural pivot in detection.** Context-aware matching + natural-English
   keyword pruning will measurably shift grade distributions on unchanged skill
   source. v2.2 users whose CI gates on `grade < B` will see pass/fail flips that
   have nothing to do with their own code. SemVer requires a major bump.
3. **Strategic positioning reset.** We publicly reframe from "authoritative audit"
   to "fast, deterministic, first-pass authoring aid, and orchestrator for a multi-
   tool defence-in-depth chain". A positioning reset deserves a major version to
   carry the narrative.

v2.3.0 ships the cheap credibility fixes first (see `BACKLOG_V2.3.0.md`) so we buy
goodwill while this roadmap cooks.

## Market context (post-Mythos)

The product-feedback document (`C:\Sites\CryptoTrader\Skills\SIGNAL_SENTINEL_PRODUCT_FEEDBACK.md`)
argues that the AI vulnerability-discovery landscape has fundamentally shifted with
Anthropic's Claude Mythos Preview (7 April 2026) and that regex-only defence has a
12-18 month shelf life. Two caveats before we build strategy on that claim:

- The Snyk "Skill Scanner = False Security" (February 2026) and SafePrompt.dev
  "Why Regex Fails for Prompt Injection Detection" (January 2026) numbers are
  peer-checkable and tool-measurable; these alone justify the strategic direction
  even if every Mythos-specific number turns out to be over-stated.
- The specific Mythos numbers (181 Firefox exploits, 3.6B-model reproduction by
  AISLE, etc.) should be independently verified before we anchor public marketing
  material on them. The strategy works without them; they are decoration, not
  foundation.

Directionally, then: treat v3.0 as "post-Snyk-post-SafePrompt" regardless of how the
Mythos specifics shake out. That gives us defensible ground under any plausible
scenario.

## Positioning statement (draft for v3.0.0 launch)

> Signal Sentinel is the fast, deterministic, offline-capable first-pass
> authoring aid for skill authors, and the orchestration layer that combines
> regex scanning, semantic LLM analysis, credential scanning, and runtime
> observability into a single defensible defence-in-depth signal.
>
> We are not, and do not aim to be, a standalone audit tool. For audit-grade
> verification we recommend running Signal Sentinel alongside at least one
> semantic scanner (Enkrypt Skill Sentinel, Snyk agent-scan, Anthropic
> Claude-based semantic scan) and at least one code-level scanner (Bandit,
> Semgrep). Signal Sentinel's `audit` command orchestrates all of these.

This language lands in `README.md`, `SECURITY.md`, the website, and the pinned
repo description at v3.0.0 release.

## Theme 1 - Detection correctness reset

### T1.1 Context-aware pattern matching (product-feedback #1)

**Proposal:** Segment every scanned document before applying rules, using a
Markdown parser (`Markdig` is already in the dotnet ecosystem and is Apache-2.0):

- YAML frontmatter -> strict capability/identity rules only.
- Prose paragraphs -> natural-language rules only (prompt-injection linguistic
  markers, not dangerous-code patterns).
- Fenced code blocks (with language hint) -> language-specific code rules
  (`fetch(` is a JS call in a ```js block, an English verb everywhere else).
- Inline code (backtick-wrapped) -> treat as quoted example; relax dangerous-
  pattern rules, keep credential/url rules.

Every rule declares which segments it operates on. The rule engine dispatches
per-segment rather than per-document. This is a substantial refactor inside
`RuleEngine` and every `IRule` implementation.

**Expected impact:** ~80% reduction in the false-positive class observed across
the CryptoTrader feedback (confirmed in the feedback document cross-check).

**Risks:** grades shift on unchanged source (hence v3.0). Risk of over-pruning if
a rule's segment declaration is too narrow - mitigated by the benchmark corpus
(see T3.2).

**Effort:** 2-3 weeks.

### T1.2 Monotonic scoring contract (product-feedback #2)

**Contract:** Applying any Signal Sentinel-generated remediation cannot worsen
the user's grade. Formally:

    for any skill S, any finding F in scan(S), any remediation R in F.remediation,
        grade(apply(R, S)) >= grade(S)

**Implementation:**
- Rubric is externalised as `scoring-rubric-v2.0.0.json`, version-stamped, and
  loaded at scan time. Stable across minor versions of v3.x; changes require a
  new v4 rubric.
- Property-based test suite (FsCheck or Hedgehog - both are MIT-licensed and
  dotnet-compatible) generates synthetic skills, applies each remediation the
  scanner emits, and asserts grade monotonicity. This runs on every PR.
- Rebalance rule weights so closing SS-012 cannot expose a latent SS-022 etc.
  The existing scoring system penalises both "many findings" and "missing
  explicit disclosure"; these must be made non-contradictory.

**Expected impact:** restores trust in grades as a progress signal.

**Effort:** 1.5-2 weeks (mostly rebalancing and test harness).

### T1.3 Natural-English keyword pruning (product-feedback #3)

**Proposal:** Align our suspicious-keyword list with Snyk `agent-scan` W001 as the
industry reference, pending any stronger industry standard.

- Current canonical list (Snyk W001):
  `important, crucial, critical, vital, urgent, ignore, disregard, override, bypass`
- Remove from Signal Sentinel: `must` (as a bare token), `fetch` (as a bare
  token). Keep `fetch(` only inside `js`/`ts` code blocks (requires T1.1).
- Remove entirely: `when the user asks` - this is canonical OpenClaw phrasing
  used in every platform skill description.

Document the rationale and the reference (Snyk W001 commit pin) in
`docs/keyword-rules.md`.

**Effort:** half a day of rule curation + 2 days of regression testing against
the benchmark corpus (T3.2).

### T1.4 Remediation diff suggestions (product-feedback #9)

**Proposal:** Every finding emits a unified-diff `suggestedFix` block:

    -  /root/crypto-portfolio/state/prices.json
    +  ${CRYPTO_PORTFOLIO_ROOT:?CRYPTO_PORTFOLIO_ROOT required}/state/prices.json

Plus a `sentinel-scan --fix` mode that auto-applies accepted fixes in place with
a `.bak` file alongside.

Depends on T1.1 (we cannot produce a correct diff without knowing the segment
context).

**Effort:** 1 week core + 0.5 day per rule that opts in (not all rules will).

## Theme 2 - Hybrid defence

### T2.1 Regex-first + LLM-second pipeline (product-feedback #10)

**Architecture:**

    SKILL.md -> Signal Sentinel regex (fast, deterministic, offline-capable)
             -> candidate findings [~N]
             -> LLM classifier (batched, one API call per skill)
             -> confirmed findings [~N - FP] + suppressed-with-explanation [FPs]
             -> user

**Concrete options:**

- **Cloud** (default): Claude Haiku 4.5 via `--llm claude-haiku`, ~$0.001 per
  scan. API key via `ANTHROPIC_API_KEY` env var.
- **Cloud alternative**: GPT-4.1-mini or equivalent via `--llm openai-mini`.
- **Local / privacy-preserving**: Ollama with a small local model
  (`--llm ollama:llama3.2:3b`). Slower but no data leaves the machine.
- **Bring-your-own-endpoint**: `--llm-endpoint https://host:port/v1` for air-
  gapped or enterprise-hosted models.

**Default behaviour:** off. Users opt in with `--llm <provider>`. We do **not**
auto-send skill content to any cloud endpoint without explicit flag. This is
non-negotiable for privacy and compliance.

**Offline guarantee:** the offline-guard infrastructure added in v2.2 continues
to enforce that `--offline` blocks all LLM calls.

**Effort:** 3-4 weeks for the core pipeline + pluggable provider interface.

### T2.2 Cross-skill attack-path reasoning (product-feedback #17)

**Extension of existing work:** we already ship `CrossServerAttackPathRule` for
MCP servers. Extend it to skills:

- Build a capability graph across all skills in a corpus: `{skill -> declared-
  capabilities}` plus `{skill -> observed-capabilities}` (the latter inferred
  from the rules).
- Flag dangerous combinations:
  - one skill has `filesystem_write`, another has `network_send` -> potential
    data-exfiltration chain
  - one skill has `credential_read`, another has any network capability ->
    potential credential-exfiltration chain
  - one skill has `shell_exec`, any other skill -> elevated risk (shell_exec
    alone may compose with anything)
- Emit a new rule `SS-026 Cross-Skill Attack Chain` with evidence listing the
  participating skills and the inferred chain.

**Effort:** 1.5-2 weeks.

### T2.3 Runtime observability integration (product-feedback #18)

**Deferred to v3.1+.** In-scope for v3.0.0 documentation only: we commit to a
partner-integration API (probably OpenTelemetry-based) so third-party runtime
monitors can feed back observed-vs-declared behaviour into the Signal Sentinel
suppression file (auto-accept if runtime confirms; auto-alert if runtime
contradicts).

**v3.0.0 deliverable:** an `SS-OBSERVABILITY.md` design doc describing the API
and calling out which partners we are talking to. No code.

### T2.4 Supply-chain / dependency verification (product-feedback #20)

**Deferred to v3.1+.** Track URLs referenced from skill content; emit an
informational finding per URL with:

- Is it HTTPS?
- Last-modified / ETag for change detection between scans (hook into the
  baseline primitive).
- Alert on content change between scans even if the URL itself is unchanged
  (skill weaponisation TTP).

**v3.0.0 deliverable:** design doc in `SS-SUPPLY-CHAIN.md`. No code.

## Theme 3 - Orchestration and benchmark

### T3.1 Multi-scanner orchestration - `sentinel audit` (product-feedback #11)

**Proposal:** a new top-level command `sentinel audit` that invokes a stable of
tools, not just Signal Sentinel:

    sentinel audit --target ./Skills \
      --scanner signal-sentinel \
      --scanner gitleaks \
      --scanner bandit \
      --scanner semgrep \
      --scanner enkrypt-skill-sentinel \
      --format sarif-unified \
      --output audit-report.sarif

- Each scanner is invoked in a sandboxed subprocess.
- Output is normalised to SARIF v2.1.0.
- We emit a unified dashboard (Markdown + HTML) showing each scanner's findings
  side by side, with a "consensus" column (how many scanners agreed).
- We **do not** redistribute the third-party scanners - users must install them
  via their preferred channel (we document the commands). We just drive them.
- Trivy is a good reference design for this approach.

**Why this matters strategically:** OWASP AST08 ("Poor Scanning") explicitly
requires multi-tool pipelines; the Snyk article explicitly argues against
single-scanner reliance. By becoming the orchestrator we stop competing on
regex accuracy and start competing on orchestration quality - a much more
defensible position and one that compounds with every new scanner plugin.

**Effort:** 3 weeks initial (Signal Sentinel + Gitleaks + Bandit + Semgrep) +
rolling additions.

### T3.2 Public benchmark corpus (product-feedback #12)

**Proposal:** a separate public repository `signal-sentinel-benchmark` that
contains:

- A labelled corpus of skills: `{benign, malicious, borderline}` with ground-
  truth labels and commentary.
- A harness that runs every peer scanner (Signal Sentinel, Snyk agent-scan,
  Enkrypt Skill Sentinel, Claude Haiku, manual AST01-10) nightly against the
  corpus.
- Published FP rate + detection rate leaderboard in the README.
- **Crucially**, the corpus includes Signal Sentinel's own documentation as
  "benign" test cases to prove we do not fall into the "antivirus paradox"
  described by Snyk (a scanner that flags its own reference files as
  dangerous).
- Nightly CI publishes the leaderboard to GitHub Pages so anyone can check the
  current state without cloning anything.

**Why this matters strategically:** it is the single most credibility-building
artefact we can produce, and it directly answers the Snyk post. Even an early
version with 30 test cases is better than nothing.

**Effort:** 2-3 weeks initial corpus + harness.

### T3.3 Adversarial robustness testing (product-feedback #19)

**Proposal:** quarterly release-gate experiment. Take N known-malicious skills
from the benchmark corpus, ask Claude to rewrite each N times with instructions
to preserve the malicious behaviour but evade regex signatures, and measure
detection decay.

Publish the decay curve in every v3.x release's changelog. Formalise the
experiment in `docs/adversarial-benchmark.md`.

**Effort:** 1 week design + 0.5 day per quarterly run.

## Release plan

Rough quarterly shape; treat dates as intent, not commitment:

- **v2.3.0** (sprint, next 3-4 weeks): additive credibility fixes per
  `BACKLOG_V2.3.0.md`. No grade-semantics changes.
- **v3.0.0** (quarter): Theme 1 (T1.1, T1.2, T1.3) + positioning reset + T3.2
  initial benchmark corpus. Breaking change on grade semantics; migration doc
  published.
- **v3.1.0** (next quarter): Theme 2 core (T2.1 hybrid LLM, T2.2 cross-skill
  attack paths, T1.4 remediation diffs).
- **v3.2.0** (following quarter): Theme 3 expansion (T3.1 orchestration beyond
  the initial scanner set, T3.3 adversarial benchmark formalised).
- **v3.3.0+**: runtime observability (T2.3), supply-chain verification (T2.4),
  additional partners.

## Acceptance criteria for v3.0.0

- [ ] Positioning statement lands in README.md, SECURITY.md, repo description,
      website.
- [ ] `scoring-rubric-v2.0.0.json` published; monotonicity property-test suite
      passes on every PR.
- [ ] Context-aware matching in place; every rule declares its applicable
      segments.
- [ ] Keyword list aligned with Snyk W001 reference; deviations documented.
- [ ] Benchmark corpus v0.1 published with at least 30 labelled test cases and
      nightly leaderboard.
- [ ] Migration guide from v2.x to v3.0.0 explains the grade-semantics change
      with worked before/after examples on representative skills.
- [ ] Every listed deferred-to-v3.0 product-feedback item (#1, #2, #3, #9,
      #17 at minimum) shipped or explicitly re-deferred with justification.
- [ ] Test suite growth commensurate (target: ~280 tests at v3.0.0, up from
      195 at v2.2.0 and ~230 at v2.3.0).
- [ ] 0 warnings, 0 errors with `TreatWarningsAsErrors=true`.

## Out of scope for v3.0.0

- Full LLM pipeline (T2.1) - phase in during v3.1.
- Complete orchestrator suite (T3.1) - initial set in v3.0, expansion rolling.
- Runtime observability (T2.3) - design doc only in v3.0; code in v3.1+.
- Supply-chain verification (T2.4) - design doc only in v3.0; code in v3.1+.
- Any migration of MCP-server-side rules beyond adding AST codes (handled in
  v2.3).
- Native VS Code / Cursor extension beyond the MVP in v2.3 (T3 scope is the
  core product).

## Open questions

1. **Rubric ownership.** Who signs off on the v2 scoring rubric before publication?
   Proposal: internal review + post to SECURITY.md for a two-week public comment
   window before v3.0.0 release.
2. **LLM provider defaults.** Claude Haiku 4.5 is the pragmatic default on
   accuracy/cost. Do we want a second provider in v3.1 for vendor risk
   diversification, or is "pluggable provider interface with BYOK"
   sufficient?
3. **Orchestrator licensing.** Each third-party scanner has its own licence.
   `sentinel audit` invokes but does not bundle - is there any legal review
   needed on instructions for downloading/installing the third-party tools?
4. **Benchmark corpus governance.** Who curates test cases and decides
   ground-truth labels? Proposal: three-person review committee, majority
   vote, public dissent noted in corpus commentary.
5. **Breaking-change communication.** How do we tell v2.x users their CI
   gates may flip? Proposal: a v2.9 "preview" release with `--use-v3-
   semantics` flag six weeks before v3.0.0 so users can test in parallel.
