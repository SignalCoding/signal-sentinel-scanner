# Evidence Rules

Read by the test-writer and the coding agents before the first capture of a task group and before
every PASS claim, and by the evaluator before judging. The contract itself (statuses, file types,
gate tokens, scripts) is in `README.md`; this file is how a capture earns its place there.

## Capturing test runs

- One command invocation per `*.testresults.txt`: the suite's totals line and a zero exit, written
  with `>` never `>>`. An appended file is a process log and the evaluator pre-flight refuses it.
- Capture the evidence run separately and last, on the tree you are about to claim.
- Capture on a fresh, clean environment: persisted defaults, caches and saved state make show-once
  behaviour fire in one run and vanish in the next, which reads as a regression and is not one.
- BEFORE captures come off a pure-HEAD build (stash, rebuild, capture, pop; or capture before the
  edit exists). Once the edit lands the old state cannot be reconstructed.
- Resolve paths from the toolchain (the build's own output directory, the runner's own report path);
  never guess a conventional location.
- Never eyeball a measurable claim: sample the pixel, the byte or the number against the pinned value.
- Transient states need burst capture or video plus an independent confirmation that the mechanism
  fired (a flag, a log line); one sleep-then-screenshot misses them.
- A committed verifier script is calibrated against known-good AND known-bad inputs before it is
  trusted, and the calibration run is part of the evidence. The same holds for a guard test: revert
  one entry, show the test names it, restore. A check that has never failed has proven nothing.
- A criterion proven against a corpus (benchmark, fixture set, reference dataset) records the corpus
  SHA-256 and the commit measured, in the file name or its first line; a number without both is an
  anecdote. When a change touches detection, scoring or classification, re-run the corpus and cite
  before and after; a green suite is necessary, not sufficient.
- A text search over source is not a completeness claim: it matches comments and string literals.
  Assert with the compiler, reflection or a parser; where grep is the only option, strip comments
  and literals first and say so in the evidence.

## Red baseline file

- Every failing test in `<TG>.red.testresults.txt` fails on an assertion about the target
  behaviour, not on a compile error, a missing route, an import, or a fixture that reuses an identity.
- The file carries one `# red-reason <test>: <assertion that fails and why>` line per failing test,
  above the runner output. A red that is really a compile failure, or a file with no red reasons,
  is a finding.
- Commit the red file on its own before any green evidence exists (`README.md`, Red baseline).

## Screenshots and text assertions

- A screenshot proves what is present and how it is arranged. It does not spell: a label, a
  message, a count or a spelling is never asserted from an image.
- Any textual claim is corroborated against the source, the DOM or the page text before it enters a
  criterion, a defect list or a client report, through a `*.uatresults.txt` or `*.http.txt` whose
  content includes the asserted text.
- Match on a stable substring, never on a full rendered string carrying a timestamp, a counter or
  framework-injected markup (scoped-CSS attributes, hydration markers, nonces). Whole-tag literal
  matches produce false negatives that read exactly like defects.
- Name the image for what it shows (`FEAT-C2-denied-state.png`): the evaluator cannot read images
  and the name is the only claim the file makes to it.
- For a UI criterion built against a LOCKED mockup, the evidence is the pair (rendered screenshot,
  reference mockup file); conformance is judged by the evaluator or a read-only agent, never by the
  agent that built the screen.
- An interaction artefact (`*.uatresults.txt`) is the output of a render-and-act test or a
  driven-browser smoke run covering the enhanced behaviour plus one graceful-failure path.

## HTTP and header evidence

- Record the exact command on the first line of the `*.http.txt`, then the raw output.
- Headers: `curl -sI <url>` (headers only), on the apex as well as the www host where both serve.
  Assert the header set against the one source that declares it in `_docs/ai/configuration.md`,
  never against a document that says it is set.
- Bodies: `curl --compressed`, so a Brotli or gzip body is decoded before you grep it; an undecoded
  body that "contains nothing" is an encoding failure, not a result.
- Liveness is not correctness. A 200 or 302 after deploy proves the app is UP. "Fix behaves as
  intended" is a second, labelled check: a functional probe that provokes the behaviour (the denied
  request actually denied, the malformed input rejected) or an automated test. Never infer the second
  from the first; when the behavioural half cannot run yet, sub-scope and BLOCK it on its gate.
- Silent-by-design components (reconcilers, seeders, migrations that catch and log) need read-back
  evidence: a log excerpt showing the step ran, or a targeted read query showing the rows landed.
  "It did not crash" is not evidence it ran.

## `.live.` captures

- A `.live.` file is captured from the DEPLOYED environment, exercised as a user would; a local
  capture renamed is a false claim. Where the criterion is about failure behaviour, the live capture
  provokes the failure.
- A new external provider or integration is proven by `<ID>.live.log`: a script starts the process,
  probes it through the PRODUCTION registration code (not the spike) and stops it; identifiers are
  redacted in the input and asserted absent in the output. Mocked green does not mean working.
- A green suite says nothing about configuration, service versions, real payloads or the deployed
  environment; the number that matters is criteria evidenced live, not the test count.

## Cloud CLI identity

- Before any cloud CLI command whose output will inform a claim or a capture, confirm the identity
  and target (`az account show`, `gcloud config list`, `aws sts get-caller-identity`,
  `gh auth status`, or the stack's equivalent) and state the verified account, tenant, subscription
  or project by NAME in the evidence, never a secret. CLIs re-authenticate and switch silently;
  "not found" under the wrong account is indistinguishable from "does not exist".
- A test that calls a cloud through the developer's CLI login holds the same roles as the identity
  the code uses in production, or it proves nothing about production authorisation.

## Process logs, CI runs and sign-off

- Build output, server logs, watch output and any running record live in `_docs/ai/logs/`; a file
  in `evidence/` is a claim about a criterion and nothing else.
- When local infrastructure is unreliable, CI is the confirming run and the evidence says so
  (`local run skipped: <reason, time>; CI run <id> is the cited artefact`); never silently assumed.
- A criterion only the owner can confirm is BLOCKED on `SIGN-OFF` with the owner named and the exact
  yes/no question. When the answer arrives, `<ID>.uatresults.txt` quotes the owner verbatim (date,
  channel, exact words) and states what the agent could not view itself; `set-criterion.sh` moves
  the row to PASS against that file.

## Before the evaluator, and what it refuses

Re-read every file a PASS criterion cites and confirm the file ITSELF demonstrates the claim: one
run, zero failures, zero exit; the asserted behaviour and not merely a 200; an image whose name
states the asserted element. The evaluator refuses, as a finding against every criterion citing it:

- a `*.testresults.txt` holding more than one test-run summary (refused before any model call);
- an image whose name does not say what it shows, or an image cited for text content;
- a red baseline with no red-reason lines, or one that is really a compile failure;
- a ui group with no `.live.` file and no criterion BLOCKED on `DEPLOY`;
- a BLOCKED row whose gate token is missing or unrecognised, or whose disposition names a topic
  instead of a question;
- the PASS half of a split criterion whose stub bypasses the real logic;
- evidence cited by a row but present in neither `evidence/` nor `_docs/ai/completed/<slug>-evidence/`.
