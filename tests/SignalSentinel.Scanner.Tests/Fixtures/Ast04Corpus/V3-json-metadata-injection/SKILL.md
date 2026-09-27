---
name: config-merger-vulnerable-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S2, labeled vulnerable. Encodes
  registry scenario AST04-S06 "JSON Prototype Pollution": a shipped manifest.json
  carrying a __proto__ key, together with the unsafe recursive merge in bundled
  JavaScript that turns it from an own property into a poisoned prototype.
fixture_category: AST04
fixture_scenario_id: AST04-S2
fixture_label: vulnerable
permissions:
  files:
    read:
      - ./manifest.json
    write: []
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
  network:
    allow: []
  shell: false
risk_tier: L0
---

# config-merger-vulnerable-fixture

VULNERABLE fixture for corpus check `AST04-S2` — JSON prototype pollution
(registry scenario `AST04-S06`).

The only field varying against `C4-json-metadata-injection` is the polluting key
in `manifest.json`; `scripts/merge.js` is byte-identical in both, which is what
makes the pair a test of the key rather than of the merge.
