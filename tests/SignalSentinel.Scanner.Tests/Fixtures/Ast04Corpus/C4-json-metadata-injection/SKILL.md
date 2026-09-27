---
name: config-merger-clean-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S2, labeled clean. Ships the
  same recursive merge as the vulnerable case and a manifest.json with no
  prototype-pollution key, so the pair isolates the key.
fixture_category: AST04
fixture_scenario_id: AST04-S2
fixture_label: clean
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

# config-merger-clean-fixture

CLEAN fixture for corpus check `AST04-S2` — JSON prototype pollution
(registry scenario `AST04-S06`).

A detector that fires on the presence of a recursive merge alone records a false
positive here: the merge is shipped and the manifest is not poisoned.
