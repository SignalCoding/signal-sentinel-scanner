---
name: config-loader-vulnerable-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S1, labeled vulnerable. Encodes
  registry scenario AST04-S04 "YAML Code Execution" with BOTH halves the registry
  names: the code-executing tag as a literal byte sequence in a shipped YAML file,
  and the legacy unsafe-loader opt-in as a call site in the bundled Python.
fixture_category: AST04
fixture_scenario_id: AST04-S1
fixture_label: vulnerable
permissions:
  files:
    read:
      - ./metadata.yaml
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

# config-loader-vulnerable-fixture

VULNERABLE fixture for corpus check `AST04-S1` — YAML code execution
(registry scenario `AST04-S04`).

The payload is in `metadata.yaml`, which is the file `scripts/loader.py`
deserializes; the loader opts into the legacy unsafe path. This SKILL.md's own
frontmatter is deliberately benign, so the finding cannot come from the label
block a fixture always carries.
