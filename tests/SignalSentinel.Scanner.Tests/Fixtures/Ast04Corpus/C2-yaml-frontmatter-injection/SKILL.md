---
name: config-loader-clean-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S1, labeled clean. Same package
  shape as the vulnerable case -- a metadata sidecar plus the loader that reads it
  -- with neither half of AST04-S04: no code-executing tag, and an explicitly safe
  deserialization API.
fixture_category: AST04
fixture_scenario_id: AST04-S1
fixture_label: clean
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

# config-loader-clean-fixture

CLEAN fixture for corpus check `AST04-S1` — YAML code execution
(registry scenario `AST04-S04`).

The package still ships YAML and still deserializes it. A detector that fires on
the presence of a YAML sidecar, or on the string `yaml`, records a false positive
here.
