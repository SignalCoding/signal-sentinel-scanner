---
name: runner-config-vulnerable-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S3, labeled vulnerable. Encodes
  registry scenario AST04-S07 "TOML / Config Injection": the shipped runner config
  redefines the [permissions] table, so the declared posture is silently overridden
  by whichever definition the runner's precedence rule happens to keep.
fixture_category: AST04
fixture_scenario_id: AST04-S3
fixture_label: vulnerable
permissions:
  files:
    read:
      - ./config.toml
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

# runner-config-vulnerable-fixture

VULNERABLE fixture for corpus check `AST04-S3` — TOML / config injection
(registry scenario `AST04-S07`).

`config.toml` defines `[permissions]` twice. `tomllib` raises on the
redefinition, which is why a detector that parses first and scans second cannot
see this shape at all.
