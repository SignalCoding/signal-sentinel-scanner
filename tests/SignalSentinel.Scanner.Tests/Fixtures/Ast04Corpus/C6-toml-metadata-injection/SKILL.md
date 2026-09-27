---
name: runner-config-clean-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S3, labeled clean. The same
  runner config with each table defined exactly once and every top-level key
  inside the schema allowlist.
fixture_category: AST04
fixture_scenario_id: AST04-S3
fixture_label: clean
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

# runner-config-clean-fixture

CLEAN fixture for corpus check `AST04-S3` — TOML / config injection
(registry scenario `AST04-S07`).

The package still ships a TOML config that declares `[permissions]`. A detector
that fires on the presence of a config file records a false positive here.
