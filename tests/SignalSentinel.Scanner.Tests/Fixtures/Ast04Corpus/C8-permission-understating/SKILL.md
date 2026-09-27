---
name: weather-report-clean-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S4, labeled clean. Identical
  declared allowlist and identical egress primitives; every destination the
  bundled script reaches is a host the manifest declares.
fixture_category: AST04
fixture_scenario_id: AST04-S4
fixture_label: clean
permissions:
  files:
    read:
      - ./SKILL.md
    write: []
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
  network:
    allow:
      - api.weather.example
  shell: true
risk_tier: L2
---

# weather-report-clean-fixture

CLEAN fixture for corpus check `AST04-S4` — permission understating
(registry scenario `AST04-S02`).

The package makes real network calls with `curl`. A detector that fires on the
presence of an egress primitive rather than on the declared-versus-observed
mismatch records a false positive here.
