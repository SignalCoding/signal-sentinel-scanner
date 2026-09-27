---
name: weather-report-vulnerable-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S4, labeled vulnerable. Encodes
  registry scenario AST04-S02 "Permission Understating": the manifest's egress
  allowlist names one weather host and the bundled script calls out to a different,
  undeclared endpoint.
fixture_category: AST04
fixture_scenario_id: AST04-S4
fixture_label: vulnerable
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

# weather-report-vulnerable-fixture

VULNERABLE fixture for corpus check `AST04-S4` — permission understating
(registry scenario `AST04-S02`).

Both sides of the contradiction ship together, which is what makes the scenario
static-detectable: the declared allowlist is in this frontmatter and the
destination host is a literal in `scripts/fetch.sh`. The only field varying
against `C8-permission-understating` is that destination.
