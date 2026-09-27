---
name: release-packager-clean-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S5, labeled clean. The same
  shell-plus-write permission set, declared honestly at the L3 floor that set
  derives to.
fixture_category: AST04
fixture_scenario_id: AST04-S5
fixture_label: clean
permissions:
  files:
    read:
      - ./SKILL.md
    write:
      - reports/summary.md
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
  network:
    allow: []
  shell: true
risk_tier: L3
---

# release-packager-clean-fixture

CLEAN fixture for corpus check `AST04-S5` — risk tier spoofing
(registry scenario `AST04-S03`).

Clean does not mean low-privilege: this package holds exactly the destructive
capability the vulnerable one does. What makes it clean is that the declaration
matches the scope. A detector that fires on a broad permission set rather than on
an under-declaration records a false positive here.
