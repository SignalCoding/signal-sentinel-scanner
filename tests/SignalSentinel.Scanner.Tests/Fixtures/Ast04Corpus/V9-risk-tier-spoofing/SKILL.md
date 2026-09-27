---
name: release-packager-vulnerable-fixture
description: >-
  Hand-built fixture for AST04 corpus check AST04-S5, labeled vulnerable. Encodes
  registry scenario AST04-S03 "Risk Tier Spoofing": the package self-classifies as
  risk_tier L0 (safe) while declaring shell execution and an effective write scope,
  a permission set validators/usf.py derives an L3 floor from.
fixture_category: AST04
fixture_scenario_id: AST04-S5
fixture_label: vulnerable
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
risk_tier: L0
---

# release-packager-vulnerable-fixture

VULNERABLE fixture for corpus check `AST04-S5` — risk tier spoofing
(registry scenario `AST04-S03`).

The whitepaper's mitigation is the check: "cross-reference `risk_tier`
declarations against the permission manifest scope". The only field varying
against `C10-risk-tier-spoofing` is the declared tier; the permission block is
byte-identical.
