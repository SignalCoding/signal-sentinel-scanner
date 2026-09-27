# Spec: SS-043 Unenforced Cross-Platform Safety Declaration (closes AST10)

> **SUPERSEDED 2026-09-27. Do not implement.** Measurement against a public corpus and a third-party
> labelled fixture set showed the premise below does not match reality, that a third reading of AST10
> exists, and that Sentinel already detects 3 of 3 of that reading's vulnerable fixtures with no new
> code. See `_docs/ai/completed/2026-09-27_ast-benchmark-and-ast10-decision.md` section 3.

**Status:** draft for owner approval. **Recommended sequencing: approve now, build after Jon's corpus arrives** (section 6).
**Branch (proposed):** `feat/ss-043-cross-platform` from `main` @ `8460eaf`.
**Closes:** the single documented exception in the coverage guard, `AST10 Cross-Platform Reuse`, left open by `owasp-full-coverage.md` section 5.
**Rule count:** 48 -> 49 (42 detection + 7 informational). The parity guard from #86 will enforce the nine-surface ripple.

---

## 1. What AST10 actually means, narrowly

OWASP AST10 is "Cross-Platform Reuse - skill mixes incompatible platform semantics unsafely". Read loosely it is a
portability bug and not a security finding. The security content is narrower and worth stating precisely, because it
determines the whole design:

> A skill's safety rests on a declaration that only one host enforces. Moved to a host that ignores that field, the
> restriction silently evaporates while the skill's instructions still assume it applies.

A skill declaring `allowed-tools: Read` is constrained under a host that honours it and completely unconstrained
under one that does not, with no error and no warning. That is the shape this rule detects. Everything else in the
"cross-platform" space is a defect rather than a vulnerability and is explicitly out of scope.

---

## 2. Why the scanner can already do this

No new parsing is required. The inputs exist:

| Input | Where | Use |
|---|---|---|
| `SkillDefinition.SourcePlatform` | set by `SkillDiscovery` at its four `SkillReader` call sites | which host the skill was actually found under |
| `SkillDefinition.ExtraFrontmatter` | `FrontmatterParser` | arbitrary frontmatter, so `allowed-tools`, `risk_tier`, host-specific keys |
| `SkillDefinition.Capabilities`, `.DenyWrite` | Universal Skill Format block parsing | declared restrictions |
| Identity-file knowledge | `SkillIdentityFileWriteRule` (SS-028) already models `CLAUDE.md`, `AGENTS.md`, `MEMORY.md`, `SOUL.md` | host markers, and a write-shape detector to reuse |
| Platform config shapes | `Config/ConfigDiscovery.cs` knows Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Gemini CLI, OpenCode, GitHub, Factory | host markers |

**Implementation note:** confirm the exact label set `SkillDiscovery` assigns to `SourcePlatform` before relying on
it; the four call sites pass it explicitly and the vocabulary was not verified when writing this spec.

---

## 3. Requirements

### R1 - The detection, one shape only
Fire when **both** hold for a skill:

**(a) It carries a host-scoped safety declaration.** At least one of:
- `allowed-tools` / `allowed_tools` in frontmatter (Claude Skills / Claude Code)
- a Universal Skill Format `capabilities:` block
- `permissions.deny_write`
- `risk_tier`

**(b) It carries evidence of a different host.** At least one of:
- a **write** to another host's identity file, detected with SS-028's existing shape logic, not a bare mention
- a reference to another host's config path (`~/.claude.json`, `.cursor/`, `.gemini/`, `opencode.json`, `.factory/`, `.github/`)
- `SourcePlatform` names a host that does not honour the field declared in (a)

The finding says: the declaration in (a) is not enforced on the host implied by (b), so the restriction it appears to
impose does not apply there.

### R2 - Graduated severity, in the style of SS-016 and SS-008
- **High** when the void declaration would have restricted a capability the skill demonstrably uses. Reuse the
  existing capability detection from SS-012 (post-3.0.2, verb-shaped) so that, for example, `allowed-tools: Read`
  alongside an observed shell or network capability is High.
- **Medium** when the declaration is void but no matching dangerous capability is observed.
- Never Critical. This is a control that fails open, not an active attack.

### R3 - False-positive guards, stated before the code exists
This is the third rule in three releases whose failure mode would be context-blind matching, so the guards are
requirements, not afterthoughts:
- **Mentions are not uses.** Host markers are counted only in prose and frontmatter segments via `SegmentFilter`,
  never inside fenced or inline code. A skill-authoring guide that shows `CLAUDE.md` in an example block must not fire.
  `skill-creator` and `mcp-builder` in the existing fixture corpus both discuss platform conventions and are the
  reference negatives.
- **Deliberate portability is not a defect.** If the skill explicitly declares multiple hosts (a `platforms:` field
  or equivalent), it has been authored for portability: do not fire, or record informationally only. Decide from
  fixture evidence, not in advance.
- **A declaration honoured where it runs is fine.** If (a) and `SourcePlatform` agree, there is nothing to report,
  however many other hosts are mentioned.

### R4 - Registry and mapping
- `SS-043`, AST code `AST10`, OWASP ASI `ASI02` (Tool Misuse / over-privilege is the closest ASI fit; confirm against
  `OwaspMapping.cs` during implementation). MCP code: none, it is a skill rule.
- All nine registry surfaces per the checklist, enforced by `RuleRegistryParityTests`.
- Remove the `AST10` exception from the coverage guard in `OwaspFullCoverageTests`. The guard must then show
  10/10 on all three frameworks with no exceptions, which is the acceptance signal for this work.

### R5 - Documentation and the claim
- `docs/owasp-ast-mapping.md`: replace the AST10 open-gap note with the coverage statement, 10/10 across all three.
- Supply the corrected website wording, which becomes the plain claim: every category in all three frameworks is
  claimed by at least one rule. That wording is for the owner to approve and is not published by this work.

---

## 4. Fixtures and evidence

The lesson of 3.0.1 and 3.0.2, learned twice: a rule validated only against strings its author wrote is tuned to
those strings.

**Negatives (must produce zero findings):** the seven existing `Fixtures/RealWorldSkills` skills. `skill-creator` and
`mcp-builder` are the load-bearing cases, because they legitimately discuss more than one host.

**Positives:** no public corpus is known to contain the shape, so the first positives must be own-authored and
labelled as synthetic in the fixture NOTICE. At minimum: a skill declaring `allowed-tools: Read` that writes to
`AGENTS.md` and invokes a shell command, which should be High; and a skill with a `capabilities:` block referencing
`.cursor/` config, which should be Medium.

**This is the weak point of the work and the spec says so plainly.** Synthetic positives prove the rule fires; they
do not prove it fires on real skills or stays quiet on real skills that merely look similar.

---

## 5. Acceptance

1. Build 0 warnings; full suite green.
2. Zero SS-043 findings across the existing real-world corpus.
3. Each synthetic positive fires at its specified severity; each negative counterpart stays silent.
4. `--list-rules` and `--help` report 49; the parity guard passes across all nine surfaces.
5. The coverage guard passes **with no exceptions**, and is demonstrated to fail if the AST10 mapping is removed.
6. Live MCP smoke matrix grades unchanged; no existing rule's behaviour altered.

---

## 6. Sequencing, and the honest caveat

**Recommendation: approve this spec now, build it once Jon's sixty-five-skill corpus arrives.** That corpus is the
only realistic source of genuine cross-platform artefacts and of the near-miss cases that would expose a
context-blind first cut. Building before it means shipping a rule whose false-positive behaviour is unmeasured,
which is precisely the position that produced the 3.0.1 and 3.0.2 remediation work.

If the owner prefers to proceed without waiting, that is a legitimate call, but the rule should ship at **Medium
only**, with the High band withheld until real evidence supports it.

**The alternative remains open.** Declining to build this and stating nine of ten permanently, on the grounds that
AST10 is partly about organisational reuse practice rather than properties of a single artefact, is defensible to
the same audience. The reason to build SS-043 is that a safety declaration which silently fails open is worth
detecting on its own merits. If that argument does not stand up, the coverage number is not a sufficient reason.
