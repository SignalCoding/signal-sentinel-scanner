# Decision Log

One numbered list, monotonically increasing, never renumbered, never deleted (v2.7.0
convention, adopted from an external collaborator's field-tested workflow). Every deviation
and judgment call gets an entry: WHAT was decided, WHY, and what EVIDENCE backs it. A
decision later reversed gets a NEW entry pointing back at the old one - history stays intact.

Items waiting on the human carry the greppable marker `OWNER-PENDING` in their entry;
`grep -n "OWNER-PENDING" _docs/ai/decision-log.md` is the authoritative open-items list.
When an item resolves, rewrite the marker to `was OWNER-PENDING` so history reads cleanly
without counting as open.

ADR-class decisions (architecture) still get full ADRs; this log is for everything smaller
that would otherwise live only in a session transcript.

---

1. (seed) Decision log adopted at bootstrap. Evidence: this file.
