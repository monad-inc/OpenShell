---
name: root-cause-analysis
description: Go from a telemetry lead to a specific code cause, and decide whether the evidence justifies opening a PR. Use only after grafana-investigation produces a concrete lead.
---

# Root Cause Analysis

Only start this once telemetry points somewhere specific. Cloning a repository
to browse it "for context" burns the cycle and finds nothing.

## Entry condition

You need at least: an onset time, an implicated service, and a symptom you can
state precisely. Without all three, stop and report findings — this skill will
not manufacture the missing one.

## Narrowing

Clone only a repository listed in `github.repos`. The provider profile permits
the whole org, but the config is narrower on purpose: staying inside it keeps
scope changes reviewable rather than accidental.

```bash
gh api "repos/<repo>/commits?until=<onset-iso>&per_page=20"
```

Work from the onset backwards:

1. **What shipped before onset?** Commits and deploys in the window preceding
   it. A deploy annotation from Grafana usually maps to a merge commit.
2. **Does any of it touch the implicated path?** Match the symptom to files.
   An error in checkout narrows to the checkout service's handlers, its
   client calls, and its config — not the whole repository.
3. **Is there a mechanism?** This is the step that separates a cause from a
   coincidence. You must be able to say *how* the change produces the observed
   symptom: this timeout shortened, this retry was removed, this query lost its
   index, this default flipped.

## Correlation is not causation, and saying so is not a failure

Most cycles should end without a proven cause, and that is the correct outcome,
not a shortfall. Report honestly at the level the evidence supports:

- **Identified cause** — you can name the line or commit and explain the
  mechanism. Only this level justifies a PR.
- **Strong lead** — a change landed in the window and plausibly touches the
  path, but you cannot explain the mechanism. Report it. No PR.
- **Correlation only** — something coincided in time with no evident
  connection. Report it as such. No PR.
- **No lead** — the telemetry did not point anywhere. Say so plainly.

A confident wrong answer is worse than no answer. The on-call engineer will
spend their first minutes checking whatever you assert; asserting the wrong
thing costs them more than silence would have.

## Deciding on a PR

Open one only at "identified cause", and only when the fix is small, obvious,
and local. Good candidates: a restored timeout, a corrected boundary condition,
a reverted default, a missing nil check on the exact path in the stack trace.

Do not open a PR for:

- A refactor, or a fix that redesigns anything.
- A change you cannot test here — unless the change is trivially safe and you
  say plainly that it is unverified.
- An infrastructure or capacity problem. Code is not the fix, and a PR
  misdirects the responder.
- A flapping alert where the threshold is the likely problem.

When you do open one, the PR body carries the investigation: the alert, the
onset, the evidence, the mechanism, what you verified, and what you did not.
A reviewer must be able to check your reasoning without redoing your work.

Never push to the base branch. Your branch prefix exists so your work is
obviously yours and easy to discard.

## Writing findings when there is no PR

The summary is the deliverable in most cycles. Make it something a person woken
at 3am can act on:

- What is firing, since when, and how bad.
- What you checked and what you found — including the things you ruled out.
  Knowing the dependency was flat is worth as much as knowing the service was.
- The most probable direction, with your confidence stated plainly.
- The exact queries you ran, so they can be re-run without reconstruction.

Ruling things out is real progress. Report it as such rather than treating a
cycle without a cause as a wasted one.
