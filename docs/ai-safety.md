# AI Safety / Design Boundary

## The rule

**The AI does not decide whether something is malicious.** The detection engine (Sigma-subset
rules) and the correlation engine (`app/correlation`) have already produced a verdict — a
confidence score, a risk level, and a status (`likely_benign` / `needs_investigation` /
`confirmed_suspicious`) — before the AI Investigation Assistant is ever invoked. The assistant's
job is strictly downstream of that verdict: explain it, summarize it, prioritize it, and suggest
investigation steps grounded in it.

## Why this matters for a SOC product specifically

"AI magically detects hackers" is not a credible pitch to a SOC analyst or a CISO, and it's not
how AI should be positioned in a detection & response product. A model that can independently
assert "this is a compromise" with no deterministic, auditable rule behind it is a liability in an
environment where an incident's classification drives account lockouts, executive notification,
and potentially legal/regulatory obligations. Analysts need to be able to point to *why* an alert
fired — a rule ID, a technique, a confidence factor — not just trust a model's intuition.

This holds identically for the **My Network** live scanner: a port being open is a deterministic
fact from `app/live/scanner.py`, and the rules in `detections/live/*.yml` decide the severity — the
AI assistant explains a real exposure finding the same way it explains a synthetic one, and never
claims a network-exposure finding is an observed MITRE ATT&CK technique (see
`docs/threat-model.md`).

SOC Navigator's split enforces that:

- **Deterministic layer** (`app/detection`, `app/correlation`) — auditable, rule-based, produces
  the actual verdict. Every confidence point is traceable to a named factor and the event field
  that triggered it (see the "Why did we alert?" panel).
- **AI layer** (`app/ai/assistant.py`) — receives the already-computed incident as its only input.
  It cannot change risk level, confidence, or status. It can only narrate.

## How this is enforced in code

- Template mode (default): every response is built from string templates filled in with the
  incident's own fields (`why_critical`, `next_steps`, `ciso_summary` in `app/ai/assistant.py`).
  There is no model in the loop at all unless `ANTHROPIC_API_KEY` is set — the app is fully
  functional and deterministic without one.
- Optional LLM mode: if enabled, the system prompt sent to the model explicitly states the
  boundary ("you do not re-adjudicate whether it is malicious... strictly grounded in the incident
  JSON provided") and the only data given to the model is the already-classified incident. The
  model is never given raw telemetry to classify from scratch, and its output is never written
  back into risk_level, confidence, or status.
- If the LLM call fails or isn't configured, the assistant falls back to template mode
  automatically — there's no failure state where the assistant has nothing to say.

## What this doesn't cover

This is a portfolio-scale demonstration of the boundary, not a hardened production system. A real
deployment would add: prompt-injection resistance for any user-supplied incident notes, rate
limiting, output logging/audit trail for every AI response, and a human-in-the-loop confirmation
step before any AI-suggested action (e.g. containment) is actually executed. None of that is
implemented here — SOC Navigator doesn't take any containment actions itself, it only recommends
them.
