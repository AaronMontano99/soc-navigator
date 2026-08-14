# Architecture

## Data flow

```
Telemetry (JSON)  →  Detection (Sigma-subset)  →  Correlation  →  Mapping (ATT&CK / NIST)  →  AI  →  API  →  Dashboard
```

Every stage is a pure function over the previous stage's output. Nothing is scenario-specific
below the telemetry layer — a new scenario is just a new JSON file; a new detection is just a new
YAML rule. The engine doesn't know or care which of the five Attack Lab scenarios it's processing.

**My Network (live) reuses this entire pipeline from the Detection stage onward.**
`app/live/scanner.py` is the only new telemetry source — a real ping sweep + TCP port scan of the
local subnet — and `app/live/pipeline.py` turns its output into the same `Event` shape everything
else expects, then calls the *unmodified* `sigma_engine.run_rules()` and `correlator.correlate()`
against `detections/live/*.yml`. No detection or correlation logic is duplicated for live mode;
only the telemetry source and the rule set differ. See `docs/threat-model.md` for the safety
boundary on the scanner itself.

## Components

### `app/models.py`
Three dataclasses everything else operates on: `Event` (raw telemetry with a flexible `fields`
bag, since real log sources never agree on schema), `Alert` (an `Event` that matched a rule, with
a confidence score and the factors behind it), and `Incident` (one or more correlated `Alert`s).

### `app/detection/sigma_engine.py`
Loads YAML rules and matches them against events. Implements selection matching (`equals`,
`contains`, `startswith`, `endswith`, numeric `gt`/`gte`/`lt`/`lte`, all OR-over-list), boolean
conditions (`and`, `or`, `and not`), and the confidence-scoring extension described in
[`detection-methodology.md`](detection-methodology.md).

### `app/correlation/correlator.py`
Clusters alerts into incidents using union-find: two alerts join the same cluster if they share a
user or a host — including a network alert's destination host, not just its source — and occur
within a 3-hour window. This is what turns "5 separate alerts" into "1 incident with a 5-step
timeline."

Confidence and risk level are deliberately separate axes. **Confidence** (peak confidence across
the incident's alerts) drives `status` — `likely_benign` / `needs_investigation` /
`confirmed_suspicious` — i.e. *how sure are we*. **Risk level** is driven by the rule severities
involved plus kill-chain depth (a 4+ tactic chain escalates a tier, since it shows a completed
chain rather than an isolated event) — i.e. *how bad if true*. An incident that hasn't cleared the
confirmed-suspicious confidence bar is capped at `high` even if the techniques involved would
otherwise read as critical, since escalating unconfirmed activity to critical would itself be the
kind of noise this tool exists to cut down.

### `app/mapping/attack.py`, `app/mapping/nist_csf.py`
Static local lookups (not live API calls, so the app runs fully offline) that annotate incidents
with MITRE ATT&CK technique/tactic names and a NIST CSF 2.0 Govern/Identify/Protect/Detect/
Respond/Recover checklist. The checklist is generated from the incident's actual data (techniques
present, affected users/hosts, status) rather than hardcoded per scenario.

### `app/ai/assistant.py`
Produces the analyst "why is this critical" explanation, the ordered investigation steps, the
forensic-timeline annotations, and the Security Leader–facing business brief (headline, business
risk, what happened, why it matters, current state) — all templated from the incident's own fields
by default (so the app requires no API key to be fully functional), with an optional live-LLM path
for free-form chat if `ANTHROPIC_API_KEY` is set. See [`ai-safety.md`](ai-safety.md) for the
boundary this module enforces.

### `app/detection/registry.py`
Read-only views over the same parsed Sigma rules the detection engine runs — rule summaries for
the Rules tab, full detail (including the raw YAML read straight off disk) for the Detection
sub-tab, and a coverage summary (rules/techniques/tactics covered vs. the full MITRE Enterprise
tactic list) for the Coverage tab. No second copy of rule content.

### `app/main.py` + `app/store.py`
FastAPI app exposing the pipeline over a small JSON API, plus an in-memory store that keeps
incident IDs stable across requests within a process (telemetry is static/synthetic, so there's no
need for a database — re-running a scenario via the API just replaces that scenario's incidents).

### `frontend/`
A full multi-page console in vanilla JS/HTML/CSS with no build step or framework — ES modules
loaded directly by the browser, served by FastAPI's `StaticFiles`. `api.js` wraps every backend
call; `helpers.js` holds formatting/escaping utilities; `views.js` renders Overview, Incidents,
Alerts, Rules, Coverage, Attack Lab, Architecture, and About; `incident.js` renders incident detail
(both presentations, all six analyst sub-tabs); `app.js` owns client-side routing and the AI
drawer. Deliberately framework-free so the whole frontend is readable in one sitting.
