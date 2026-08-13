# Architecture

## Data flow

```
Telemetry (JSON)  →  Detection (Sigma-subset)  →  Correlation  →  Mapping (ATT&CK / NIST)  →  AI  →  API  →  Dashboard
```

Every stage is a pure function over the previous stage's output. Nothing is scenario-specific
below the telemetry layer — a new scenario is just a new JSON file; a new detection is just a new
YAML rule. The engine doesn't know or care which of the five Attack Story Mode scenarios it's
processing.

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
user or a host and occur within a 3-hour window. This is what turns "5 separate alerts" into "1
incident with a 5-step timeline." Risk level is derived from three inputs — the confidence score,
the raw rule severities involved, and how many distinct ATT&CK tactics are represented (a single
alert is one thing; a chain spanning Initial Access → Credential Access → Lateral Movement is
categorically more serious, because it shows a completed kill chain rather than an isolated
event).

### `app/mapping/attack.py`, `app/mapping/nist_csf.py`
Static local lookups (not live API calls, so the app runs fully offline) that annotate incidents
with MITRE ATT&CK technique/tactic names and a NIST CSF 2.0 Govern/Identify/Protect/Detect/
Respond/Recover checklist. The checklist is generated from the incident's actual data (techniques
present, affected users/hosts, status) rather than hardcoded per scenario.

### `app/ai/assistant.py`
Produces the analyst "why is this critical" explanation, the ordered investigation steps, and the
CISO-facing executive summary — all templated from the incident's own fields by default (so the
app requires no API key to be fully functional), with an optional live-LLM path for free-form
chat if `ANTHROPIC_API_KEY` is set. See [`ai-safety.md`](ai-safety.md) for the boundary this module
enforces.

### `app/main.py` + `app/store.py`
FastAPI app exposing the pipeline over a small JSON API, plus an in-memory store that keeps
incident IDs stable across requests within a process (telemetry is static/synthetic, so there's no
need for a database — re-running a scenario via the API just replaces that scenario's incidents).

### `frontend/`
A single-page dashboard in vanilla JS/HTML/CSS with no build step — `index.html` + `app.js` +
`styles.css`, served directly by FastAPI's `StaticFiles`. Deliberately framework-free so the whole
frontend is readable in one sitting.
