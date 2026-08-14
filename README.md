# SOC Navigator

**Turn security noise into investigations.**

SOC Navigator is an open-source, AI-assisted SOC investigation platform. It runs telemetry through
a Sigma-style detection engine, correlates the resulting alerts into prioritized incidents, maps
them to [MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/) and
[NIST CSF 2.0](https://www.nist.gov/cyberframework), and gives an AI assistant that explains,
prioritizes, and recommends next steps — without ever being the thing that decides if something
is malicious.

It exists to answer one question end to end: **how does a pile of raw events actually become an
incident an analyst can act on and a CISO can understand?**

**Overview, Incidents, and Alerts show your real network** — they're empty until you run a scan
from **My Network**, and never contain fabricated data. **Attack Lab** is a separate, self-contained
synthetic simulator (five fabricated attack scenarios) for learning and demoing the pipeline without
touching your network at all — its incidents are reached directly from its own "Investigate" button,
not mixed into the real views. A badge in the top bar and sidebar always says which one you're
looking at, so the two are never ambiguous.

> Raw findings → signals above threshold → correlated incidents → prioritized by risk — the same
> funnel whether it's your real network (My Network) or a synthetic scenario (Attack Lab).

## Try it locally

No paid services. No production telemetry. No required external security platform.

```bash
git clone https://github.com/AaronMontano99/soc-navigator.git
cd soc-navigator
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

<details>
<summary>Windows (PowerShell)</summary>

```powershell
git clone https://github.com/AaronMontano99/soc-navigator.git
cd soc-navigator
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```
</details>

Open **http://localhost:8000**. **Overview** starts empty — click **Scan My Network** (there or
under **My Network**) to see your own devices and any exposed-service findings. Separately, try
**Attack Lab** to run a synthetic scenario and investigate its resulting incident — toggle
Analyst / Security Leader view, walk the Timeline/Evidence/Detection/ATT&CK/NIST tabs, and ask the
AI assistant a question about it. Everything on screen — dashboard numbers, incident tables,
detection rule text, coverage stats — comes from the live FastAPI app, not fixtures.

### Testing it from other devices on your network

By default `uvicorn` only binds to `localhost`. To reach the dashboard from another device on the
same Wi-Fi/LAN (a phone, tablet, or second computer), bind to all interfaces instead:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then find this machine's LAN IP (`ipconfig getifaddr en0` on macOS, `ipconfig` on Windows, `hostname -I`
on Linux) and open `http://<that-ip>:8000` from the other device. Two things worth knowing before you
do this:

- **No authentication** — anyone on the same network who has the URL can use it, including running
  Attack Lab scenarios.
- **macOS Firewall** — the first time another device connects, macOS may prompt to allow incoming
  connections for Python. Click **Allow**; if a device still can't reach it afterward, that's almost
  always a firewall rule silently blocking it rather than the app itself.

This is meant for quick local testing across your own devices, not for exposing the app to the
internet.

## Why this exists

Most portfolio security projects are a port scanner or a password cracker — offensive toy tooling
that proves you can write code, not that you understand how a SOC operates. SOC Navigator is the
opposite bet: it's built around the actual workflow a detection & response product has to support —
telemetry → detection → correlation → prioritization → investigation → executive communication —
and it's built to be run, not just read.

## How it works

```mermaid
flowchart LR
    T[Synthetic Telemetry\nJSON events] --> D[Detection Engine\nSigma-subset rules]
    D -->|Alert + confidence factors| C[Correlation Engine\nunion-find by user/host/time]
    C -->|Incident| M1[MITRE ATT&CK mapping]
    C -->|Incident| M2[NIST CSF 2.0 mapping]
    C -->|Incident| A[AI Investigation Assistant\nexplain / prioritize / suggest]
    M1 --> UI[Analyst View + Security Leader View]
    M2 --> UI
    A --> UI
```

1. **Telemetry** — synthetic events (`app/data/telemetry/*.json`) simulate identity, endpoint,
   email, and cloud logs. No real customer or production data anywhere in this repo.
2. **Detection** — a small interpreter for a practical subset of the [Sigma](https://github.com/SigmaHQ/sigma)
   rule spec (`app/detection/sigma_engine.py`) matches rules in `detections/sigma/*.yml` against
   events and computes a confidence score from declarative increase/decrease factors.
3. **Correlation** — `app/correlation/correlator.py` clusters related alerts (same user or host,
   within a time window) into a single incident instead of showing an analyst N separate alerts
   for one attack.
4. **Mapping** — every incident is annotated with the MITRE ATT&CK techniques/tactics involved
   (`app/mapping/attack.py`) and a NIST CSF 2.0 Govern/Identify/Protect/Detect/Respond/Recover
   checklist generated from the incident's own data (`app/mapping/nist_csf.py`).
5. **AI Investigation Assistant** — `app/ai/assistant.py` explains *why* an incident is risky (or
   why it was downgraded to benign), suggests next investigation steps, and translates the
   incident into an executive summary. **The AI never decides whether something is malicious** —
   that verdict already exists before the AI runs anything. It's grounded in whichever incident is
   currently open (`Grounded in <incident-id>` in the drawer) and answers free-text questions, not
   just the suggested ones. See [`docs/ai-safety.md`](docs/ai-safety.md).
6. **Console UI** — a full multi-page frontend (vanilla JS/HTML/CSS, no build step, no framework).
   Live-network pages: **Overview** (your network's posture + signal funnel), **Incidents**
   (searchable/filterable table of your findings), **Alerts** (every raw finding before
   correlation), **My Network** (device inventory + scan control). Synthetic pages: **Attack Lab**
   (run a scenario and watch it become an incident), **Rules** (the actual Sigma YAML for the
   synthetic rule set, readable in-browser), **Coverage** (what that rule set detects vs.
   deliberately not). Reference pages: **Architecture** and **About**. Incident detail gives the
   same underlying data as two audiences regardless of which side it came from: a **SOC Analyst
   View** (timeline, evidence, matched detection + confidence factors, ATT&CK chain, NIST mapping)
   and a **Security Leader View** (plain-language business risk, no technical detail). A pill in
   the top bar and sidebar always says which mode you're looking at — **Synthetic Environment** or
   **Live Network — Real Data**.

## Attack Lab

Five synthetic scenarios exercise the full pipeline end to end — click **Run Scenario** and watch
raw telemetry become alerts become an incident, live:

| Scenario | Story | Demonstrates |
|---|---|---|
| **Account Compromise → Lateral Movement** | Unusual login → encoded PowerShell → credential access → SMB pivot to a finance workstation | Multi-stage correlation, kill-chain visibility |
| **Ransomware** | Phishing click → PowerShell → credential dumping → lateral movement → mass file encryption | Full kill chain, Impact-tier urgency |
| **Credential Stuffing** | 400+ failed logins → one success from a new location → immediate privileged action | Volume-based detection, account takeover |
| **Insider Threat** | Off-hours mass download outside normal scope → upload to a personal cloud account | Behavioral/baseline deviation, exfiltration |
| **Benign False Positive** | The *same* encoded-PowerShell signature as scenario 1 — but run by IT during an approved maintenance window with a known script | Context-aware scoring, alert-fatigue reduction |

That last scenario is the point: the same raw signature produces a **critical** incident in one
context and a **reviewed, likely-benign** one in another, because the confidence score is a
function of context, not just pattern-matching. That's the whole pitch behind "reducing
operational noise" — and you can watch it happen by running scenario 1 and scenario 5 back to back.

Attack Lab is intentionally self-contained: after a run, its own **Investigate** button opens the
resulting incident directly. Synthetic incidents are never listed in the Overview/Incidents/Alerts
pages — those are reserved for your real network — so there's no path where demo data and real
findings end up in the same table.

## Live Network Scanning

The **My Network** tab is a real network scanner, not a simulation — click **Scan My Network** and
it will:

1. Auto-detect your machine's local subnet and ping-sweep it (via the system `ping` binary, no raw
   sockets, no elevated permissions).
2. TCP-connect-scan each responding device against a small, curated list of commonly-relevant
   ports (remote access, databases, file shares — not a full 65535-port sweep).
3. Run the results through the exact same Sigma-subset engine and correlator the synthetic
   scenarios use (`app/live/pipeline.py` — no duplicated detection logic), producing real
   incidents: e.g. *"Insecure Telnet Service Exposed"* on a real device at a real IP, with real
   remediation steps.

**Safety boundary, enforced server-side, not just in the UI:** `app/live/scanner.py` will only ever
scan a private (RFC1918) or link-local subnet, capped at a /24 — this is validated on every call
regardless of what's requested, so it can never be pointed at a public IP range. It only checks
whether a TCP port accepts a connection; no authentication, exploitation, or credential access is
attempted anywhere.

**What this can and can't tell you:** it gives real device/port inventory — useful for "is there
something on my network I don't recognize" or "did I leave a database open to my whole Wi-Fi." It
cannot see process execution, command lines, or credential theft the way the synthetic Attack Lab
rules do — that requires OS-level endpoint instrumentation (Sysmon/EDR-grade), which is out of
scope here. Live findings are deliberately never mapped to a MITRE ATT&CK technique (an open port
isn't an observed attack technique) — the UI says so explicitly rather than forcing a fake mapping.

**No authentication on this app** — if you bind it to your LAN (see below), anyone with the URL can
trigger a scan of your network.

## Detection rules

10 rules in `detections/sigma/`, each documenting its logic, MITRE technique, false-positive
causes, and the specific contextual factors that raise or lower confidence. Browse them live in
the **Rules** tab (full YAML, in-browser) or the table below:

| Rule | Technique |
|---|---|
| Suspicious Encoded PowerShell Execution | T1059.001 |
| Credential Access via LSASS Memory | T1003.001 |
| SMB Admin Share Connection | T1021.002 |
| Authentication from a New Location | T1078 |
| Mass File Modification (Ransomware) | T1486 |
| Credential Stuffing / Brute Force | T1110.004 |
| Privileged Action After New Session | T1078.004 |
| Anomalous Mass File Download | T1530 |
| Upload to Unsanctioned Personal Cloud | T1567.002 |
| Malicious Phishing Link Clicked | T1566.002 |

See [`docs/detection-methodology.md`](docs/detection-methodology.md) for exactly what subset of
the Sigma spec this engine implements (and doesn't).

## API

All read from the same in-memory incident store; nothing here duplicates detection logic in JS.

| Endpoint | Purpose |
|---|---|
| `GET /api/dashboard` | Your network's posture from the last scan: devices, findings, signals, incidents, risk counts |
| `GET /api/incidents` | Incident list — **live only**, from your last scan |
| `GET /api/alerts` | Every finding, flattened, before correlation — **live only** |
| `POST /api/live/scan` / `GET /api/live/last` | Run (or re-fetch) a real scan of your local network |
| `GET /api/incidents/{id}` | Full incident detail (analyst + leader data) — works for either live or synthetic |
| `POST /api/incidents/{id}/ask` | AI Investigation Assistant, grounded in that incident |
| `GET /api/scenarios` / `POST /api/scenarios/{id}/run` | List / run an Attack Lab (synthetic) scenario — response includes its resulting incidents directly |
| `GET /api/detections` / `GET /api/detections/{id}` | Synthetic rule metadata / full rule detail + raw YAML (also resolves live rule IDs) |
| `GET /api/coverage` | Synthetic rule set's technique/tactic coverage, and what's deliberately not covered |

## Project structure

```
soc-navigator/
├── app/
│   ├── main.py                # FastAPI app + all API routes, serves the frontend
│   ├── models.py               # Event / Alert / Incident dataclasses
│   ├── pipeline.py             # telemetry -> detection -> correlation
│   ├── store.py                 # in-memory incident store
│   ├── detection/                # Sigma-subset rule engine + rule registry (for the API)
│   ├── correlation/               # alert clustering + risk scoring
│   ├── mapping/                     # MITRE ATT&CK + NIST CSF 2.0
│   ├── ai/                           # investigation assistant
│   ├── live/                          # real network scanner + its detection pipeline
│   └── data/                           # scenario registry + synthetic telemetry
├── detections/
│   ├── sigma/                            # the 10 synthetic-scenario detection rules (YAML)
│   └── live/                              # the 6 real network-exposure rules (YAML)
├── frontend/                                # console UI (vanilla JS, ES modules, no build step)
│   ├── index.html                            # three-column shell
│   ├── styles.css                             # design tokens + all component styles
│   ├── api.js / helpers.js                     # fetch wrappers, formatting/escaping helpers
│   ├── views.js                                 # Overview/Incidents/Alerts/Rules/Coverage/Lab/Architecture/About
│   ├── incident.js                               # incident detail: both views, all six analyst tabs
│   ├── live.js                                    # My Network page
│   └── app.js                                      # routing + the AI drawer
├── docs/                                      # architecture, methodology, AI safety, design, sales demo
└── tests/                                       # detection, correlation, live scanner, and API tests
```

## Docs

- [`docs/architecture.md`](docs/architecture.md) — component breakdown and data flow
- [`docs/detection-methodology.md`](docs/detection-methodology.md) — the Sigma subset + confidence scoring model
- [`docs/ai-safety.md`](docs/ai-safety.md) — why the AI explains but never adjudicates
- [`docs/design.md`](docs/design.md) — the console UI's design tokens and layout
- [`docs/threat-model.md`](docs/threat-model.md) — what this project is and isn't (synthetic data only)
- [`docs/sales-demo.md`](docs/sales-demo.md) — a discovery-call-style demo script for this project

## Roadmap

- Export detections to Splunk/Sentinel/Elastic query syntax (Sigma's actual multi-backend value)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)-based validation: run authorized
  atomic tests in a lab VM and confirm the rules in `detections/sigma/` actually fire, instead of
  only validating against synthetic JSON
- Additional scenarios (compromised M365 mailbox + inbox-rule persistence, supply-chain alert)
- Real SIEM/EDR ingestion adapter (currently synthetic JSON telemetry only)

## License

MIT — see [LICENSE](LICENSE). Attack Lab telemetry is entirely synthetic; no real organizational
or customer data is used anywhere in this repository. My Network is the one real capability — it
only ever scans your own local network (see [Live Network Scanning](#live-network-scanning) for
the exact safety boundary), and only device/port inventory it discovers there is ever processed.
