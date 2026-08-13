# Detection Methodology

## The Sigma subset this engine implements

[Sigma](https://github.com/SigmaHQ/sigma) is the open, YAML-based standard for describing
detections in a SIEM-agnostic way, so a single rule can in principle be translated to Splunk,
Elastic, Microsoft Sentinel, and others. SOC Navigator implements a **practical subset** of the
spec directly (`app/detection/sigma_engine.py`) rather than depending on a full backend like
pySigma, so the detection logic stays visible and auditable in ~200 lines instead of hidden behind
a library.

**Supported:**
- `logsource` (category/product — used as documentation/metadata, not currently used for routing)
- Named `detection` selections of `field: value` (equality, or OR-over-a-list)
- String modifiers: `field|contains`, `field|startswith`, `field|endswith` (also OR-over-a-list)
- Numeric modifiers: `field|gt`, `field|gte`, `field|lt`, `field|lte` (for volume-based rules like
  "400+ failed logins" or "200+ files modified")
- Boolean `condition` strings combining named selections with `and`, `or`, `and not`
- `level`, `tags` (`attack.<tactic>`, `attack.t<technique>`), `falsepositives`, `description`

**Not implemented** (out of scope for a single-log-source, portfolio-scale engine): Sigma's full
aggregation functions (`count()`, `near`), the `1 of them` / `all of them` selection-group syntax,
correlation rules (Sigma's newer multi-event correlation spec — SOC Navigator's own
`app/correlation` module fills this role instead, deliberately kept separate from the rule format),
and field-mapping/pipeline transforms for specific SIEM backends.

If this engine graduates beyond a portfolio project, the natural next step is swapping it for
[pySigma](https://github.com/SigmaHQ/pySigma) with a real backend, since these YAML rules are
already close to spec-compliant.

## Confidence scoring — a deliberate extension beyond Sigma

Upstream Sigma gives you a rule match: yes or no, plus a static `level`. Real analysts don't treat
a match as a verdict — they weigh context. Did this come from an IT admin during a maintenance
window, or from finance at 2am from an unfamiliar IP?

Each rule's `confidence` block encodes that reasoning declaratively:

```yaml
confidence:
  base: 60
  increase:
    - factor: "External network connection observed from this process"
      field_check: {field: network_connection, equals: true}
      weight: 15
  decrease:
    - factor: "User belongs to the IT/Administrators department"
      field_check: {field: user_department, equals: IT}
      weight: -20
```

Every increase/decrease factor is evaluated against the actual event and surfaced verbatim on the
"Why did we alert?" panel in the Analyst View — so nothing about a confidence score is a black
box. This is what lets the same `suspicious_powershell_encoded` rule produce a 97%-confidence
critical alert in the account-compromise scenario and a 3%-confidence "likely benign" review in
the false-positive scenario, from the same detection logic.

## Correlation and risk level

Confidence is per-alert. Risk level is per-incident, computed in `app/correlation/correlator.py`
from three inputs: the highest confidence among the incident's alerts, the highest raw rule
severity involved, and how many distinct ATT&CK tactics are represented — two or more tactics
bumps the risk level up, since a chain of behaviors across the kill chain is a materially bigger
signal than any single alert in isolation.
