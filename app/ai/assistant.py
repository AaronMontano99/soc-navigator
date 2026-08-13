"""AI Investigation Assistant.

Architectural rule this file exists to enforce: the AI does not decide
whether something is malicious. The detection engine (Sigma rules) and
correlation engine (app/correlation) already produced a verdict —
confidence score, risk level, status — before this module ever runs. The
assistant's only job is to explain, summarize, prioritize, and suggest
investigation steps grounded in that already-computed incident data. See
docs/ai-safety.md for why this boundary matters for a SOC product.

Two modes:
  - Template mode (default, no API key required): every answer is built
    deterministically from the incident's own fields, so the app is fully
    functional and free to run out of the box.
  - LLM mode (optional): if ANTHROPIC_API_KEY is set and the `anthropic`
    package is installed, free-form chat questions are answered by
    Claude, but constrained by a system prompt that repeats the same
    "explain, don't adjudicate" boundary and is grounded in the incident
    JSON. Template mode is always the fallback if the API call fails.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

from app.mapping.attack import describe

if TYPE_CHECKING:
    from app.models import Incident

_TACTIC_PLAIN = {
    "Initial Access": "an initial point of entry into the environment",
    "Execution": "execution of code on an internal system",
    "Credential Access": "attempted or actual theft of account credentials",
    "Lateral Movement": "movement from one internal system to another",
    "Impact": "disruption, encryption, or destruction of business data",
    "Collection": "unusual access to internal data",
    "Exfiltration": "data leaving the organization's control",
    "Privilege Escalation": "use of elevated account privileges",
}

_TECHNIQUE_STEPS = {
    "T1059.001": "Review PowerShell process ancestry and the full decoded command line on {host} to determine what actually executed.",
    "T1003.001": "Confirm whether credential material was read from memory on {host}; if so, treat {user}'s credentials as exposed and rotate them.",
    "T1021.002": "Review SMB/admin-share connections from {host} to check for additional lateral movement beyond what's already visible.",
    "T1078": "Verify whether the authentication for {user} originated from a known device and location, and confirm MFA was enforced.",
    "T1078.004": "Confirm whether the privileged action taken by {user} is consistent with their normal role and responsibilities.",
    "T1486": "Isolate {host} immediately — this matches ransomware encryption behavior and delay increases blast radius.",
    "T1110.004": "Check whether other accounts from the same source were targeted, and confirm no other successful logins resulted from the same burst.",
    "T1530": "Review exactly which files {user} accessed during the download to scope what data may be exposed.",
    "T1567.002": "Determine whether the upload destination for {user} is fully outside organizational control, and whether it can be revoked.",
    "T1566.002": "Retrieve the original phishing email sent to {user}, identify other recipients, and check whether anyone else clicked the link.",
}


def _primary_user(incident: "Incident") -> str:
    return incident.users[0] if incident.users else "the affected account"


def _primary_host(incident: "Incident") -> str:
    return incident.hosts[0] if incident.hosts else "the affected system"


def next_steps(incident: "Incident") -> list[str]:
    steps: list[str] = []
    seen_techniques: set[str] = set()
    for alert in incident.alerts:
        for tid in alert.attack_techniques:
            if tid in seen_techniques or tid not in _TECHNIQUE_STEPS:
                continue
            seen_techniques.add(tid)
            steps.append(
                _TECHNIQUE_STEPS[tid].format(
                    host=alert.event.host or _primary_host(incident),
                    user=alert.event.user or _primary_user(incident),
                )
            )
    if incident.status != "likely_benign":
        steps.append("Document findings and update the incident status once the investigation is complete.")
    return steps


def why_critical(incident: "Incident") -> str:
    if incident.status == "likely_benign":
        factors = []
        for alert in incident.alerts:
            factors.extend(f.label for f in alert.decreasing_factors)
        factor_text = "; ".join(dict.fromkeys(factors)) or "contextual factors on the source event"
        return (
            f"This alert matched a detection signature, but was downgraded on review. "
            f"{factor_text}. Resulting confidence this reflects malicious activity: "
            f"{incident.confidence}% (roughly {100 - incident.confidence}% likely benign)."
        )

    tactic_count = len(incident.tactics)
    alert_count = len(incident.alerts)
    entities = ", ".join(incident.users + incident.hosts) or "the affected environment"
    tactic_list = ", ".join(incident.tactics)
    return (
        f"This incident combines {tactic_count} distinct MITRE ATT&CK tactic(s) — {tactic_list} — "
        f"across {alert_count} correlated alert(s) involving {entities}. Individually, some of these "
        f"alerts might only warrant moderate attention on their own, but their sequence and shared "
        f"identity/host context raise confidence this is a single connected attack rather than "
        f"{alert_count} unrelated events. Peak confidence across constituent alerts: {incident.confidence}%."
    )


def ciso_summary(incident: "Incident") -> str:
    if incident.status == "likely_benign":
        return (
            "No business impact identified. This activity was reviewed and matches an approved, "
            "expected pattern (e.g. authorized IT maintenance). No further action is required, though "
            "the underlying detection rule may be worth tuning for this context to reduce future noise."
        )

    plain = [_TACTIC_PLAIN.get(t, t.lower()) for t in incident.tactics]
    who = ", ".join(incident.users) or "an account"
    activity_desc = "; ".join(plain)
    lead = f"{who} was involved in activity showing {activity_desc}."

    if "Impact" in incident.tactics:
        impact = (
            f"Potential impact: business data on {', '.join(incident.hosts) or 'affected systems'} "
            "may be encrypted or destroyed. This pattern is consistent with ransomware."
        )
        priority = "Immediate — recommend isolating affected systems now."
    elif "Exfiltration" in incident.tactics or "Collection" in incident.tactics:
        impact = "Potential impact: company data may have left organizational control."
        priority = "Immediate investigation recommended."
    elif "Lateral Movement" in incident.tactics or "Credential Access" in incident.tactics:
        impact = (
            f"Potential impact: unauthorized access to internal systems, including "
            f"{', '.join(incident.hosts) or 'internal infrastructure'}."
        )
        priority = "Immediate investigation recommended."
    else:
        impact = "Potential impact is still being scoped."
        priority = "Investigate to confirm scope and intent."

    status_line = {
        "needs_investigation": "Under investigation.",
        "confirmed_suspicious": "Containment recommended.",
    }.get(incident.status, "Under investigation.")

    return f"{lead} {impact} Recommended priority: {priority} Current status: {status_line}"


def why_did_we_alert(incident: "Incident") -> list[dict]:
    """Evidence-chain view for the 'Why did we alert?' analyst page — one entry per alert."""
    out = []
    for alert in incident.alerts:
        out.append(
            {
                "rule_title": alert.rule_title,
                "description": alert.description,
                "confidence": alert.confidence,
                "attack_techniques": [{"id": t, **describe(t)} for t in alert.attack_techniques],
                "increasing_factors": [{"label": f.label, "weight": f.weight} for f in alert.increasing_factors],
                "decreasing_factors": [{"label": f.label, "weight": f.weight} for f in alert.decreasing_factors],
                "falsepositives": alert.falsepositives,
                "event": {
                    "timestamp": alert.event.timestamp,
                    "host": alert.event.host,
                    "user": alert.event.user,
                    "event_type": alert.event.event_type,
                    "fields": alert.event.fields,
                },
            }
        )
    return out


def _template_answer(incident: "Incident", question: str) -> str:
    q = question.lower()
    if "why" in q and any(k in q for k in ("critical", "risk", "severe", "alert", "high")):
        return why_critical(incident)
    if "benign" in q or "false positive" in q or "false-positive" in q:
        return why_critical(incident)
    if any(k in q for k in ("next", "investigate", "should i", "steps")):
        steps = next_steps(incident)
        return "\n".join(f"{i + 1}. {s}" for i, s in enumerate(steps)) if steps else "No further investigation steps generated for this incident."
    if any(k in q for k in ("impact", "business", "ciso", "exec", "executive")):
        return ciso_summary(incident)
    return (
        f"{incident.title} — risk {incident.risk_level.upper()}, status {incident.status.replace('_', ' ')}, "
        f"confidence {incident.confidence}%. Ask me things like 'why is this critical', "
        "'what should I investigate next', or 'what's the business impact'."
    )


_SYSTEM_PROMPT = """You are the SOC Navigator investigation assistant. A detection and \
correlation engine has ALREADY determined this incident's risk level, status, and confidence \
score -- you do not re-adjudicate whether it is malicious. Your only job is to explain, \
summarize, prioritize, and suggest concrete investigation steps, strictly grounded in the \
incident JSON provided below. Be concise and analyst-appropriate. If asked something the data \
doesn't support, say so rather than inventing detail.

INCIDENT DATA:
{incident_json}
"""


def _incident_to_dict(incident: "Incident") -> dict:
    return {
        "title": incident.title,
        "risk_level": incident.risk_level,
        "status": incident.status,
        "confidence": incident.confidence,
        "users": incident.users,
        "hosts": incident.hosts,
        "tactics": incident.tactics,
        "attack_techniques": incident.attack_techniques,
        "alerts": [
            {
                "rule_title": a.rule_title,
                "severity": a.severity,
                "confidence": a.confidence,
                "timestamp": a.event.timestamp,
            }
            for a in incident.alerts
        ],
    }


def _llm_answer(incident: "Incident", question: str) -> str | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None
    try:
        client = anthropic.Anthropic(api_key=api_key)
        system = _SYSTEM_PROMPT.format(incident_json=json.dumps(_incident_to_dict(incident), indent=2))
        resp = client.messages.create(
            model="claude-sonnet-5",
            max_tokens=500,
            system=system,
            messages=[{"role": "user", "content": question}],
        )
        return resp.content[0].text
    except Exception:
        return None


def answer(incident: "Incident", question: str) -> str:
    llm_response = _llm_answer(incident, question)
    if llm_response:
        return llm_response
    return _template_answer(incident, question)
