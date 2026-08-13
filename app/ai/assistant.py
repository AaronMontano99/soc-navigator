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


_TECHNIQUE_CLAUSE = {
    "T1078": "a user authenticated from a location not previously seen for that identity",
    "T1078.004": "a privileged action was taken shortly after a new login",
    "T1059.001": "PowerShell was executed using an obfuscated, encoded command",
    "T1003.001": "credential-access behavior targeting LSASS memory was observed",
    "T1021.002": "the endpoint connected to another system over an SMB admin share",
    "T1486": "a large number of files began being modified, consistent with encryption",
    "T1110.004": "a burst of failed logins targeted one or more accounts",
    "T1530": "an unusually large volume of files was downloaded",
    "T1567.002": "data was uploaded to a destination outside organizational control",
    "T1566.002": "a malicious phishing link was clicked",
}


def _primary_user(incident: "Incident") -> str:
    return incident.users[0] if incident.users else "the affected account"


def _primary_host(incident: "Incident") -> str:
    return incident.hosts[0] if incident.hosts else "the affected system"


def _last_host(incident: "Incident") -> str:
    if incident.alerts:
        last = incident.alerts[-1].event
        dest = last.fields.get("dest_host")
        if dest:
            return dest
        if last.host:
            return last.host
    return _primary_host(incident)


def _top_factor_label(alert) -> str | None:
    """The single most salient confidence factor for an alert, for short per-step annotations."""
    factors = alert.increasing_factors or alert.decreasing_factors
    if not factors:
        return None
    top = max(factors, key=lambda f: abs(f.weight))
    return top.label


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


def what_happened(incident: "Incident") -> str:
    if incident.status == "likely_benign":
        alert = incident.alerts[0]
        factor = _top_factor_label(alert)
        base = f"{alert.rule_title} matched on {alert.event.host or 'a monitored host'}."
        return f"{base} {factor + '.' if factor else ''}".strip()

    clauses: list[str] = []
    seen: set[str] = set()
    for alert in incident.alerts:
        for tid in alert.attack_techniques:
            if tid in seen or tid not in _TECHNIQUE_CLAUSE:
                continue
            seen.add(tid)
            clauses.append(_TECHNIQUE_CLAUSE[tid])
    if not clauses:
        return f"{incident.alerts[0].rule_title} was observed on {_primary_host(incident)}."
    if len(clauses) == 1:
        return clauses[0].capitalize() + "."
    lead, *rest = clauses
    return lead.capitalize() + ". Then " + ". Then ".join(rest) + "."


def why_it_matters(incident: "Incident") -> str:
    if incident.status == "likely_benign":
        return "No business impact identified — this activity matches an approved, expected pattern."
    tactics = set(incident.tactics)
    last = _last_host(incident)
    if "Impact" in tactics:
        return (
            f"If this pattern continues, data on {last} and any systems it can reach may be encrypted "
            "or destroyed. This is consistent with ransomware and time-sensitive to contain."
        )
    if "Exfiltration" in tactics or "Collection" in tactics:
        return (
            "If genuine, company data has left — or is about to leave — organizational control. "
            "Scope of exposure should be confirmed as a priority."
        )
    if "Lateral Movement" in tactics or "Credential Access" in tactics:
        return (
            f"If the account is genuinely compromised, the attacker has already moved beyond the first "
            f"machine and reached {last}. Containing the account and the endpoint now limits how far this can spread."
        )
    return "Impact is still being scoped from the available evidence."


def business_snapshot(incident: "Incident") -> dict:
    """Structured facts for the Security Leader / CISO view — same incident, no separate data."""
    if incident.status == "likely_benign":
        headline = "Reviewed — No Action Required"
        priority = "None — closed as benign"
        current_state = [
            {"label": "Evidence collected", "done": True},
            {"label": "Reviewed and closed as benign", "done": True},
        ]
    else:
        headline = incident.title.split("→")[0].strip().rstrip("-").strip() or incident.title
        for prefix in ("Possible ", "Potential "):
            if headline.startswith(prefix):
                headline = headline[len(prefix) :]
        headline = "Potential " + headline
        priority = {
            "critical": "Immediate Investigation",
            "high": "Immediate Investigation",
            "medium": "Investigate Soon",
            "low": "Monitor",
        }.get(incident.risk_level, "Investigate")
        current_state = [
            {"label": "Evidence collected", "done": True},
            {"label": "Incident correlated", "done": True},
            {
                "label": "Containment recommended"
                if incident.risk_level in ("critical", "high")
                else "Containment not currently required",
                "done": incident.risk_level in ("critical", "high"),
            },
        ]

    return {
        "headline": headline,
        "business_risk": incident.risk_level,
        "recommended_priority": priority,
        "current_status": incident.status.replace("_", " "),
        "systems_affected": len(incident.hosts),
        "identities_involved": len(incident.users),
        "environment_reached": _last_host(incident) if incident.hosts else "n/a",
        "what_happened": what_happened(incident),
        "why_it_matters": why_it_matters(incident),
        "current_state": current_state,
    }


def ciso_summary(incident: "Incident") -> str:
    """Flat paragraph form, used by the AI chat answer (which returns plain text)."""
    brief = business_snapshot(incident)
    if incident.status == "likely_benign":
        return (
            f"{brief['what_happened']} No business impact identified — this activity was reviewed and "
            "matches an approved, expected pattern. No further action is required."
        )
    return (
        f"{brief['what_happened']} {brief['why_it_matters']} "
        f"Recommended priority: {brief['recommended_priority']}. "
        f"Current status: {brief['current_status']}."
    )


def attack_progression(incident: "Incident") -> list[dict]:
    """Per-alert step used by both the Summary mini-timeline and the Timeline sub-tab."""
    steps = []
    for alert in incident.alerts:
        technique = alert.attack_techniques[0] if alert.attack_techniques else None
        info = describe(technique) if technique else {"name": alert.rule_title, "tactic": "—"}
        steps.append(
            {
                "timestamp": alert.event.timestamp,
                "tactic": info["tactic"],
                "technique_id": technique,
                "technique_name": info["name"],
                "title": alert.rule_title,
                "host": alert.event.host,
                "user": alert.event.user,
                "event_type": alert.event.event_type,
                "annotation": _top_factor_label(alert),
                "fields": alert.event.fields,
            }
        )
    return steps


def attack_chain_note(incident: "Incident") -> str:
    if incident.status == "likely_benign":
        return "Signature matched, but contextual factors reduced confidence below the investigation threshold."
    last = _last_host(incident)
    if "Impact" in set(incident.tactics):
        return f"Chain reaches the Impact tier at {last}. Treat as time-sensitive."
    return f"Chain terminates at {last}. No Impact-tier technique observed."


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


def _evidence_for(incident: "Incident", question: str) -> str:
    q = question.lower()
    matches = [
        a
        for a in incident.alerts
        if any(
            kw in q
            for kw in (
                describe(t)["tactic"].lower() for t in a.attack_techniques
            )
        )
        or any(kw in q for kw in (a.rule_title.lower().split()))
    ]
    if not matches:
        matches = incident.alerts
    lines = []
    for a in matches[:4]:
        field_bits = ", ".join(f"{k}={v}" for k, v in list(a.event.fields.items())[:4])
        lines.append(f"- {a.rule_title} on {a.event.host or 'n/a'} at {a.event.timestamp} ({field_bits})")
    return "Supporting evidence:\n" + "\n".join(lines)


def _confidence_delta(incident: "Incident") -> str:
    lines = []
    for a in incident.alerts:
        for f in a.increasing_factors:
            lines.append(f"+{f.weight} {f.label} ({a.rule_title})")
        for f in a.decreasing_factors:
            lines.append(f"{f.weight} {f.label} ({a.rule_title})")
    if not lines:
        return "No confidence-adjusting factors were declared for this incident's rules."
    return "Confidence factors across this incident:\n" + "\n".join(lines)


def _template_answer(incident: "Incident", question: str) -> str:
    q = question.lower()
    if "happened first" in q or ("what happened" in q and "why" not in q):
        return what_happened(incident)
    if "evidence" in q:
        return _evidence_for(incident, question)
    if "confidence" in q:
        return _confidence_delta(incident)
    if "why" in q and any(k in q for k in ("critical", "risk", "severe", "alert", "high")):
        return why_critical(incident)
    if "benign" in q or "false positive" in q or "false-positive" in q:
        return why_critical(incident)
    if any(k in q for k in ("next", "investigate", "should i", "steps")):
        steps = next_steps(incident)
        return "\n".join(f"{i + 1}. {s}" for i, s in enumerate(steps)) if steps else "No further investigation steps generated for this incident."
    if any(k in q for k in ("impact", "business", "ciso", "exec", "executive", "leader")):
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
