"""NIST Cybersecurity Framework 2.0 mapping.

CSF 2.0 organizes cybersecurity outcomes into six functions: Govern,
Identify, Protect, Detect, Respond, Recover
(https://www.nist.gov/cyberframework). SOC Navigator uses this to show
that a detection isn't the end of the story -- it maps every incident to
where it sits in the broader risk-management lifecycle, which is the
frame a CISO actually manages against.

The checklist below is generated from the incident's own data (techniques
present, risk status, affected assets) rather than hardcoded per scenario,
so it stays accurate as new scenarios/rules are added.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.mapping.attack import describe

if TYPE_CHECKING:
    from app.models import Incident

FUNCTIONS = {
    "GOVERN": "Establish and monitor cybersecurity risk management strategy, expectations, and policy.",
    "IDENTIFY": "Understand the organization's assets, risks, and context.",
    "PROTECT": "Apply safeguards to manage risk and limit impact.",
    "DETECT": "Find and analyze possible security incidents.",
    "RESPOND": "Take action on a detected incident.",
    "RECOVER": "Restore assets and operations affected by an incident.",
}

_CREDENTIAL_TECHNIQUES = {"T1003.001", "T1110.004"}
_CONTAINMENT_TECHNIQUES = {"T1021.002", "T1003.001", "T1486", "T1567.002"}


def _build_live_checklist(incident: "Incident") -> dict[str, list[dict[str, str]]]:
    """Live (real network scan) findings have no ATT&CK techniques to map — they're
    exposure/hygiene facts about a real device, not an attack technique observed. This
    checklist speaks in those terms (remediation, not containment) instead of forcing
    the synthetic-incident wording onto them.
    """
    checklist: dict[str, list[dict[str, str]]] = {fn: [] for fn in FUNCTIONS}
    rule_titles = sorted({a.rule_title for a in incident.alerts})

    checklist["GOVERN"].append({"item": "Scan logged for this session", "status": "done"})
    checklist["GOVERN"].append(
        {"item": f"Escalation criteria applied per risk level ({incident.risk_level.upper()})", "status": "done"}
    )
    if incident.hosts:
        checklist["IDENTIFY"].append(
            {"item": f"Device inventoried: {', '.join(incident.hosts)}", "status": "done"}
        )
    checklist["PROTECT"].append(
        {"item": f"Exposure surface reviewed: {len(incident.alerts)} finding(s) on this device", "status": "done"}
    )
    for title in rule_titles:
        checklist["DETECT"].append({"item": f"Finding identified: {title}", "status": "done"})
    if len(incident.alerts) > 1:
        checklist["DETECT"].append(
            {"item": f"Findings correlated to one device across {len(incident.alerts)} results", "status": "done"}
        )
    if incident.status == "likely_benign":
        checklist["RESPOND"].append(
            {"item": "No response action required — reviewed, no remediation needed", "status": "done"}
        )
        checklist["RECOVER"].append({"item": "No recovery action required", "status": "not_applicable"})
    else:
        for title in rule_titles:
            checklist["RESPOND"].append({"item": f"Review and remediate: {title}", "status": "pending"})
        checklist["RECOVER"].append(
            {"item": "Re-scan after remediation to confirm the finding is resolved", "status": "pending"}
        )
    return checklist


def build_checklist(incident: "Incident") -> dict[str, list[dict[str, str]]]:
    if incident.source == "live":
        return _build_live_checklist(incident)

    technique_ids = set(incident.attack_techniques)
    checklist: dict[str, list[dict[str, str]]] = {fn: [] for fn in FUNCTIONS}

    checklist["GOVERN"].append(
        {"item": "Incident logged and mapped to a detection rule for audit trail", "status": "done"}
    )
    checklist["GOVERN"].append(
        {
            "item": f"Escalation criteria applied per incident risk level ({incident.risk_level.upper()})",
            "status": "done",
        }
    )

    if incident.hosts:
        checklist["IDENTIFY"].append(
            {"item": f"Affected assets inventoried: {', '.join(incident.hosts)}", "status": "done"}
        )
    if incident.users:
        checklist["IDENTIFY"].append(
            {"item": f"Affected identities inventoried: {', '.join(incident.users)}", "status": "done"}
        )

    checklist["PROTECT"].append(
        {
            "item": f"Detection coverage mapped to {len(technique_ids)} MITRE ATT&CK technique(s)",
            "status": "done",
        }
    )
    if incident.status == "likely_benign":
        checklist["PROTECT"].append(
            {
                "item": "Consider tuning this rule for this context to reduce future false positives",
                "status": "pending",
            }
        )

    rule_titles = sorted({a.rule_title for a in incident.alerts})
    for title in rule_titles:
        checklist["DETECT"].append({"item": f"Suspicious activity identified: {title}", "status": "done"})
    if len(incident.alerts) > 1:
        checklist["DETECT"].append(
            {
                "item": f"Behavioral correlation applied across {len(incident.alerts)} related alerts",
                "status": "done",
            }
        )

    if incident.status == "likely_benign":
        checklist["RESPOND"].append(
            {"item": "No response action required — reviewed and closed as benign", "status": "done"}
        )
    else:
        if incident.users:
            checklist["RESPOND"].append(
                {"item": f"Validate account ownership for {', '.join(incident.users)}", "status": "pending"}
            )
        if incident.hosts:
            checklist["RESPOND"].append(
                {"item": f"Investigate affected endpoint(s): {', '.join(incident.hosts)}", "status": "pending"}
            )
        source_ips = sorted(
            {a.event.fields.get("source_ip") for a in incident.alerts if a.event.fields.get("source_ip")}
        )
        if source_ips:
            checklist["RESPOND"].append(
                {"item": f"Review active sessions for {', '.join(source_ips)}", "status": "pending"}
            )
        if technique_ids & _CONTAINMENT_TECHNIQUES:
            checklist["RESPOND"].append(
                {
                    "item": f"Endpoint isolation recommended for {', '.join(incident.hosts) or 'affected host(s)'}",
                    "status": "pending",
                }
            )
        if "T1486" in technique_ids:
            checklist["RESPOND"].append(
                {
                    "item": "Immediate isolation required — potential impact to system availability",
                    "status": "pending",
                }
            )

    if incident.status == "likely_benign":
        checklist["RECOVER"].append({"item": "No recovery action required", "status": "not_applicable"})
    else:
        if technique_ids & _CREDENTIAL_TECHNIQUES:
            checklist["RECOVER"].append(
                {"item": "Password reset for affected account(s)", "status": "pending"}
            )
        if "T1486" in technique_ids:
            checklist["RECOVER"].append({"item": "Restore affected systems from backup", "status": "pending"})
            checklist["RECOVER"].append({"item": "Validate backup integrity before restore", "status": "pending"})
        checklist["RECOVER"].append(
            {"item": "Endpoint validation / reimage if compromise is confirmed", "status": "pending"}
        )

    return checklist


def technique_summary(technique_ids: list[str]) -> list[dict[str, str]]:
    return [{"id": tid, **describe(tid)} for tid in technique_ids]
