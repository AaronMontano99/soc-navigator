"""Read-only views over the Sigma rule set for the Rules/Coverage/Detection API surfaces.

Everything here reads from the same parsed rule dicts the detection engine
uses (app.pipeline.get_rules()) — there is no second copy of rule content
and no duplicate detection logic. The raw YAML text is read straight from
the file on disk so what's shown in the UI is always exactly the rule
that ran, not a JS re-serialization of it.
"""

from __future__ import annotations

from typing import Any

from app.mapping.attack import describe

# The full MITRE ATT&CK Enterprise tactic list, in kill-chain order, used
# only to show what this project deliberately does NOT claim to detect
# (see docs/threat-model.md — coverage is honest, not comprehensive).
ALL_ENTERPRISE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def _technique_ids(rule: dict[str, Any]) -> list[str]:
    return [tag.split(".", 1)[1].upper() for tag in rule.get("tags", []) if tag.startswith("attack.t")]


def rule_summary(rule: dict[str, Any]) -> dict[str, Any]:
    technique_ids = _technique_ids(rule)
    techniques = [{"id": t, **describe(t)} for t in technique_ids]
    return {
        "id": rule.get("id"),
        "title": rule.get("title"),
        "description": rule.get("description", "").strip(),
        "severity": rule.get("level", "medium"),
        "status": "active",
        "techniques": techniques,
        "tactics": sorted({t["tactic"] for t in techniques}),
        "falsepositives": rule.get("falsepositives", []),
        "filename": rule.get("id", "") + ".yml",
    }


def rule_detail(rule: dict[str, Any]) -> dict[str, Any]:
    summary = rule_summary(rule)
    path = rule.get("_path")
    raw_yaml = ""
    if path:
        try:
            with open(path, "r") as f:
                raw_yaml = f.read()
        except OSError:
            raw_yaml = ""
    summary["raw_yaml"] = raw_yaml
    summary["confidence"] = rule.get("confidence", {})
    detection = rule.get("detection", {})
    summary["condition"] = detection.get("condition", "")
    summary["selections"] = [
        {"name": name, "criteria": criteria}
        for name, criteria in detection.items()
        if name != "condition"
    ]
    return summary


def coverage_summary(rules: list[dict[str, Any]], scenario_count: int) -> dict[str, Any]:
    covered: dict[str, list[dict[str, str]]] = {}
    all_technique_ids: set[str] = set()
    for rule in rules:
        for tid in _technique_ids(rule):
            all_technique_ids.add(tid)
            info = describe(tid)
            covered.setdefault(info["tactic"], [])
            if not any(t["id"] == tid for t in covered[info["tactic"]]):
                covered[info["tactic"]].append({"id": tid, "name": info["name"]})

    # Order tactics by kill-chain position for a coherent read.
    ordered_covered = [
        {"tactic": tactic, "techniques": covered[tactic]}
        for tactic in ALL_ENTERPRISE_TACTICS
        if tactic in covered
    ]
    not_covered = [t for t in ALL_ENTERPRISE_TACTICS if t not in covered]

    return {
        "rule_count": len(rules),
        "technique_count": len(all_technique_ids),
        "scenario_count": scenario_count,
        "covered": ordered_covered,
        "not_covered": not_covered,
    }
