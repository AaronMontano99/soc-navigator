"""Attack Story Mode: registry of synthetic scenarios.

Every scenario is just a telemetry JSON file fed through the same
detection -> correlation -> mapping pipeline used for everything else in
the app. Nothing about a scenario is special-cased in the engine; only
the narrative copy below is scenario-specific.

All telemetry is synthetic and generated for this project. No real
customer, employee, or production data is used anywhere in this repo.
"""

from __future__ import annotations

import json
import os
from typing import Any

_TELEMETRY_DIR = os.path.join(os.path.dirname(__file__), "telemetry")

SCENARIOS: list[dict[str, str]] = [
    {
        "id": "account-compromise",
        "name": "Compromised Account → Lateral Movement",
        "category": "Account Compromise",
        "narrative": (
            "An unusual login is followed by obfuscated PowerShell execution, "
            "credential access, and a pivot to a sensitive finance workstation "
            "over SMB — a textbook account-takeover-to-lateral-movement chain."
        ),
    },
    {
        "id": "ransomware",
        "name": "Ransomware",
        "category": "Ransomware",
        "narrative": (
            "A phishing link leads to PowerShell execution, credential dumping, "
            "lateral movement to a file server, and mass file encryption with a "
            "ransom note dropped — the full kill chain from click to impact."
        ),
    },
    {
        "id": "credential-stuffing",
        "name": "Credential Stuffing",
        "category": "Credential Access",
        "narrative": (
            "A burst of 400+ failed logins against many usernames is followed by "
            "one successful authentication from a new location and an immediate "
            "privileged action — a stolen-password-list attack that succeeded."
        ),
    },
    {
        "id": "insider-threat",
        "name": "Insider Threat",
        "category": "Insider Threat",
        "narrative": (
            "A normal employee downloads an unusually large volume of files "
            "outside their normal scope, off-hours, then uploads a matching "
            "volume of data to an unsanctioned personal cloud account."
        ),
    },
    {
        "id": "false-positive",
        "name": "Benign False Positive",
        "category": "Alert Tuning",
        "narrative": (
            "The same encoded-PowerShell pattern that looked malicious in the "
            "account-compromise scenario shows up again — this time run by IT "
            "during an approved maintenance window using a known deployment "
            "script. Context should drive the verdict, not the raw signature."
        ),
    },
]

_BY_ID = {s["id"]: s for s in SCENARIOS}


def list_scenarios() -> list[dict[str, str]]:
    return SCENARIOS


def get_scenario(scenario_id: str) -> dict[str, str]:
    if scenario_id not in _BY_ID:
        raise KeyError(f"Unknown scenario '{scenario_id}'")
    return _BY_ID[scenario_id]


def load_telemetry(scenario_id: str) -> list[dict[str, Any]]:
    if scenario_id not in _BY_ID:
        raise KeyError(f"Unknown scenario '{scenario_id}'")
    path = os.path.join(_TELEMETRY_DIR, f"{scenario_id}.json")
    with open(path, "r") as f:
        return json.load(f)
