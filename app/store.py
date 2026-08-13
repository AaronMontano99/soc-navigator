"""In-memory incident store.

Telemetry here is small and static (synthetic scenarios, not a live
stream), so there's no need for a database. Incidents are computed once
per scenario and kept in memory so their IDs stay stable across requests
within a process — re-running a scenario (via the API) replaces just that
scenario's incidents, simulating a fresh detection pass.
"""

from __future__ import annotations

from app.data.scenarios import list_scenarios
from app.models import Incident
from app.pipeline import run_scenario

_incidents_by_scenario: dict[str, list[Incident]] = {}


def _build_all() -> None:
    for scenario in list_scenarios():
        _incidents_by_scenario[scenario["id"]] = run_scenario(scenario["id"])


def rebuild_scenario(scenario_id: str) -> list[Incident]:
    incidents = run_scenario(scenario_id)
    _incidents_by_scenario[scenario_id] = incidents
    return incidents


def all_incidents() -> list[Incident]:
    if not _incidents_by_scenario:
        _build_all()
    out: list[Incident] = []
    for incidents in _incidents_by_scenario.values():
        out.extend(incidents)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda i: (order.get(i.risk_level, 4), -i.confidence))
    return out


def get_incident(incident_id: str) -> Incident | None:
    for incident in all_incidents():
        if incident.id == incident_id:
            return incident
    return None
