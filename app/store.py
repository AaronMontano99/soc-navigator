"""In-memory incident store.

Telemetry here is small and static (synthetic scenarios, not a live
stream), so there's no need for a database. Incidents are computed once
per scenario and kept in memory so their IDs stay stable across requests
within a process — re-running a scenario (via the API) replaces just that
scenario's incidents, simulating a fresh detection pass.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.data.scenarios import list_scenarios, load_telemetry
from app.models import Incident
from app.pipeline import run_scenario

_incidents_by_scenario: dict[str, list[Incident]] = {}
_generated_at_by_scenario: dict[str, str] = {}

# Live (real network scan) results — kept entirely separate from the synthetic
# Attack Lab store so /api/dashboard and /api/incidents (both synthetic-only)
# never mix real findings in with the education/demo data.
_live_incidents: list[Incident] = []
_live_scan_meta: dict = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_all() -> None:
    for scenario in list_scenarios():
        _incidents_by_scenario[scenario["id"]] = run_scenario(scenario["id"])
        _generated_at_by_scenario[scenario["id"]] = _now()


def rebuild_scenario(scenario_id: str) -> list[Incident]:
    incidents = run_scenario(scenario_id)
    _incidents_by_scenario[scenario_id] = incidents
    _generated_at_by_scenario[scenario_id] = _now()
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
    for incident in _live_incidents:
        if incident.id == incident_id:
            return incident
    return None


def set_live_scan_result(subnet: str, scanned_at: str, devices: list[dict], incidents: list[Incident]) -> None:
    global _live_incidents
    _live_incidents = incidents
    _live_scan_meta.clear()
    _live_scan_meta.update({"subnet": subnet, "scanned_at": scanned_at, "devices": devices})


def live_incidents() -> list[Incident]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(_live_incidents, key=lambda i: (order.get(i.risk_level, 4), -i.confidence))


def live_scan_meta() -> dict | None:
    return dict(_live_scan_meta) if _live_scan_meta else None


def generated_at(scenario_id: str) -> str | None:
    if not _generated_at_by_scenario:
        _build_all()
    return _generated_at_by_scenario.get(scenario_id)


def raw_event_count() -> int:
    """Total synthetic telemetry events across every scenario that has been run."""
    if not _incidents_by_scenario:
        _build_all()
    return sum(len(load_telemetry(sid)) for sid in _incidents_by_scenario)


def raw_event_count_for(scenario_id: str) -> int:
    return len(load_telemetry(scenario_id))
