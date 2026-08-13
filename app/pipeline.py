"""Wires telemetry -> detection -> correlation into a single call.

This is deliberately the only place that knows about all the other
modules; everything else (API layer, AI assistant) works off the
resulting Incident objects.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from app.correlation.correlator import correlate
from app.data.scenarios import load_telemetry
from app.detection.sigma_engine import load_rules, run_rules
from app.models import Event, Incident

_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "detections", "sigma")


@lru_cache(maxsize=1)
def get_rules() -> list[dict[str, Any]]:
    return load_rules(os.path.abspath(_RULES_DIR))


def _to_events(raw_events: list[dict[str, Any]]) -> list[Event]:
    return [
        Event(
            id=e["id"],
            timestamp=e["timestamp"],
            host=e.get("host"),
            user=e.get("user"),
            event_type=e["event_type"],
            fields=e.get("fields", {}),
        )
        for e in raw_events
    ]


def run_scenario(scenario_id: str) -> list[Incident]:
    events = _to_events(load_telemetry(scenario_id))
    alerts = run_rules(get_rules(), events)
    return correlate(alerts, scenario_id)


@lru_cache(maxsize=1)
def _all_scenario_ids() -> tuple[str, ...]:
    from app.data.scenarios import list_scenarios

    return tuple(s["id"] for s in list_scenarios())


def run_all_scenarios() -> list[Incident]:
    incidents: list[Incident] = []
    for scenario_id in _all_scenario_ids():
        incidents.extend(run_scenario(scenario_id))
    return incidents
