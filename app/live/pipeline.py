"""Turns a real network scan into real Incidents, using the exact same
detection engine and correlator the synthetic Attack Lab scenarios use.

No detection or correlation logic is duplicated here — `scan_to_events`
is the only new thing. Everything after that (rule matching, confidence
scoring, clustering into incidents, risk-level derivation) is the same
code path as `app/pipeline.py`, just fed real events instead of
synthetic ones.

Discovery/scan functions are accepted as parameters (defaulting to the
real network I/O in `scanner.py`) so this can be exercised in tests
without touching an actual network.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Callable

from app.correlation.correlator import correlate
from app.detection.sigma_engine import load_rules, run_rules
from app.live.scanner import detect_local_subnet, discover_hosts, scan_ports
from app.models import Event, Incident

_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "detections", "live")

# Devices seen in a previous scan this session, for "new device" detection.
# Session-only, like the rest of the app's in-memory state — no persistence.
_seen_ips: set[str] = set()


@lru_cache(maxsize=1)
def get_live_rules() -> list[dict[str, Any]]:
    return load_rules(os.path.abspath(_RULES_DIR))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_to_events(
    devices: list[dict[str, Any]],
    ports_by_ip: dict[str, list[dict[str, Any]]],
    previously_seen: set[str],
) -> list[Event]:
    events: list[Event] = []
    now = _now()
    for device in devices:
        ip = device["ip"]
        is_new = ip not in previously_seen
        events.append(
            Event(
                id=str(uuid.uuid4())[:8],
                timestamp=now,
                host=ip,
                user=None,
                event_type="device_discovery",
                fields={"ip": ip, "hostname": device.get("hostname"), "is_new": is_new},
            )
        )
        for finding in ports_by_ip.get(ip, []):
            events.append(
                Event(
                    id=str(uuid.uuid4())[:8],
                    timestamp=now,
                    host=ip,
                    user=None,
                    event_type="port_exposure",
                    fields={
                        "ip": ip,
                        "hostname": device.get("hostname"),
                        "port": finding["port"],
                        "service": finding["service"],
                        "banner": finding.get("banner"),
                    },
                )
            )
    return events


def run_live_scan(
    subnet: str | None = None,
    discover_fn: Callable[[str], list[dict[str, Any]]] = discover_hosts,
    scan_fn: Callable[[str], list[dict[str, Any]]] = scan_ports,
) -> dict[str, Any]:
    subnet = subnet or detect_local_subnet()
    devices = discover_fn(subnet)

    ports_by_ip = {device["ip"]: scan_fn(device["ip"]) for device in devices}
    previously_seen = set(_seen_ips)
    events = scan_to_events(devices, ports_by_ip, previously_seen)

    alerts = run_rules(get_live_rules(), events)
    incidents = correlate(alerts, scenario_id="live-network", source="live")

    _seen_ips.update(device["ip"] for device in devices)

    return {
        "subnet": subnet,
        "scanned_at": _now(),
        "devices": [
            {
                "ip": d["ip"],
                "hostname": d.get("hostname"),
                "open_ports": ports_by_ip.get(d["ip"], []),
                "is_new": d["ip"] not in previously_seen,
            }
            for d in devices
        ],
        "incidents": incidents,
    }
