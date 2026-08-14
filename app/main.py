"""SOC Navigator API.

Run with: uvicorn app.main:app --reload
Serves the JSON API under /api/* and the static dashboard at /.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import store
from app.ai import assistant
from app.data.scenarios import list_scenarios
from app.detection.registry import coverage_summary, rule_detail, rule_summary
from app.mapping.attack import describe
from app.mapping.nist_csf import build_checklist
from app.models import Alert, Incident
from app.pipeline import get_rules

app = FastAPI(title="SOC Navigator", version="0.1.0")


def _serialize_alert(alert: Alert) -> dict[str, Any]:
    return {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_title": alert.rule_title,
        "severity": alert.severity,
        "description": alert.description,
        "confidence": alert.confidence,
        "attack_techniques": [{"id": t, **describe(t)} for t in alert.attack_techniques],
        "event": {
            "timestamp": alert.event.timestamp,
            "host": alert.event.host,
            "user": alert.event.user,
            "event_type": alert.event.event_type,
            "fields": alert.event.fields,
        },
    }


def _generated_at_for(incident: Incident) -> str | None:
    if incident.source == "live":
        meta = store.live_scan_meta()
        return meta["scanned_at"] if meta else None
    return store.generated_at(incident.scenario_id)


def _serialize_incident_summary(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "scenario_id": incident.scenario_id,
        "source": incident.source,
        "title": incident.title,
        "risk_level": incident.risk_level,
        "status": incident.status,
        "confidence": incident.confidence,
        "users": incident.users,
        "hosts": incident.hosts,
        "attack_techniques": incident.attack_techniques,
        "tactics": incident.tactics,
        "alert_count": len(incident.alerts),
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "generated_at": _generated_at_for(incident),
    }


def _rules_for(incident: Incident) -> list[dict[str, Any]]:
    if incident.source == "live":
        from app.live.pipeline import get_live_rules

        return get_live_rules()
    return get_rules()


def _serialize_incident_detail(incident: Incident) -> dict[str, Any]:
    summary = _serialize_incident_summary(incident)
    total_rules = len(_rules_for(incident))
    summary.update(
        {
            "alerts": [_serialize_alert(a) for a in incident.alerts],
            "timeline": assistant.attack_progression(incident),
            "why_did_we_alert": assistant.why_did_we_alert(incident),
            "analyst": {
                "why_critical": assistant.why_critical(incident),
                "next_steps": assistant.next_steps(incident),
            },
            "ciso": assistant.business_snapshot(incident),
            "nist_csf": build_checklist(incident),
            "attack_chain": {
                "steps": assistant.attack_progression(incident),
                "mapped_techniques": len(incident.attack_techniques),
                "total_techniques": total_rules,
                "note": assistant.attack_chain_note(incident),
            },
        }
    )
    return summary


@app.get("/api/scenarios")
def get_scenarios() -> list[dict[str, str]]:
    return list_scenarios()


@app.post("/api/scenarios/{scenario_id}/run")
def run_scenario_endpoint(scenario_id: str) -> dict[str, Any]:
    try:
        incidents = store.rebuild_scenario(scenario_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown scenario '{scenario_id}'")
    return {
        "scenario_id": scenario_id,
        "raw_events": store.raw_event_count_for(scenario_id),
        "incidents": [_serialize_incident_summary(i) for i in incidents],
    }


@app.get("/api/incidents")
def get_incidents() -> list[dict[str, Any]]:
    """Incidents from your real network (last scan). Attack Lab's synthetic
    incidents are reached directly by ID from the Attack Lab run response —
    see POST /api/scenarios/{id}/run — deliberately not listed here, so this
    view always reflects your actual environment, never the demo data."""
    return [_serialize_incident_summary(i) for i in store.live_incidents()]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _serialize_incident_detail(incident)


class AskRequest(BaseModel):
    question: str


@app.post("/api/incidents/{incident_id}/ask")
def ask_incident(incident_id: str, body: AskRequest) -> dict[str, str]:
    incident = store.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"answer": assistant.answer(incident, body.question)}


@app.get("/api/dashboard")
def get_dashboard() -> dict[str, Any]:
    """Your real network's posture, from the last scan. There is no synthetic
    data in this response — before any scan has run, every count is honestly
    zero rather than backfilled with demo numbers."""
    meta = store.live_scan_meta()
    incidents = store.live_incidents()
    total_alerts = sum(len(i.alerts) for i in incidents)
    total_signals = sum(len(i.alerts) for i in incidents if i.status != "likely_benign")
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in incidents:
        risk_counts[i.risk_level] = risk_counts.get(i.risk_level, 0) + 1
    investigated = sum(1 for i in incidents if i.status != "likely_benign")
    escalated = sum(1 for i in incidents if i.risk_level in ("high", "critical"))

    device_breakdown: dict[str, int] = {}
    for i in incidents:
        for host in i.hosts:
            device_breakdown[host] = device_breakdown.get(host, 0) + len(i.alerts)

    return {
        "has_scanned": meta is not None,
        "subnet": meta["subnet"] if meta else None,
        "scanned_at": meta["scanned_at"] if meta else None,
        "devices_scanned": len(meta["devices"]) if meta else 0,
        "alerts_generated": total_alerts,
        "signals": total_signals,
        "incidents_total": len(incidents),
        "risk_counts": risk_counts,
        "investigated": investigated,
        "escalated": escalated,
        "device_breakdown": [{"ip": ip, "alert_count": c} for ip, c in device_breakdown.items()],
        "active_incidents": [
            _serialize_incident_summary(i) for i in incidents if i.status != "likely_benign"
        ],
    }


@app.get("/api/alerts")
def get_alerts() -> dict[str, Any]:
    """Every finding from your last network scan, before correlation."""
    meta = store.live_scan_meta()
    incidents = store.live_incidents()
    flattened: list[dict[str, Any]] = []
    for incident in incidents:
        for alert in incident.alerts:
            flattened.append(
                {
                    "id": alert.id,
                    "timestamp": alert.event.timestamp,
                    "severity": alert.severity,
                    "rule_id": alert.rule_id,
                    "rule_title": alert.rule_title,
                    "user": alert.event.user,
                    "host": alert.event.host,
                    "attack_techniques": [{"id": t, **describe(t)} for t in alert.attack_techniques],
                    "confidence": alert.confidence,
                    "incident_id": incident.id,
                    "incident_status": incident.status,
                }
            )
    flattened.sort(key=lambda a: a["timestamp"], reverse=True)
    never_escalated = sum(len(i.alerts) for i in incidents if i.status == "likely_benign")
    return {
        "has_scanned": meta is not None,
        "devices_scanned": len(meta["devices"]) if meta else 0,
        "total_alerts": len(flattened),
        "total_signals": len(flattened) - never_escalated,
        "total_incidents": len(incidents),
        "never_escalated": never_escalated,
        "alerts": flattened,
    }


@app.get("/api/detections")
def get_detections() -> list[dict[str, Any]]:
    return [rule_summary(r) for r in get_rules()]


@app.get("/api/detections/{rule_id}")
def get_detection(rule_id: str) -> dict[str, Any]:
    from app.live.pipeline import get_live_rules

    for rule in [*get_rules(), *get_live_rules()]:
        if rule.get("id") == rule_id:
            return rule_detail(rule)
    raise HTTPException(status_code=404, detail=f"Unknown rule '{rule_id}'")


@app.get("/api/coverage")
def get_coverage() -> dict[str, Any]:
    return coverage_summary(get_rules(), scenario_count=len(list_scenarios()))


class LiveScanRequest(BaseModel):
    subnet: str | None = None


def _serialize_live_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "subnet": result["subnet"],
        "scanned_at": result["scanned_at"],
        "devices": result["devices"],
        "incidents": [_serialize_incident_summary(i) for i in result["incidents"]],
    }


@app.post("/api/live/scan")
def run_live_scan_endpoint(body: LiveScanRequest = LiveScanRequest()) -> dict[str, Any]:
    from app.live.pipeline import run_live_scan
    from app.live.scanner import UnsafeSubnetError

    try:
        result = run_live_scan(subnet=body.subnet)
    except UnsafeSubnetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    store.set_live_scan_result(result["subnet"], result["scanned_at"], result["devices"], result["incidents"])
    return _serialize_live_result(result)


@app.get("/api/live/last")
def get_last_live_scan() -> dict[str, Any]:
    meta = store.live_scan_meta()
    if not meta:
        return {"subnet": None, "scanned_at": None, "devices": [], "incidents": []}
    return {
        "subnet": meta["subnet"],
        "scanned_at": meta["scanned_at"],
        "devices": meta["devices"],
        "incidents": [_serialize_incident_summary(i) for i in store.live_incidents()],
    }


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
