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
from app.mapping.attack import describe
from app.mapping.nist_csf import build_checklist
from app.models import Alert, Incident

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


def _serialize_incident_summary(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "scenario_id": incident.scenario_id,
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
    }


def _serialize_incident_detail(incident: Incident) -> dict[str, Any]:
    summary = _serialize_incident_summary(incident)
    summary.update(
        {
            "alerts": [_serialize_alert(a) for a in incident.alerts],
            "timeline": [
                {
                    "timestamp": a.event.timestamp,
                    "summary": a.rule_title,
                    "host": a.event.host,
                    "user": a.event.user,
                }
                for a in incident.alerts
            ],
            "why_did_we_alert": assistant.why_did_we_alert(incident),
            "analyst": {
                "why_critical": assistant.why_critical(incident),
                "next_steps": assistant.next_steps(incident),
            },
            "ciso": {
                "summary": assistant.ciso_summary(incident),
            },
            "nist_csf": build_checklist(incident),
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
    return {"scenario_id": scenario_id, "incidents": [_serialize_incident_summary(i) for i in incidents]}


@app.get("/api/incidents")
def get_incidents(scenario_id: str | None = None) -> list[dict[str, Any]]:
    incidents = store.all_incidents()
    if scenario_id:
        incidents = [i for i in incidents if i.scenario_id == scenario_id]
    return [_serialize_incident_summary(i) for i in incidents]


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
    incidents = store.all_incidents()
    total_alerts = sum(len(i.alerts) for i in incidents)
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in incidents:
        risk_counts[i.risk_level] = risk_counts.get(i.risk_level, 0) + 1
    investigated = sum(1 for i in incidents if i.status != "likely_benign")
    escalated = sum(1 for i in incidents if i.risk_level in ("high", "critical"))
    return {
        "alerts_generated": total_alerts,
        "incidents_total": len(incidents),
        "risk_counts": risk_counts,
        "investigated": investigated,
        "escalated": escalated,
        "active_incidents": [
            _serialize_incident_summary(i) for i in incidents if i.status != "likely_benign"
        ],
    }


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
