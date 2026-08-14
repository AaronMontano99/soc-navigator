"""Domain model for SOC Navigator.

Everything downstream (detection, correlation, scoring, AI explanations)
operates on these shapes. Events are intentionally loose (a `fields` bag)
because real telemetry from EDR/identity/email/cloud sources never agrees
on a schema -- Sigma rules are written against whatever field names the
synthetic telemetry uses, same as they would be against a real log source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Event:
    id: str
    timestamp: str  # ISO 8601
    host: Optional[str]
    user: Optional[str]
    event_type: str  # e.g. authentication, process_creation, network_connection, file_modification, email, data_access
    fields: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        if key in ("id", "timestamp", "host", "user", "event_type"):
            return getattr(self, key)
        return self.fields.get(key, default)


@dataclass
class ConfidenceFactor:
    label: str
    weight: int  # positive = increases confidence, negative = decreases it


@dataclass
class Alert:
    id: str
    rule_id: str
    rule_title: str
    severity: str  # informational | low | medium | high | critical (from the rule)
    description: str
    event: Event
    attack_techniques: list[str]
    confidence: int  # 0-100, likelihood this reflects genuinely malicious/risky activity
    increasing_factors: list[ConfidenceFactor]
    decreasing_factors: list[ConfidenceFactor]
    falsepositives: list[str]


@dataclass
class Incident:
    id: str
    scenario_id: str
    title: str
    risk_level: str  # low | medium | high | critical
    status: str  # likely_benign | needs_investigation | confirmed_suspicious
    confidence: int  # max confidence across constituent alerts
    users: list[str]
    hosts: list[str]
    alerts: list[Alert]
    attack_techniques: list[str]
    tactics: list[str]
    created_at: str
    updated_at: str
    source: str = "synthetic"  # "synthetic" (Attack Lab) | "live" (real network scan)
