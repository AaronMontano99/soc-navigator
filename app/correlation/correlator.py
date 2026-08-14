"""Alert correlation and incident scoring.

This is the piece that matters most for the pitch: don't hand an analyst
143 individual alerts, group the ones that are actually the same story.

Alerts are clustered with union-find: two alerts join the same cluster if
they share a user or a host and occur within CORRELATION_WINDOW_MINUTES of
each other. That's enough to capture "same user, different host" (lateral
movement) and "same host, different user" (shared workstation) without
needing a bespoke graph per scenario.

Risk level is derived, not asserted: a mix of the rule severities involved,
the confidence the detection engine attached to each alert, and how many
distinct ATT&CK tactics are represented (a single high-severity alert is
serious; three techniques spanning Initial Access -> Credential Access ->
Lateral Movement in one session is a materially bigger deal, because it
shows a kill chain rather than an isolated event).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from app.mapping.attack import tactics_for
from app.models import Alert, Incident

CORRELATION_WINDOW_MINUTES = 180

_RISK_LEVELS = ["low", "medium", "high", "critical"]
_SEVERITY_RANK = {"informational": 0, "low": 0, "medium": 1, "high": 2, "critical": 3}


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _severity_tier(alerts: list[Alert]) -> str:
    max_rank = max(_SEVERITY_RANK.get(a.severity, 1) for a in alerts)
    return _RISK_LEVELS[max_rank]


def _status_for(confidence: int) -> str:
    if confidence < 40:
        return "likely_benign"
    if confidence < 70:
        return "needs_investigation"
    return "confirmed_suspicious"


def _dominant_alert(alerts: list[Alert]) -> Alert:
    """The single most salient alert in a cluster — highest rule severity,
    tie-broken by confidence. Used wherever a title needs to represent 'the
    finding that matters most' rather than 'whichever alert came first' —
    the latter is meaningless for a cluster of same-timestamp findings, like
    everything a live network scan produces for one host in one pass.
    """
    return max(alerts, key=lambda a: (_SEVERITY_RANK.get(a.severity, 1), a.confidence))


def _title_for(tactics: list[str], status: str, alerts: list[Alert]) -> str:
    if status == "likely_benign":
        return f"{_dominant_alert(alerts).rule_title} — Reviewed, Likely Benign"
    tset = set(tactics)
    if "Impact" in tset:
        return "Possible Ransomware Activity"
    if {"Credential Access", "Lateral Movement"} <= tset:
        return "Possible Account Compromise → Lateral Movement"
    if "Credential Access" in tset and any(t == "T1110.004" for a in alerts for t in a.attack_techniques):
        return "Possible Credential Stuffing Attack"
    if {"Collection", "Exfiltration"} & tset:
        return "Possible Data Exfiltration / Insider Threat Activity"
    if len(tactics) > 1:
        return " → ".join(tactics) + " Activity"
    return _dominant_alert(alerts).rule_title


def correlate(alerts: list[Alert], scenario_id: str, source: str = "synthetic") -> list[Incident]:
    if not alerts:
        return []

    uf = _UnionFind(len(alerts))
    for i in range(len(alerts)):
        for j in range(i + 1, len(alerts)):
            a, b = alerts[i], alerts[j]
            shares_entity = (a.event.user and a.event.user == b.event.user) or (
                a.event.host and a.event.host == b.event.host
            )
            if not shares_entity:
                continue
            delta = abs((_parse_ts(a.event.timestamp) - _parse_ts(b.event.timestamp)).total_seconds())
            if delta <= CORRELATION_WINDOW_MINUTES * 60:
                uf.union(i, j)

    clusters: dict[int, list[Alert]] = {}
    for i, alert in enumerate(alerts):
        clusters.setdefault(uf.find(i), []).append(alert)

    incidents: list[Incident] = []
    for cluster_alerts in clusters.values():
        cluster_alerts = sorted(cluster_alerts, key=lambda a: a.event.timestamp)
        users = sorted({a.event.user for a in cluster_alerts if a.event.user})
        host_set = {a.event.host for a in cluster_alerts if a.event.host}
        # A network-connection alert's source is event.host; its destination
        # (e.g. a lateral-movement target) is only in fields.dest_host — both
        # are "affected assets" for the incident.
        host_set |= {
            a.event.fields.get("dest_host")
            for a in cluster_alerts
            if a.event.fields.get("dest_host")
        }
        hosts = sorted(host_set)
        technique_ids: list[str] = []
        for a in cluster_alerts:
            for t in a.attack_techniques:
                if t not in technique_ids:
                    technique_ids.append(t)
        tactics = tactics_for(technique_ids)
        confidence = max(a.confidence for a in cluster_alerts)
        status = _status_for(confidence)

        # Risk level tracks impact (rule severity, kill-chain depth), not detection
        # confidence — confidence instead drives `status` above. A 4+ stage chain
        # (e.g. initial access through impact) escalates one tier because it shows
        # a completed kill chain rather than an isolated high-severity event. An
        # incident that hasn't cleared the confirmed-suspicious confidence bar yet
        # is capped at "high" even if the underlying techniques would be critical,
        # since escalating to critical on unconfirmed activity would itself be the
        # kind of noise this tool is trying to cut down.
        base_rank = _RISK_LEVELS.index(_severity_tier(cluster_alerts))
        if len(tactics) >= 4:
            base_rank = min(base_rank + 1, len(_RISK_LEVELS) - 1)
        if status == "needs_investigation":
            base_rank = min(base_rank, _RISK_LEVELS.index("high"))
        risk_level = "low" if status == "likely_benign" else _RISK_LEVELS[base_rank]

        timestamps = [a.event.timestamp for a in cluster_alerts]
        incidents.append(
            Incident(
                id=str(uuid.uuid4())[:8],
                scenario_id=scenario_id,
                title=_title_for(tactics, status, cluster_alerts),
                risk_level=risk_level,
                status=status,
                confidence=confidence,
                users=users,
                hosts=hosts,
                alerts=cluster_alerts,
                attack_techniques=technique_ids,
                tactics=tactics,
                created_at=min(timestamps),
                updated_at=max(timestamps),
                source=source,
            )
        )

    incidents.sort(key=lambda i: (_RISK_LEVELS.index(i.risk_level), i.confidence), reverse=True)
    return incidents
