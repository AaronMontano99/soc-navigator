from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_dashboard_includes_raw_events_and_signals():
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert body["raw_events"] >= body["alerts_generated"] >= body["signals"]
    assert "scenario_breakdown" in body


def test_alerts_endpoint_flattens_all_alerts():
    r = client.get("/api/alerts")
    assert r.status_code == 200
    body = r.json()
    assert body["total_alerts"] == len(body["alerts"])
    if body["alerts"]:
        first = body["alerts"][0]
        assert {"rule_title", "incident_id", "confidence", "host"} <= first.keys()


def test_detections_endpoint_lists_all_rules():
    r = client.get("/api/detections")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 10
    assert all("raw_yaml" not in rule for rule in body)  # summary view omits raw text


def test_detection_detail_includes_raw_yaml():
    r = client.get("/api/detections/suspicious_powershell_encoded")
    assert r.status_code == 200
    body = r.json()
    assert "title:" in body["raw_yaml"]


def test_detection_detail_404_for_unknown_rule():
    r = client.get("/api/detections/does-not-exist")
    assert r.status_code == 404


def test_coverage_endpoint_matches_rule_count():
    r = client.get("/api/coverage")
    assert r.status_code == 200
    body = r.json()
    assert body["rule_count"] == 10
    assert set(body["not_covered"]).isdisjoint({t["tactic"] for t in body["covered"]})


def test_account_compromise_incident_includes_destination_host():
    incidents = client.get("/api/incidents?scenario_id=account-compromise").json()
    incident = incidents[0]
    detail = client.get(f"/api/incidents/{incident['id']}").json()
    assert "FINANCE-WS03" in detail["hosts"]
    assert "Potential" in detail["ciso"]["headline"]
    assert "Potential Potential" not in detail["ciso"]["headline"]
    assert "Possible" not in detail["ciso"]["headline"]
