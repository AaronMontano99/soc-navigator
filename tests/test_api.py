from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_dashboard_reflects_live_network_not_synthetic_demo():
    # Dashboard/Incidents/Alerts are deliberately live-only -- before any
    # scan, everything is honestly zero rather than backfilled with the
    # Attack Lab's demo numbers.
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert body["alerts_generated"] >= body["signals"] >= 0
    assert "has_scanned" in body and "device_breakdown" in body


def test_incidents_endpoint_is_live_only():
    r = client.get("/api/incidents")
    assert r.status_code == 200
    body = r.json()
    assert all(i["source"] == "live" for i in body)


def test_alerts_endpoint_flattens_live_alerts_only():
    r = client.get("/api/alerts")
    assert r.status_code == 200
    body = r.json()
    assert body["total_alerts"] == len(body["alerts"])
    assert "has_scanned" in body
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
    # Synthetic (Attack Lab) incidents are reached by ID from the run
    # response, not from GET /api/incidents -- that endpoint is live-only.
    run = client.post("/api/scenarios/account-compromise/run").json()
    incident = run["incidents"][0]
    detail = client.get(f"/api/incidents/{incident['id']}").json()
    assert "FINANCE-WS03" in detail["hosts"]
    assert "Potential" in detail["ciso"]["headline"]
    assert "Potential Potential" not in detail["ciso"]["headline"]
    assert "Possible" not in detail["ciso"]["headline"]


def test_live_scan_rejects_public_subnet():
    # A real scan is exercised manually (see docs/threat-model.md); this
    # test only needs to confirm the safety boundary is wired to the API.
    r = client.post("/api/live/scan", json={"subnet": "8.8.8.0/24"})
    assert r.status_code == 400
    assert "private" in r.json()["detail"].lower()


def test_live_last_before_any_scan_has_run():
    # Order-independent: whether or not a previous test triggered a scan,
    # the shape of the response must always be well-formed.
    r = client.get("/api/live/last")
    assert r.status_code == 200
    body = r.json()
    assert {"subnet", "scanned_at", "devices", "incidents"} <= body.keys()
