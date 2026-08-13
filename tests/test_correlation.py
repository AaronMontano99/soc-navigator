from app.pipeline import run_scenario


def test_account_compromise_correlates_into_one_critical_incident():
    incidents = run_scenario("account-compromise")
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.risk_level == "critical"
    assert incident.status == "confirmed_suspicious"
    assert "j.smith@acme.com" in incident.users
    assert "LAPTOP-184" in incident.hosts
    assert len(incident.alerts) >= 3
    assert len(incident.tactics) >= 3


def test_ransomware_scenario_is_critical_and_spans_two_hosts():
    incidents = run_scenario("ransomware")
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.risk_level == "critical"
    assert "Impact" in incident.tactics
    assert {"WKS-221", "FILESVR-02"} <= set(incident.hosts)
    assert "Possible Ransomware Activity" == incident.title


def test_false_positive_scenario_is_downgraded_to_benign():
    incidents = run_scenario("false-positive")
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.status == "likely_benign"
    assert incident.risk_level == "low"
    assert incident.confidence < 40


def test_all_five_scenarios_produce_at_least_one_incident():
    for scenario_id in [
        "account-compromise",
        "ransomware",
        "credential-stuffing",
        "insider-threat",
        "false-positive",
    ]:
        incidents = run_scenario(scenario_id)
        assert len(incidents) >= 1, f"{scenario_id} produced no incidents"
