import os

from app.detection.sigma_engine import load_rules, run_rules
from app.models import Event

_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "detections", "sigma")


def _rules():
    return load_rules(os.path.abspath(_RULES_DIR))


def test_rules_load():
    rules = _rules()
    assert len(rules) == 10
    ids = {r["id"] for r in rules}
    assert "suspicious_powershell_encoded" in ids


def test_encoded_powershell_matches_and_scores_high_without_context():
    rules = [r for r in _rules() if r["id"] == "suspicious_powershell_encoded"]
    event = Event(
        id="e1",
        timestamp="2026-01-01T00:00:00+00:00",
        host="HOST1",
        user="attacker@acme.com",
        event_type="process_creation",
        fields={
            "process": "powershell.exe",
            "parent_process": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand abcd",
            "network_connection": True,
            "first_seen_for_user": True,
            "user_department": "Sales",
            "approved_maintenance_window": False,
            "known_deployment_script": False,
        },
    )
    alerts = run_rules(rules, [event])
    assert len(alerts) == 1
    assert alerts[0].confidence >= 90


def test_same_signature_scores_low_with_benign_context():
    rules = [r for r in _rules() if r["id"] == "suspicious_powershell_encoded"]
    event = Event(
        id="e2",
        timestamp="2026-01-01T00:00:00+00:00",
        host="MGMT-SVR-04",
        user="it.admin@acme.com",
        event_type="process_creation",
        fields={
            "process": "powershell.exe",
            "parent_process": "services.exe",
            "command_line": "powershell.exe -EncodedCommand abcd",
            "network_connection": False,
            "first_seen_for_user": False,
            "user_department": "IT",
            "approved_maintenance_window": True,
            "known_deployment_script": True,
        },
    )
    alerts = run_rules(rules, [event])
    assert len(alerts) == 1
    assert alerts[0].confidence <= 20


def test_non_matching_event_produces_no_alert():
    rules = _rules()
    event = Event(
        id="e3",
        timestamp="2026-01-01T00:00:00+00:00",
        host="HOST1",
        user="someone@acme.com",
        event_type="process_creation",
        fields={"process": "notepad.exe", "command_line": "notepad.exe report.txt"},
    )
    alerts = run_rules(rules, [event])
    assert alerts == []


def test_numeric_threshold_modifier():
    rules = [r for r in _rules() if r["id"] == "mass_file_modification_ransomware"]
    below = Event(
        id="e4",
        timestamp="2026-01-01T00:00:00+00:00",
        host="HOST1",
        user="user@acme.com",
        event_type="file_modification",
        fields={"extension_change": True, "file_count": 5, "backup_job": False},
    )
    above = Event(
        id="e5",
        timestamp="2026-01-01T00:00:00+00:00",
        host="HOST1",
        user="user@acme.com",
        event_type="file_modification",
        fields={"extension_change": True, "file_count": 5000, "ransom_note_dropped": True, "backup_job": False},
    )
    assert run_rules(rules, [below]) == []
    alerts = run_rules(rules, [above])
    assert len(alerts) == 1
    assert alerts[0].confidence >= 90
