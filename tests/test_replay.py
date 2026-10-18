"""Replaying public attack recordings: the normalizer, the tightened host rules, and the scoring."""

import json

from app.detection.sigma_engine import run_rules
from app.pipeline import get_rules
from app.replay import evaluate as ev
from app.replay.normalize import normalize


def _rule(rule_id):
    return [r for r in get_rules() if r["id"] == rule_id]


def _lsass(granted, source="C:\\Windows\\System32\\rundll32.exe"):
    return {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 10, "Hostname": "WS5",
            "SourceImage": source, "TargetImage": "C:\\windows\\system32\\lsass.exe", "GrantedAccess": granted}


def _share(share, target=None, channel="Security"):
    return {"Channel": channel, "EventID": 5145, "Hostname": "DC1", "ShareName": share, "RelativeTargetName": target}


def test_process_access_keeps_what_the_log_recorded():
    e = normalize(_lsass("0x1410"), 1)
    assert e.event_type == "credential_access"
    assert e.fields["process"] == "rundll32.exe" and e.fields["target_process"] == "lsass.exe"
    assert e.fields["access_rights"] == "PROCESS_VM_READ"
    assert normalize(_lsass("0x1000"), 2).fields["access_rights"] == "0x1000"


def test_share_events_are_read_whatever_case_the_channel_is_in():
    assert normalize(_share("\\\\*\\IPC$", channel="security"), 1).event_type == "network_connection"


def test_ipc_counts_as_an_admin_share_the_way_mitre_defines_it():
    assert normalize(_share("\\\\*\\IPC$"), 1).fields["admin_share"] is True
    assert normalize(_share("\\\\*\\SYSVOL"), 1).fields["admin_share"] is False


def test_unmapped_events_are_dropped():
    assert normalize({"Channel": "Security", "EventID": 4658}, 1) is None


def test_lsass_rule_needs_a_memory_read_not_just_a_handle():
    rules = _rule("credential_dumping_lsass")
    assert run_rules(rules, [normalize(_lsass("0x1000", "C:\\Windows\\System32\\svchost.exe"), 1)]) == []
    assert len(run_rules(rules, [normalize(_lsass("0x1fffff"), 2)])) == 1


def test_smb_rule_ignores_routine_ipc_but_catches_service_control_and_file_shares():
    rules = _rule("smb_lateral_movement")
    assert run_rules(rules, [normalize(_share("\\\\*\\IPC$"), 1)]) == []
    assert len(run_rules(rules, [normalize(_share("\\\\*\\IPC$", "svcctl"), 2)])) == 1
    assert len(run_rules(rules, [normalize(_share("\\\\*\\C$", "ProgramData\\payload.exe"), 3)])) == 1


def test_labels_relate_exactly_by_parent_or_not_at_all():
    assert ev.relation("T1021.002", ["T1021.002"]) == "expected"
    assert ev.relation("T1021.002", ["T1021"]) == "related"
    assert ev.relation("T1003.001", ["T1003.002"]) == "other"


def _cache(tmp_path, name, events):
    folder = tmp_path / name
    folder.mkdir()
    (folder / "rec.json").write_text("\n".join(json.dumps(e) for e in events))


def test_a_recording_is_scored_detected_missed_or_unexpected(tmp_path):
    _cache(tmp_path, "dump", [_lsass("0x1fffff")])
    _cache(tmp_path, "quiet_dump", [_lsass("0x1000")])
    _cache(tmp_path, "other", [_lsass("0x1410")])
    datasets = [{"name": "dump", "techniques": ["T1003.001"]}, {"name": "quiet_dump", "techniques": ["T1003.001"]},
                {"name": "other", "techniques": ["T1053.005"]}, {"name": "gone", "techniques": ["T1003.001"]}]
    r = ev.evaluate(datasets, cache=str(tmp_path))
    status = {row["dataset"]["name"]: row["cells"]["credential_dumping_lsass"].status for row in r["rows"]}
    assert status == {"dump": "detected", "quiet_dump": "missed", "other": "unexpected"}
    assert r["unavailable"] == ["gone"]
    assert r["summary"]["credential_dumping_lsass"]["detected"] == 1
    assert "Could not be downloaded" in ev.report(r)


def test_every_manifest_recording_has_otrf_labels_and_a_split():
    for d in ev.manifest():
        assert d["techniques"] and d["otrf_id"].startswith("SDWIN") and d["split"] in ("dev", "holdout")
