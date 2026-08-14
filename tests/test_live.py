"""Tests for the live network scanner and pipeline.

Deliberately no real network I/O here — discover_hosts/scan_ports are
swapped for fakes so the suite stays fast and deterministic in CI. The
scanner's actual socket/subprocess code is exercised manually (see
docs/threat-model.md), not in the automated suite.
"""

import pytest

from app.live.pipeline import run_live_scan
from app.live.scanner import UnsafeSubnetError, validate_subnet


def _fake_discover(devices):
    def discover(subnet):
        return devices

    return discover


def _fake_scan(ports_by_ip):
    def scan(ip):
        return ports_by_ip.get(ip, [])

    return scan


@pytest.fixture(autouse=True)
def reset_seen_ips():
    from app.live import pipeline

    pipeline._seen_ips.clear()
    yield
    pipeline._seen_ips.clear()


def test_validate_subnet_rejects_public_ranges():
    with pytest.raises(UnsafeSubnetError):
        validate_subnet("8.8.8.0/24")


def test_validate_subnet_rejects_oversized_ranges():
    with pytest.raises(UnsafeSubnetError):
        validate_subnet("10.0.0.0/16")


def test_validate_subnet_accepts_private_slash_24():
    network = validate_subnet("192.168.1.0/24")
    assert str(network) == "192.168.1.0/24"


def test_telnet_exposure_produces_critical_finding():
    result = run_live_scan(
        subnet="192.168.1.0/24",
        discover_fn=_fake_discover([{"ip": "192.168.1.10", "hostname": "device.local"}]),
        scan_fn=_fake_scan({"192.168.1.10": [{"port": 23, "service": "Telnet", "banner": None}]}),
    )
    assert len(result["incidents"]) == 1
    incident = result["incidents"][0]
    assert incident.source == "live"
    assert incident.risk_level == "critical"
    assert incident.title == "Insecure Telnet Service Exposed"
    assert incident.attack_techniques == []  # exposure findings claim no ATT&CK technique


def test_benign_ports_produce_no_exposure_finding():
    result = run_live_scan(
        subnet="192.168.1.0/24",
        discover_fn=_fake_discover([{"ip": "192.168.1.20", "hostname": None}]),
        scan_fn=_fake_scan({"192.168.1.20": [{"port": 80, "service": "HTTP", "banner": None}]}),
    )
    # No live rule matches port 80 by itself -- only the (informational)
    # new-device finding should appear, nothing alarming.
    assert len(result["incidents"]) == 1
    assert result["incidents"][0].title == "New Device Joined the Network"
    assert result["incidents"][0].risk_level == "low"


def test_multiple_findings_on_one_device_correlate_into_one_incident():
    result = run_live_scan(
        subnet="192.168.1.0/24",
        discover_fn=_fake_discover([{"ip": "192.168.1.10", "hostname": None}]),
        scan_fn=_fake_scan(
            {
                "192.168.1.10": [
                    {"port": 23, "service": "Telnet", "banner": None},
                    {"port": 445, "service": "SMB", "banner": None},
                ]
            }
        ),
    )
    assert len(result["incidents"]) == 1
    incident = result["incidents"][0]
    # 3 alerts: telnet_exposed, file_share_exposed, and new_device_on_network
    assert len(incident.alerts) == 3


def test_device_is_new_on_first_scan_and_not_on_second():
    devices = [{"ip": "192.168.1.30", "hostname": None}]
    first = run_live_scan(subnet="192.168.1.0/24", discover_fn=_fake_discover(devices), scan_fn=_fake_scan({}))
    second = run_live_scan(subnet="192.168.1.0/24", discover_fn=_fake_discover(devices), scan_fn=_fake_scan({}))

    assert first["devices"][0]["is_new"] is True
    assert second["devices"][0]["is_new"] is False
    # First scan flags it as a new-device finding; second scan (nothing
    # changed, already seen) produces no finding at all.
    assert len(first["incidents"]) == 1
    assert len(second["incidents"]) == 0
