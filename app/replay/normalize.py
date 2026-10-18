"""Map raw Windows events (Sysmon + Security, as OTRF records them) onto SOC Navigator's
event schema, so the same Sigma rules can run on real telemetry.

This is the job OCSF or Elastic's ECS mappings do in a real SIEM. The rule is to map
faithfully, never helpfully: a field is copied as the log recorded it (no ".exe" added,
no definitions widened) so that a rule which misses real data is shown missing it.

Mapped (everything else is kept out, and counted):
- Sysmon 1 / Security 4688, process creation  -> process_creation
- Sysmon 10, a process opening another process -> credential_access (the rules'
  category for "a handle was opened on a process", which is what LSASS dumping is)
- Security 5140 / 5145, network share access    -> network_connection over SMB
"""

from __future__ import annotations

import ntpath
import re
from typing import Any

from app.models import Event

PROCESS_VM_READ = 0x0010
# MITRE T1021.002 (SMB/Windows Admin Shares): "C$, ADMIN$, and IPC$" plus the other drive shares.
_ADMIN_SHARE = re.compile(r"\\(ADMIN|IPC|[A-Z])\$$", re.IGNORECASE)


def _base(path: Any) -> str | None:
    return ntpath.basename(str(path)) if path else None


def _access_rights(granted: Any) -> str | None:
    try:
        mask = int(str(granted), 16)
    except (TypeError, ValueError):
        return None
    return "PROCESS_VM_READ" if mask & PROCESS_VM_READ else f"0x{mask:x}"


def normalize(raw: dict[str, Any], index: int) -> Event | None:
    """One raw Windows event -> one Event, or None when no rule here could use it."""
    eid, channel = raw.get("EventID"), str(raw.get("Channel") or "")
    sysmon = "sysmon" in channel.lower()
    security = channel.lower() == "security"  # some recordings write it lowercase
    host = raw.get("Hostname") or raw.get("Computer")
    ts = str(raw.get("@timestamp") or raw.get("TimeCreated") or raw.get("EventTime") or "")
    base = {"id": f"r{index}", "timestamp": ts, "host": host}

    if (sysmon and eid == 1) or (security and eid == 4688):
        image = raw.get("Image") or raw.get("NewProcessName")
        parent = raw.get("ParentImage") or raw.get("ParentProcessName")
        return Event(**base, user=raw.get("User") or raw.get("SubjectUserName"), event_type="process_creation",
                     fields={"process": _base(image), "image": image, "parent_process": _base(parent),
                             "command_line": raw.get("CommandLine"), "source_event": f"{channel} {eid}"})

    if sysmon and eid == 10:
        return Event(**base, user=raw.get("SourceUser"), event_type="credential_access",
                     fields={"process": _base(raw.get("SourceImage")), "image": raw.get("SourceImage"),
                             "target_process": _base(raw.get("TargetImage")),
                             "access_rights": _access_rights(raw.get("GrantedAccess")),
                             "granted_access": raw.get("GrantedAccess"), "source_event": f"{channel} {eid}"})

    if security and eid in (5140, 5145):
        share = str(raw.get("ShareName") or "")
        return Event(**base, user=raw.get("SubjectUserName"), event_type="network_connection",
                     fields={"protocol": "SMB", "share": share, "admin_share": bool(_ADMIN_SHARE.search(share)),
                             "relative_target": raw.get("RelativeTargetName"), "source_ip": raw.get("IpAddress"),
                             "source_event": f"{channel} {eid}"})
    return None
