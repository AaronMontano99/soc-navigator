"""Replay public attack recordings through the real detection rules and grade them.

The rules were written against SOC Navigator's own synthetic scenarios, so passing
those proves little. Here the data was recorded by someone else (OTRF), on real
Windows hosts, with real background noise, and the labels are theirs.

Scoring, per rule and recording:
- expected:  the recording's ATT&CK label is the rule's technique  -> fired = detected, silent = missed
- related:   parent/child technique (e.g. labeled T1021, rule T1021.002) -> shown, not scored
- other:     a different technique -> any alert is "unexpected" and listed with its evidence,
             because it can be noise or a correct catch the label didn't mention
There is no per-event ground truth in these datasets, so precision isn't claimed; the
unexpected alerts are shown for a person to judge.
"""

from __future__ import annotations

import collections
import glob
import json
import os
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, field

from app.detection.sigma_engine import run_rules
from app.pipeline import get_rules
from app.replay.normalize import normalize

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
CACHE = os.path.join(ROOT, ".replay-cache", "raw")
HOST_RULES = ("credential_dumping_lsass", "suspicious_powershell_encoded", "smb_lateral_movement")


def manifest() -> list[dict]:
    with open(os.path.join(HERE, "manifest.json")) as f:
        return json.load(f)["datasets"]


def fetch(datasets: list[dict], cache: str = CACHE, log=print) -> None:
    """Download and unpack each recording into its own folder. Archives are only unpacked, never run."""
    for d in datasets:
        folder = os.path.join(cache, d["name"])
        if glob.glob(os.path.join(folder, "*.json")):
            continue
        os.makedirs(folder, exist_ok=True)
        archive = os.path.join(folder, os.path.basename(d["url"]))
        try:
            urllib.request.urlretrieve(d["url"], archive)
        except OSError as err:                      # a moved file upstream: report it, don't guess another URL
            log(f"unavailable: {d['name']} ({err})")
            continue
        if archive.endswith(".zip"):
            with zipfile.ZipFile(archive) as z:
                for member in z.namelist():
                    if member.endswith(".json") and ".." not in member and not member.startswith("/"):
                        z.extract(member, folder)
        else:
            with tarfile.open(archive) as t:
                t.extractall(folder, filter="data")
        log(f"fetched {d['name']}")


def load_events(name: str, cache: str = CACHE) -> tuple[list, int]:
    """Normalized events for one recording, and how many raw events it had."""
    events, total = [], 0
    for path in sorted(glob.glob(os.path.join(cache, name, "**", "*.json"), recursive=True)):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                total += 1
                e = normalize(json.loads(line), total)
                if e is not None:
                    events.append(e)
    return events, total


def relation(rule_tech: str, labels: list[str]) -> str:
    if rule_tech in labels:
        return "expected"
    if any(rule_tech.startswith(l + ".") or l.startswith(rule_tech + ".") for l in labels):
        return "related"
    return "other"


def evidence(alert) -> str:
    f = alert.event.fields
    if alert.rule_id == "credential_dumping_lsass":
        return f"{f.get('process')} opened {f.get('target_process')} ({f.get('granted_access')})"
    if alert.rule_id == "smb_lateral_movement":
        return f"share {f.get('share')} {f.get('relative_target') or ''}".strip()
    return f"{f.get('process')}: {str(f.get('command_line'))[:90]}"


@dataclass
class Cell:
    relation: str
    alerts: int = 0
    evidence: collections.Counter = field(default_factory=collections.Counter)
    confidence: list = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.relation == "expected":
            return "detected" if self.alerts else "missed"
        if self.relation == "related":
            return "related, fired" if self.alerts else "related, silent"
        return "unexpected" if self.alerts else "quiet"


def evaluate(datasets: list[dict] | None = None, cache: str = CACHE, split: str | None = None) -> dict:
    datasets = [d for d in (datasets or manifest()) if split is None or d.get("split", "dev") == split]
    rules = {r["id"]: r for r in get_rules()}
    techs = {rid: next(t.split(".", 1)[1].upper() for t in rules[rid]["tags"] if t.startswith("attack.t")) for rid in HOST_RULES}
    rows, unavailable = [], []
    for d in datasets:
        events, total = load_events(d["name"], cache)
        if not total:
            unavailable.append(d["name"])
            continue
        alerts = run_rules([rules[r] for r in HOST_RULES], events)
        cells = {rid: Cell(relation(techs[rid], d["techniques"])) for rid in HOST_RULES}
        for a in alerts:
            c = cells[a.rule_id]
            c.alerts += 1
            c.evidence[evidence(a)] += 1
            c.confidence.append(a.confidence)
        rows.append({"dataset": d, "raw": total, "mapped": len(events), "cells": cells})
    summary = {}
    for rid in HOST_RULES:
        cs = [r["cells"][rid] for r in rows]
        expected = [c for c in cs if c.relation == "expected"]
        summary[rid] = {
            "technique": techs[rid],
            "expected": len(expected),
            "detected": sum(c.alerts > 0 for c in expected),
            "unexpected_recordings": sum(c.status == "unexpected" for c in cs),
            "alerts": sum(c.alerts for c in cs),
        }
    return {"rows": rows, "summary": summary, "rules": rules, "untested": sorted(set(rules) - set(HOST_RULES)), "split": split,
            "unavailable": unavailable}


def report(result: dict) -> str:
    rows, summary, rules = result["rows"], result["summary"], result["rules"]
    raw = sum(r["raw"] for r in rows)
    out = [
        f"# Detection replay report{': ' + result['split'] + ' recordings' if result.get('split') else ''}",
        "",
        f"The real detection rules, run on {len(rows)} public attack recordings ({raw:,} raw Windows events) from "
        "[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets), recorded on real hosts with ordinary "
        "background activity. Labels are OTRF's ATT&CK mappings. Generated by `python -m app.replay`.",
        "",
        "## Per rule",
        "",
        "| Rule | Technique | Recordings labeled with it | Detected | Recordings with unexpected alerts | Total alerts |",
        "|---|---|---|---|---|---|",
    ]
    for rid, s in summary.items():
        out.append(f"| {rules[rid]['title']} | {s['technique']} | {s['expected']} | {s['detected']} of {s['expected']} | "
                   f"{s['unexpected_recordings']} | {s['alerts']} |")
    out += ["", "## Per recording", "", "| Recording | OTRF label | Events (mapped) | "
            + " | ".join(rules[r]["title"] for r in HOST_RULES) + " |", "|---|---|---|" + "---|" * len(HOST_RULES)]
    for r in rows:
        d = r["dataset"]
        cells = [f"{c.status}" + (f" ({c.alerts})" if c.alerts else "") for c in r["cells"].values()]
        out.append(f"| `{d['name']}` | {', '.join(d['techniques'])} | {r['raw']:,} ({r['mapped']:,}) | " + " | ".join(cells) + " |")
    out += ["", "## What fired, and why", ""]
    for r in rows:
        for rid, c in r["cells"].items():
            if c.alerts or c.status == "missed":
                top = "; ".join(f"{e} x{n}" for e, n in c.evidence.most_common(3)) or "nothing fired"
                conf = f", confidence {min(c.confidence)}-{max(c.confidence)}" if c.confidence else ""
                out.append(f"- **{r['dataset']['name']} / {rules[rid]['title']}: {c.status}**{conf}. {top}")
    if result.get("unavailable"):
        out += ["", f"Could not be downloaded (moved upstream), so not scored: {', '.join(result['unavailable'])}."]
    out += ["", "## Not tested here", "",
            "These rules read identity-provider, email-gateway, SaaS or aggregated file telemetry, which these Windows "
            "host recordings don't contain: " + ", ".join(f"`{u}`" for u in result["untested"]) + ".",
            "",
            "## Limits", "",
            "- The datasets have recording-level labels, not per-event ones, so precision isn't claimed. Unexpected "
            "alerts are listed with their evidence for a person to judge.",
            "- Recordings are from 2019-2020 lab hosts. They show whether a rule's logic survives real logs, not how "
            "it would do on today's tooling or in a busy network.",
            ""]
    return "\n".join(out)
