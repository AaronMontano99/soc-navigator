"""A small, self-contained interpreter for a *subset* of the Sigma rule spec.

Sigma (https://github.com/SigmaHQ/sigma) is the open, YAML-based standard
for describing detections in a SIEM-agnostic way: a `logsource`, one or
more named `detection` selections, a `condition` that combines them, and
metadata (`level`, `tags` with `attack.*` technique IDs, `falsepositives`).

This engine implements the mechanics that matter for a portfolio-scale SOC
simulator, without pulling in a full Sigma backend/pySigma dependency:

  - selections are `field: value` (equality / OR-over-list) or
    `field|contains|startswith|endswith: value` (string modifiers, also
    OR-over-list)
  - conditions are boolean expressions over selection names using
    `and`, `or`, `and not` (sufficient for single-log-source detections;
    Sigma's full aggregation/`1 of`/`near` grammar is intentionally out
    of scope -- see docs/detection-methodology.md)

It also layers on a `confidence` block that is NOT part of upstream Sigma.
That's a deliberate SOC Navigator extension: real analysts don't treat a
rule match as a binary verdict, they weigh context (who, what host, what
time, is this expected). Encoding that as declarative increase/decrease
factors keeps the "why did we alert" reasoning data-driven per rule
instead of hardcoded per demo scenario.
"""

from __future__ import annotations

import glob
import os
import uuid
from typing import Any

import yaml

from app.models import Alert, ConfidenceFactor, Event


def load_rules(rules_dir: str) -> list[dict[str, Any]]:
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        with open(path, "r") as f:
            rule = yaml.safe_load(f)
        rule["_path"] = path
        rules.append(rule)
    return rules


def _technique_ids(rule: dict[str, Any]) -> list[str]:
    ids = []
    for tag in rule.get("tags", []):
        if tag.startswith("attack.t"):
            ids.append(tag.split(".", 1)[1].upper())
    return ids


_NUMERIC_MODIFIERS = {"gt", "gte", "lt", "lte"}


def _value_matches(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False
    if modifier in _NUMERIC_MODIFIERS:
        try:
            actual_num, expected_num = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {
            "gt": actual_num > expected_num,
            "gte": actual_num >= expected_num,
            "lt": actual_num < expected_num,
            "lte": actual_num <= expected_num,
        }[modifier]

    candidates = expected if isinstance(expected, list) else [expected]
    actual_str = str(actual).lower()
    for cand in candidates:
        cand_str = str(cand).lower()
        if modifier == "contains":
            if cand_str in actual_str:
                return True
        elif modifier == "startswith":
            if actual_str.startswith(cand_str):
                return True
        elif modifier == "endswith":
            if actual_str.endswith(cand_str):
                return True
        else:
            if actual_str == cand_str:
                return True
    return False


def _selection_matches(selection: dict[str, Any], event: Event) -> bool:
    for raw_field, expected in selection.items():
        modifier = None
        field_name = raw_field
        if "|" in raw_field:
            field_name, modifier = raw_field.split("|", 1)
        actual = event.get(field_name)
        if not _value_matches(actual, expected, modifier):
            return False
    return True


def _condition_matches(condition: str, selections: dict[str, dict], event: Event) -> bool:
    condition = condition.strip()
    if " and not " in condition:
        left, right = condition.split(" and not ", 1)
        return _condition_matches(left, selections, event) and not _condition_matches(
            right, selections, event
        )
    if " and " in condition:
        left, right = condition.split(" and ", 1)
        return _condition_matches(left, selections, event) and _condition_matches(
            right, selections, event
        )
    if " or " in condition:
        left, right = condition.split(" or ", 1)
        return _condition_matches(left, selections, event) or _condition_matches(
            right, selections, event
        )
    name = condition.strip()
    if name not in selections:
        raise ValueError(f"Condition references unknown selection '{name}'")
    return _selection_matches(selections[name], event)


def rule_matches_event(rule: dict[str, Any], event: Event) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not condition or not selections:
        return False
    return _condition_matches(condition, selections, event)


def _check_field_condition(check: dict[str, Any], event: Event) -> bool:
    value = event.get(check["field"])
    if "equals" in check:
        return str(value).lower() == str(check["equals"]).lower() if value is not None else False
    if "not_equals" in check:
        return str(value).lower() != str(check["not_equals"]).lower() if value is not None else True
    if "in" in check:
        return value is not None and str(value).lower() in [str(v).lower() for v in check["in"]]
    if "not_in" in check:
        if value is None:
            return True
        return str(value).lower() not in [str(v).lower() for v in check["not_in"]]
    if "exists" in check:
        present = value is not None
        return present == bool(check["exists"])
    for modifier in _NUMERIC_MODIFIERS:
        if modifier in check:
            return _value_matches(value, check[modifier], modifier)
    return False


def score_confidence(
    rule: dict[str, Any], event: Event
) -> tuple[int, list[ConfidenceFactor], list[ConfidenceFactor]]:
    conf_cfg = rule.get("confidence", {})
    score = int(conf_cfg.get("base", 50))
    increasing: list[ConfidenceFactor] = []
    decreasing: list[ConfidenceFactor] = []

    for item in conf_cfg.get("increase", []):
        if _check_field_condition(item["field_check"], event):
            weight = int(item["weight"])
            score += weight
            increasing.append(ConfidenceFactor(label=item["factor"], weight=weight))

    for item in conf_cfg.get("decrease", []):
        if _check_field_condition(item["field_check"], event):
            weight = int(item["weight"])
            score += weight  # weight is already negative in the rule
            decreasing.append(ConfidenceFactor(label=item["factor"], weight=weight))

    score = max(3, min(97, score))
    return score, increasing, decreasing


def run_rules(rules: list[dict[str, Any]], events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        for rule in rules:
            if not rule_matches_event(rule, event):
                continue
            confidence, increasing, decreasing = score_confidence(rule, event)
            alerts.append(
                Alert(
                    id=str(uuid.uuid4())[:8],
                    rule_id=rule.get("id", os.path.basename(rule.get("_path", ""))),
                    rule_title=rule.get("title", "Untitled rule"),
                    severity=rule.get("level", "medium"),
                    description=rule.get("description", ""),
                    event=event,
                    attack_techniques=_technique_ids(rule),
                    confidence=confidence,
                    increasing_factors=increasing,
                    decreasing_factors=decreasing,
                    falsepositives=rule.get("falsepositives", []),
                )
            )
    alerts.sort(key=lambda a: a.event.timestamp)
    return alerts
