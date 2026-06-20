"""Report rendering tests: JSON round-trip and SARIF 2.1.0 validity."""

from __future__ import annotations

import json

from ghostcloud.checks import default_registry
from ghostcloud.report import to_json, to_sarif
from ghostcloud.scanner import scan
from ghostcloud.snapshot import load_snapshot


def _scan(path, provider="all"):
    return scan(load_snapshot(path), default_registry(), provider=provider)


def test_json_roundtrip(aws_vulnerable):
    result = _scan(aws_vulnerable, "aws")
    payload = json.loads(to_json(result))
    assert payload["tool"] == "ghostcloud"
    assert payload["summary"]["findings"] == len(result.findings)
    assert len(payload["findings"]) == len(result.findings)
    sample = payload["findings"][0]
    for key in (
        "check_id",
        "provider",
        "service",
        "title",
        "severity",
        "resource_id",
        "remediation",
        "evidence",
    ):
        assert key in sample


def test_json_clean_has_no_findings(aws_clean):
    payload = json.loads(to_json(_scan(aws_clean, "aws")))
    assert payload["findings"] == []
    assert payload["summary"]["findings"] == 0


def test_sarif_structure_is_valid(aws_vulnerable):
    result = _scan(aws_vulnerable, "aws")
    log = json.loads(to_sarif(result))

    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    assert len(log["runs"]) == 1

    run = log["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ghostcloud"

    rule_ids = {r["id"] for r in driver["rules"]}
    result_rule_ids = {r["ruleId"] for r in run["results"]}
    # Every result references a defined rule.
    assert result_rule_ids <= rule_ids
    assert len(run["results"]) == len(result.findings)

    for r in run["results"]:
        assert r["level"] in ("error", "warning", "note", "none")
        assert r["message"]["text"]
        loc = r["locations"][0]
        assert loc["logicalLocations"][0]["fullyQualifiedName"]

    for rule in driver["rules"]:
        sev = rule["properties"]["security-severity"]
        assert 0.0 <= float(sev) <= 10.0
        assert rule["defaultConfiguration"]["level"] in ("error", "warning", "note", "none")


def test_sarif_empty_findings(aws_clean):
    log = json.loads(to_sarif(_scan(aws_clean, "aws")))
    run = log["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
