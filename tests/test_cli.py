"""End-to-end CLI tests using Typer's CliRunner."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ghostcloud.cli import app

runner = CliRunner()


def test_version():
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "ghostcloud" in res.stdout


def test_checks_lists_all():
    res = runner.invoke(app, ["checks"])
    assert res.exit_code == 0
    assert "GC-AWS-S3-001" in res.stdout
    assert "GC-GCP-STORAGE-001" in res.stdout
    assert "GC-AZURE-NSG-001" in res.stdout


def test_checks_provider_filter():
    res = runner.invoke(app, ["checks", "--provider", "aws"])
    assert res.exit_code == 0
    assert "GC-AWS-S3-001" in res.stdout
    assert "GC-GCP" not in res.stdout


def test_scan_console_clean(aws_clean):
    res = runner.invoke(app, ["scan", "--input", str(aws_clean), "--provider", "aws"])
    assert res.exit_code == 0
    assert "No findings" in res.stdout


def test_scan_console_vulnerable(aws_vulnerable):
    res = runner.invoke(app, ["scan", "--input", str(aws_vulnerable), "--provider", "aws"])
    assert res.exit_code == 0
    assert "GC-AWS-S3-001" in res.stdout


def test_scan_json_format(aws_vulnerable):
    res = runner.invoke(
        app, ["scan", "--input", str(aws_vulnerable), "--provider", "aws", "--format", "json"]
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)
    assert payload["summary"]["findings"] > 0


def test_scan_sarif_format(aws_vulnerable):
    res = runner.invoke(
        app, ["scan", "--input", str(aws_vulnerable), "--provider", "aws", "--format", "sarif"]
    )
    assert res.exit_code == 0
    log = json.loads(res.stdout)
    assert log["version"] == "2.1.0"


def test_fail_on_critical_exits_nonzero(aws_vulnerable):
    res = runner.invoke(
        app,
        ["scan", "--input", str(aws_vulnerable), "--provider", "aws", "--fail-on", "critical"],
    )
    assert res.exit_code == 1


def test_fail_on_clean_exits_zero(aws_clean):
    res = runner.invoke(
        app,
        ["scan", "--input", str(aws_clean), "--provider", "aws", "--fail-on", "low"],
    )
    assert res.exit_code == 0


def test_min_severity_suppresses_low_findings(aws_vulnerable):
    # With min-severity critical, fail-on high should not trip because only
    # critical findings remain to be compared. Verify counts shrink.
    full = runner.invoke(
        app, ["scan", "--input", str(aws_vulnerable), "--provider", "aws", "--format", "json"]
    )
    filtered = runner.invoke(
        app,
        [
            "scan",
            "--input",
            str(aws_vulnerable),
            "--provider",
            "aws",
            "--format",
            "json",
            "--min-severity",
            "critical",
        ],
    )
    full_count = json.loads(full.stdout)["summary"]["findings"]
    filtered_count = json.loads(filtered.stdout)["summary"]["findings"]
    assert filtered_count < full_count
    assert all(
        f["severity"] == "CRITICAL" for f in json.loads(filtered.stdout)["findings"]
    )


def test_malformed_snapshot_exits_two(malformed):
    res = runner.invoke(app, ["scan", "--input", str(malformed), "--provider", "aws"])
    assert res.exit_code == 2


def test_missing_snapshot_exits_two():
    res = runner.invoke(app, ["scan", "--input", "/no/such/file.json"])
    assert res.exit_code == 2


def test_scan_output_to_file(aws_vulnerable, tmp_path):
    out = tmp_path / "report.json"
    res = runner.invoke(
        app,
        [
            "scan",
            "--input",
            str(aws_vulnerable),
            "--provider",
            "aws",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert res.exit_code == 0
    assert out.exists()
    payload = json.loads(out.read_text())
    assert payload["summary"]["findings"] > 0


def test_scan_all_providers(fixtures_dir):
    example = fixtures_dir.parent.parent / "examples" / "all_providers.json"
    res = runner.invoke(app, ["scan", "--input", str(example), "--provider", "all"])
    assert res.exit_code == 0
    assert "GC-AWS" in res.stdout
    assert "GC-GCP" in res.stdout
    assert "GC-AZURE" in res.stdout
