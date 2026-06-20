"""Per-check tests: every check fires on its vulnerable fixture and is silent on clean."""

from __future__ import annotations

import pytest

from ghostcloud.checks import default_registry
from ghostcloud.scanner import scan
from ghostcloud.snapshot import load_snapshot

# Every check id we ship. Kept explicit so a dropped or renamed check is caught.
ALL_CHECK_IDS = {
    "GC-AWS-S3-001",
    "GC-AWS-S3-002",
    "GC-AWS-S3-003",
    "GC-AWS-EC2-001",
    "GC-AWS-IAM-001",
    "GC-AWS-IAM-002",
    "GC-AWS-RDS-001",
    "GC-AWS-RDS-002",
    "GC-AWS-CLOUDTRAIL-001",
    "GC-AWS-EBS-001",
    "GC-GCP-STORAGE-001",
    "GC-GCP-VPC-001",
    "GC-GCP-IAM-001",
    "GC-GCP-COMPUTE-001",
    "GC-AZURE-STORAGE-001",
    "GC-AZURE-NSG-001",
    "GC-AZURE-DISK-001",
}


def _scan(path, provider):
    return scan(load_snapshot(path), default_registry(), provider=provider)


def test_registry_has_expected_check_ids():
    registry = default_registry()
    ids = {c.id for c in registry.all()}
    assert ids == ALL_CHECK_IDS
    assert len(registry) >= 15


def test_no_duplicate_check_ids():
    ids = [c.id for c in default_registry().all()]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    ("fixture", "provider", "expected_ids"),
    [
        (
            "aws_vulnerable.json",
            "aws",
            {
                "GC-AWS-S3-001",
                "GC-AWS-S3-002",
                "GC-AWS-S3-003",
                "GC-AWS-EC2-001",
                "GC-AWS-IAM-001",
                "GC-AWS-IAM-002",
                "GC-AWS-RDS-001",
                "GC-AWS-RDS-002",
                "GC-AWS-CLOUDTRAIL-001",
                "GC-AWS-EBS-001",
            },
        ),
        (
            "gcp_vulnerable.json",
            "gcp",
            {
                "GC-GCP-STORAGE-001",
                "GC-GCP-VPC-001",
                "GC-GCP-IAM-001",
                "GC-GCP-COMPUTE-001",
            },
        ),
        (
            "azure_vulnerable.json",
            "azure",
            {
                "GC-AZURE-STORAGE-001",
                "GC-AZURE-NSG-001",
                "GC-AZURE-DISK-001",
            },
        ),
    ],
)
def test_vulnerable_fires_every_check(fixtures_dir, fixture, provider, expected_ids):
    result = _scan(fixtures_dir / fixture, provider)
    fired = {f.check_id for f in result.findings}
    assert fired == expected_ids
    assert result.errors == []


@pytest.mark.parametrize(
    ("fixture", "provider"),
    [
        ("aws_clean.json", "aws"),
        ("gcp_clean.json", "gcp"),
        ("azure_clean.json", "azure"),
    ],
)
def test_clean_fires_nothing(fixtures_dir, fixture, provider):
    result = _scan(fixtures_dir / fixture, provider)
    assert result.findings == []
    assert result.errors == []


def test_findings_sorted_by_severity_descending(aws_vulnerable):
    result = _scan(aws_vulnerable, "aws")
    severities = [int(f.severity) for f in result.findings]
    assert severities == sorted(severities, reverse=True)


def test_findings_carry_resource_metadata(aws_vulnerable):
    result = _scan(aws_vulnerable, "aws")
    sg = next(f for f in result.findings if f.check_id == "GC-AWS-EC2-001")
    assert sg.resource_id == "sg-0a1b2c3d4e"
    assert sg.region == "us-east-1"
    assert sg.remediation
    assert "open_admin_rules" in sg.evidence
