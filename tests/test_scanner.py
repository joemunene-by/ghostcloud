"""Scanner behavior: filtering, thresholds, and per-check isolation."""

from __future__ import annotations

from ghostcloud.checks import default_registry
from ghostcloud.checks.base import Check, Registry
from ghostcloud.models import Finding, Resource, Severity
from ghostcloud.scanner import scan
from ghostcloud.snapshot import load_snapshot, parse_snapshot


def test_filter_severity_drops_below_threshold(aws_vulnerable):
    result = scan(load_snapshot(aws_vulnerable), default_registry(), provider="aws")
    high_only = result.filter_severity(Severity.HIGH)
    assert high_only.findings
    assert all(f.severity >= Severity.HIGH for f in high_only.findings)
    assert len(high_only.findings) < len(result.findings)


def test_has_at_or_above(aws_vulnerable):
    result = scan(load_snapshot(aws_vulnerable), default_registry(), provider="aws")
    assert result.has_at_or_above(Severity.CRITICAL) is True
    assert result.has_at_or_above(Severity.INFO) is True


def test_clean_has_nothing_at_or_above_low(aws_clean):
    result = scan(load_snapshot(aws_clean), default_registry(), provider="aws")
    assert result.has_at_or_above(Severity.LOW) is False
    assert result.max_severity() is None


def test_provider_all_scans_every_cloud():
    snap = parse_snapshot(
        {
            "aws": [
                {
                    "service": "ec2",
                    "type": "volume",
                    "id": "vol-x",
                    "config": {"encrypted": False},
                }
            ],
            "azure": [
                {
                    "service": "storage",
                    "type": "storage_account",
                    "id": "stg-x",
                    "config": {"allow_blob_public_access": True},
                }
            ],
        }
    )
    result = scan(snap, default_registry(), provider="all")
    providers = {f.provider for f in result.findings}
    assert providers == {"aws", "azure"}


class _Exploder(Check):
    id = "GC-TEST-BOOM-001"
    provider = "aws"
    service = "ec2"
    severity = Severity.HIGH
    applies_to_types = ("volume",)

    def evaluate(self, resource: Resource) -> Finding | None:
        raise RuntimeError("synthetic failure")


def test_check_exception_is_isolated():
    registry = Registry()
    registry.register(_Exploder())
    # A second, well-behaved check on the same resource still produces a finding.
    from ghostcloud.checks.aws import EbsVolumeUnencrypted

    registry.register(EbsVolumeUnencrypted())

    snap = parse_snapshot(
        {
            "aws": [
                {
                    "service": "ec2",
                    "type": "volume",
                    "id": "vol-boom",
                    "config": {"encrypted": False},
                }
            ]
        }
    )
    result = scan(snap, registry, provider="aws")

    assert len(result.errors) == 1
    assert result.errors[0].check_id == "GC-TEST-BOOM-001"
    assert result.errors[0].resource_id == "vol-boom"
    # The good check still fired despite the sibling raising.
    assert any(f.check_id == "GC-AWS-EBS-001" for f in result.findings)


def test_scan_counts(aws_vulnerable):
    snap = load_snapshot(aws_vulnerable)
    result = scan(snap, default_registry(), provider="aws")
    assert result.resources_scanned == len(snap.for_provider("aws"))
    assert result.checks_run == len(default_registry().for_provider("aws"))
