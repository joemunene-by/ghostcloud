"""Snapshot loading and validation tests."""

from __future__ import annotations

import pytest

from ghostcloud.snapshot import SnapshotError, load_snapshot, parse_snapshot


def test_load_multi_provider(fixtures_dir):
    snap = load_snapshot(fixtures_dir.parent.parent / "examples" / "all_providers.json")
    providers = {r.provider for r in snap.resources}
    assert providers == {"aws", "gcp", "azure"}


def test_for_provider_filters(aws_vulnerable):
    snap = load_snapshot(aws_vulnerable)
    assert all(r.provider == "aws" for r in snap.for_provider("aws"))
    assert snap.for_provider("gcp") == []
    assert snap.for_provider("all") == snap.resources


def test_missing_file_raises():
    with pytest.raises(SnapshotError, match="not found"):
        load_snapshot("/does/not/exist.json")


def test_malformed_json_raises(malformed):
    with pytest.raises(SnapshotError, match="not valid JSON"):
        load_snapshot(malformed)


def test_root_must_be_object():
    with pytest.raises(SnapshotError, match="root must be a JSON object"):
        parse_snapshot([1, 2, 3])


def test_no_provider_keys_raises():
    with pytest.raises(SnapshotError, match="no provider keys"):
        parse_snapshot({"schema_version": 1})


def test_provider_must_be_list():
    with pytest.raises(SnapshotError, match="must be a list"):
        parse_snapshot({"aws": {"not": "a list"}})


def test_resource_missing_required_field():
    with pytest.raises(SnapshotError, match="missing required field"):
        parse_snapshot({"aws": [{"service": "s3", "type": "bucket"}]})


def test_resource_config_must_be_object():
    with pytest.raises(SnapshotError, match="must be an object"):
        parse_snapshot(
            {"aws": [{"service": "s3", "type": "bucket", "id": "b", "config": "nope"}]}
        )


def test_schema_version_must_be_int():
    with pytest.raises(SnapshotError, match="schema_version must be an integer"):
        parse_snapshot({"schema_version": "1", "aws": []})
