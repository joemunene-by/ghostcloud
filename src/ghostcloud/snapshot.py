"""Snapshot loading: parse a normalized resource snapshot file into Resources.

Snapshot schema (JSON)::

    {
      "schema_version": 1,
      "aws":   [ { "service": "s3", "type": "bucket", "id": "...",
                   "region": "us-east-1", "config": { ... } }, ... ],
      "gcp":   [ ... ],
      "azure": [ ... ]
    }

Each provider key maps to a list of resource objects. ``service``, ``type``, and
``id`` are required on every resource. ``region`` and ``config`` are optional.
Provider keys are optional: a snapshot may describe a single cloud.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ghostcloud.models import PROVIDERS, Resource


class SnapshotError(ValueError):
    """Raised when a snapshot file is missing, malformed, or invalid."""


@dataclass
class Snapshot:
    schema_version: int
    resources: list[Resource]

    def for_provider(self, provider: str) -> list[Resource]:
        if provider == "all":
            return list(self.resources)
        return [r for r in self.resources if r.provider == provider]


def load_snapshot(path: str | Path) -> Snapshot:
    p = Path(path)
    if not p.exists():
        raise SnapshotError(f"snapshot file not found: {p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"snapshot is not valid JSON: {exc}") from exc
    return parse_snapshot(raw)


def parse_snapshot(raw: object) -> Snapshot:
    if not isinstance(raw, dict):
        raise SnapshotError("snapshot root must be a JSON object")

    schema_version = raw.get("schema_version", 1)
    if not isinstance(schema_version, int):
        raise SnapshotError("schema_version must be an integer")

    resources: list[Resource] = []
    seen_provider = False
    for provider in PROVIDERS:
        if provider not in raw:
            continue
        seen_provider = True
        entries = raw[provider]
        if not isinstance(entries, list):
            raise SnapshotError(f"'{provider}' must be a list of resources")
        for index, entry in enumerate(entries):
            try:
                resources.append(Resource.from_dict(provider, entry))
            except ValueError as exc:
                raise SnapshotError(f"{provider}[{index}]: {exc}") from exc

    if not seen_provider:
        raise SnapshotError(
            "snapshot contains no provider keys; expected at least one of: "
            + ", ".join(PROVIDERS)
        )

    return Snapshot(schema_version=schema_version, resources=resources)
