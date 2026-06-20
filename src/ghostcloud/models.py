"""Core data model: severities, providers, resources, and findings.

ghostcloud evaluates a normalized resource snapshot (plain JSON) against a set of
security checks. Nothing here talks to a cloud API: the snapshot is the single
source of truth, which keeps the scanner deterministic, offline, and testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Finding severity, ordered so comparisons and sorting are meaningful.

    Higher integer value means more severe. The ordering is used by
    ``--min-severity`` and ``--fail-on`` thresholds and by report sorting.
    """

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_str(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(
                f"unknown severity {value!r}; choose one of: {valid}"
            ) from exc


# Provider identifiers used throughout the registry and snapshot schema.
PROVIDERS = ("aws", "gcp", "azure")


@dataclass(frozen=True)
class Resource:
    """A single normalized cloud resource drawn from a snapshot.

    Attributes:
        provider: One of ``aws``, ``gcp``, ``azure``.
        service: Logical service name, e.g. ``s3``, ``ec2``, ``storage``.
        type: Resource type within the service, e.g. ``bucket``, ``security_group``.
        id: Stable resource identifier (ARN, self link, resource id, or name).
        region: Region or location the resource lives in (may be empty for global).
        config: Provider-shaped configuration block the checks inspect.
    """

    provider: str
    service: str
    type: str
    id: str
    region: str = ""
    config: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, provider: str, raw: dict[str, Any]) -> Resource:
        if not isinstance(raw, dict):
            raise ValueError(f"resource entry must be an object, got {type(raw).__name__}")
        missing = [k for k in ("service", "type", "id") if k not in raw]
        if missing:
            raise ValueError(
                f"resource is missing required field(s): {', '.join(missing)}"
            )
        config = raw.get("config", {})
        if not isinstance(config, dict):
            raise ValueError(f"resource {raw.get('id')!r} 'config' must be an object")
        return cls(
            provider=provider,
            service=str(raw["service"]),
            type=str(raw["type"]),
            id=str(raw["id"]),
            region=str(raw.get("region", "")),
            config=config,
        )


@dataclass
class Finding:
    """A misconfiguration detected by a check against a resource."""

    check_id: str
    provider: str
    service: str
    title: str
    severity: Severity
    resource_id: str
    region: str
    description: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "provider": self.provider,
            "service": self.service,
            "title": self.title,
            "severity": self.severity.label,
            "resource_id": self.resource_id,
            "region": self.region,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }
