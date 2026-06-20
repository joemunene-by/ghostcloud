"""Check base class and the provider-keyed check registry.

A check is a small, self-contained rule. It declares metadata (id, provider,
service, severity, human guidance) and implements ``evaluate``, which inspects a
single :class:`~ghostcloud.models.Resource` and returns a
:class:`~ghostcloud.models.Finding` when the resource is misconfigured, or
``None`` when it is clean or out of scope.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ghostcloud.models import Finding, Resource, Severity


class Check(ABC):
    """Base class for all security checks.

    Subclasses set the class attributes and implement :meth:`evaluate`. The id
    convention is ``GC-<PROVIDER>-<SERVICE>-<NNN>``, for example
    ``GC-AWS-S3-001``.
    """

    id: str = ""
    provider: str = ""
    service: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    remediation: str = ""

    # Resource ``type`` values this check applies to. Empty means "any type
    # within the service". The scanner uses this to skip irrelevant resources
    # cheaply before calling evaluate.
    applies_to_types: tuple[str, ...] = ()

    def applies(self, resource: Resource) -> bool:
        if resource.provider != self.provider or resource.service != self.service:
            return False
        if self.applies_to_types and resource.type not in self.applies_to_types:
            return False
        return True

    @abstractmethod
    def evaluate(self, resource: Resource) -> Finding | None:
        """Return a Finding if ``resource`` violates this check, else None."""

    def finding(
        self,
        resource: Resource,
        evidence: dict[str, Any] | None = None,
        title: str | None = None,
        description: str | None = None,
    ) -> Finding:
        """Helper to build a Finding from this check's metadata."""

        return Finding(
            check_id=self.id,
            provider=self.provider,
            service=self.service,
            title=title or self.title,
            severity=self.severity,
            resource_id=resource.id,
            region=resource.region,
            description=description or self.description,
            remediation=self.remediation,
            evidence=evidence or {},
        )


class Registry:
    """Holds all known checks, indexed by provider."""

    def __init__(self) -> None:
        self._checks: list[Check] = []

    def register(self, check: Check) -> Check:
        if not check.id:
            raise ValueError(f"check {type(check).__name__} has no id")
        if any(existing.id == check.id for existing in self._checks):
            raise ValueError(f"duplicate check id: {check.id}")
        self._checks.append(check)
        return check

    def all(self) -> list[Check]:
        return list(self._checks)

    def for_provider(self, provider: str) -> list[Check]:
        if provider == "all":
            return self.all()
        return [c for c in self._checks if c.provider == provider]

    def __len__(self) -> int:
        return len(self._checks)
