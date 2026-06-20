"""Scanner: runs checks over resources with per-check isolation.

A single misbehaving check must never abort a scan. Each ``evaluate`` call is
wrapped so an unexpected exception is logged and recorded as a scan error, and
the remaining checks and resources still run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ghostcloud.checks.base import Registry
from ghostcloud.models import Finding, Resource, Severity
from ghostcloud.snapshot import Snapshot

logger = logging.getLogger("ghostcloud")


@dataclass
class ScanError:
    check_id: str
    resource_id: str
    message: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    resources_scanned: int = 0
    checks_run: int = 0

    def filter_severity(self, minimum: Severity) -> ScanResult:
        kept = [f for f in self.findings if f.severity >= minimum]
        return ScanResult(
            findings=kept,
            errors=self.errors,
            resources_scanned=self.resources_scanned,
            checks_run=self.checks_run,
        )

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def has_at_or_above(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)


def scan(
    snapshot: Snapshot,
    registry: Registry,
    provider: str = "all",
) -> ScanResult:
    """Evaluate all applicable checks for ``provider`` against the snapshot."""

    resources: list[Resource] = snapshot.for_provider(provider)
    checks = registry.for_provider(provider)
    result = ScanResult(resources_scanned=len(resources), checks_run=len(checks))

    for resource in resources:
        for check in checks:
            if not check.applies(resource):
                continue
            try:
                finding = check.evaluate(resource)
            except Exception as exc:  # noqa: BLE001 - isolation is intentional
                logger.warning(
                    "check %s raised on resource %s: %s", check.id, resource.id, exc
                )
                result.errors.append(
                    ScanError(check_id=check.id, resource_id=resource.id, message=str(exc))
                )
                continue
            if finding is not None:
                logger.debug("finding %s on %s", check.id, resource.id)
                result.findings.append(finding)

    result.findings.sort(key=lambda f: (-int(f.severity), f.check_id, f.resource_id))
    return result
