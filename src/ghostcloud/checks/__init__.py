"""Check package: assembles the default registry from all provider modules."""

from __future__ import annotations

from ghostcloud.checks import aws, azure, gcp
from ghostcloud.checks.base import Check, Registry


def default_registry() -> Registry:
    """Build a fresh registry populated with every shipped check."""

    registry = Registry()
    for module in (aws, gcp, azure):
        for check in module.build():
            registry.register(check)
    return registry


__all__ = ["Check", "Registry", "default_registry"]
