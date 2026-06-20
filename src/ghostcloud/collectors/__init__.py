"""Collector interfaces for producing snapshots from live cloud APIs.

The core scanner runs entirely on snapshot files and needs no cloud credentials.
Collectors are an optional, future-facing seam: a collector reads a live account
and emits the same normalized snapshot dict the file loader consumes. The
default registry is empty so importing this package pulls in no cloud SDKs.

To add live collection, implement :class:`Collector` (for example with boto3 for
AWS) and register it, then a future ``--live`` flag can build a snapshot in
memory and hand it to :func:`ghostcloud.snapshot.parse_snapshot`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Collector(ABC):
    """Produces a normalized snapshot fragment for one provider."""

    provider: str = ""

    @abstractmethod
    def collect(self) -> list[dict[str, Any]]:
        """Return a list of normalized resource dicts for this provider."""


class CollectorRegistry:
    """Registry of available live collectors, keyed by provider."""

    def __init__(self) -> None:
        self._collectors: dict[str, Collector] = {}

    def register(self, collector: Collector) -> None:
        if not collector.provider:
            raise ValueError("collector must declare a provider")
        self._collectors[collector.provider] = collector

    def get(self, provider: str) -> Collector | None:
        return self._collectors.get(provider)

    def build_snapshot(self, providers: list[str]) -> dict[str, Any]:
        snapshot: dict[str, Any] = {"schema_version": 1}
        for provider in providers:
            collector = self._collectors.get(provider)
            if collector is None:
                raise ValueError(f"no collector registered for provider {provider!r}")
            snapshot[provider] = collector.collect()
        return snapshot


__all__ = ["Collector", "CollectorRegistry"]
