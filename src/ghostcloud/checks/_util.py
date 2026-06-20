"""Shared helpers for evaluating provider configuration blocks."""

from __future__ import annotations

from typing import Any

# CIDR blocks that expose a resource to the entire internet.
OPEN_IPV4 = "0.0.0.0/0"
OPEN_IPV6 = "::/0"


def is_open_cidr(cidr: str) -> bool:
    return cidr in (OPEN_IPV4, OPEN_IPV6)


def as_list(value: Any) -> list[Any]:
    """Coerce a scalar-or-list field into a list, treating None as empty.

    Cloud APIs are inconsistent about returning a single value versus a list
    (a single IAM action versus an array, for example). This normalizes both.
    """

    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def port_in_range(port: int, from_port: Any, to_port: Any) -> bool:
    """True if ``port`` falls within the inclusive [from_port, to_port] range.

    A missing or null bound is treated as "all ports" on that side, which
    matches how security groups represent an unrestricted range.
    """

    low = 0 if from_port is None else int(from_port)
    high = 65535 if to_port is None else int(to_port)
    if low > high:
        low, high = high, low
    return low <= port <= high
