"""Helpers aligned to edge.emit.v0.1 privacy-relevant fields."""

from __future__ import annotations

from typing import Any, Mapping


def local_only(event: Mapping[str, Any]) -> bool:
    return bool((event.get("context") or {}).get("local_only"))


def training_consent(event: Mapping[str, Any]) -> bool:
    """Passthrough only — false does not imply egress; true does not open upload."""
    return bool((event.get("context") or {}).get("training_consent"))


def encrypted_at_rest(event: Mapping[str, Any]) -> bool:
    return (event.get("clip") or {}).get("encrypted_at_rest") is True
