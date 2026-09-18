"""Egress gate. Upload blocked by default in MVP."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class GateDecision:
    allow: bool
    reason: str


def allow_egress(
    event: Mapping[str, Any],
    *,
    upload_disabled: bool = True,
    keys_present: bool | None = None,
) -> GateDecision:
    """Decide whether an event may leave the device.

    Deny order:
    1. upload_disabled (MVP default True)
    2. context.local_only
    3. missing keys
    4. clip.encrypted_at_rest is not True
    """
    if upload_disabled:
        return GateDecision(False, "upload_disabled")

    ctx = event.get("context") or {}
    if ctx.get("local_only") is True:
        return GateDecision(False, "local_only")

    if keys_present is False:
        return GateDecision(False, "missing_keys")
    if keys_present is None:
        try:
            from .crypto import require_key

            require_key()
        except Exception:
            return GateDecision(False, "missing_keys")

    clip = event.get("clip") or {}
    if clip.get("encrypted_at_rest") is not True:
        return GateDecision(False, "not_encrypted_at_rest")

    return GateDecision(True, "ok")
