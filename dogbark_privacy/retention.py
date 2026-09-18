"""Retention: default 7d pending Vivek freeze. owner_keep blocks purge."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

DEFAULT_RETENTION_DAYS = 7


def _parse_ts(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        ts = value
    else:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def compute_retention_until(
    captured_at: str | datetime,
    *,
    days: int = DEFAULT_RETENTION_DAYS,
) -> datetime:
    return _parse_ts(captured_at) + timedelta(days=days)


def should_purge(clip_row: Mapping[str, Any], *, now: datetime | None = None) -> bool:
    """Purge when past retention_until and owner_keep is false."""
    if clip_row.get("owner_keep") is True:
        return False
    until = clip_row.get("retention_until")
    if until is None:
        return False
    now = now or datetime.now(timezone.utc)
    return _parse_ts(until) <= now
