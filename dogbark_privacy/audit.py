"""Append-only egress audit stub (JSONL)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class AuditRecord:
    event_id: str
    action: Literal["allow", "deny"]
    reason: str
    ts: str

    @classmethod
    def make(cls, event_id: str, action: Literal["allow", "deny"], reason: str) -> "AuditRecord":
        return cls(
            event_id=event_id,
            action=action,
            reason=reason,
            ts=datetime.now(timezone.utc).isoformat(),
        )


def append_audit(path: str | Path, record: AuditRecord) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(record), separators=(",", ":")) + "\n")
