"""CLI: check-event against the egress gate (no network)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditRecord, append_audit
from .gate import allow_egress


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dogbark-privacy")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check-event", help="Gate an edge.emit.v0.1 JSON file")
    check.add_argument("path", type=Path)
    check.add_argument("--audit", type=Path, default=None, help="Optional JSONL audit path")
    check.add_argument(
        "--allow-upload",
        action="store_true",
        help="Set upload_disabled=false (still subject to local_only/keys/encrypt)",
    )
    args = parser.parse_args(argv)

    if args.cmd == "check-event":
        event = json.loads(args.path.read_text(encoding="utf-8"))
        decision = allow_egress(event, upload_disabled=not args.allow_upload)
        out = {
            "event_id": event.get("event_id"),
            "allow": decision.allow,
            "reason": decision.reason,
        }
        print(json.dumps(out))
        if args.audit is not None:
            action = "allow" if decision.allow else "deny"
            append_audit(
                args.audit,
                AuditRecord.make(str(event.get("event_id") or "unknown"), action, decision.reason),
            )
        return 0 if decision.allow else 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
