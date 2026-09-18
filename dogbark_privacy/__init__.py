"""Dog Bark privacy lane — encrypt, gate, retention, audit."""

__version__ = "0.1.0"

from .audit import AuditRecord, append_audit
from .crypto import MissingKeyError, decrypt, encrypt, require_key
from .gate import GateDecision, allow_egress
from .retention import compute_retention_until, should_purge

__all__ = [
    "AuditRecord",
    "GateDecision",
    "MissingKeyError",
    "allow_egress",
    "append_audit",
    "compute_retention_until",
    "decrypt",
    "encrypt",
    "require_key",
    "should_purge",
]
