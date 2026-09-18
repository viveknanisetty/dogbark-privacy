import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from dogbark_privacy.audit import AuditRecord, append_audit
from dogbark_privacy.crypto import MissingKeyError, decrypt, encrypt, require_key
from dogbark_privacy.gate import allow_egress
from dogbark_privacy.retention import compute_retention_until, should_purge


def _event(**overrides):
    base = {
        "event_id": "01TESTEVENTID000000000000",
        "clip": {"encrypted_at_rest": True, "local_uri": "file:///tmp/x.enc"},
        "context": {"local_only": False, "training_consent": False},
    }
    if "context" in overrides:
        ctx = {"local_only": False, "training_consent": False}
        ctx.update(overrides.pop("context"))
        base["context"] = ctx
    if "clip" in overrides:
        clip = {"encrypted_at_rest": True, "local_uri": "file:///tmp/x.enc"}
        clip.update(overrides.pop("clip"))
        base["clip"] = clip
    base.update(overrides)
    return base


def test_fail_closed_without_key(monkeypatch):
    monkeypatch.delenv("DOGBARK_MEDIA_KEY", raising=False)
    with pytest.raises(MissingKeyError):
        require_key()


def test_encrypt_roundtrip(monkeypatch):
    key = base64.b64encode(b"0" * 32).decode()
    monkeypatch.setenv("DOGBARK_MEDIA_KEY", key)
    nonce, ct, tag = encrypt(b"bark-clip", aad=b"event")
    assert decrypt(nonce, ct, tag, aad=b"event") == b"bark-clip"


def test_deny_local_only(monkeypatch):
    monkeypatch.setenv("DOGBARK_MEDIA_KEY", base64.b64encode(b"1" * 32).decode())
    d = allow_egress(_event(context={"local_only": True}), upload_disabled=False)
    assert d.allow is False and d.reason == "local_only"


def test_upload_disabled_blocks_even_when_otherwise_ok(monkeypatch):
    monkeypatch.setenv("DOGBARK_MEDIA_KEY", base64.b64encode(b"1" * 32).decode())
    d = allow_egress(_event(), upload_disabled=True)
    assert d.allow is False and d.reason == "upload_disabled"


def test_training_consent_false_does_not_affect_egress(monkeypatch):
    monkeypatch.setenv("DOGBARK_MEDIA_KEY", base64.b64encode(b"1" * 32).decode())
    d = allow_egress(
        _event(context={"local_only": False, "training_consent": False}),
        upload_disabled=False,
    )
    assert d.allow is True and d.reason == "ok"


def test_retention_purge():
    now = datetime(2026, 9, 18, tzinfo=timezone.utc)
    until = compute_retention_until(now - timedelta(days=8), days=7)
    assert should_purge({"retention_until": until.isoformat(), "owner_keep": False}, now=now)
    assert not should_purge({"retention_until": until.isoformat(), "owner_keep": True}, now=now)


def test_audit_jsonl(tmp_path: Path):
    path = tmp_path / "egress_audit.jsonl"
    append_audit(path, AuditRecord.make("e1", "deny", "local_only"))
    line = json.loads(path.read_text().strip())
    assert line["action"] == "deny" and line["reason"] == "local_only"
