"""AES-256-GCM helpers. Fail closed if key missing — no plaintext media path."""

from __future__ import annotations

import base64
import os
import secrets
from typing import Tuple

KEY_ENV = "DOGBARK_MEDIA_KEY"


class MissingKeyError(RuntimeError):
    """Raised when DOGBARK_MEDIA_KEY is absent or invalid. Fail closed."""


def require_key() -> bytes:
    raw = os.environ.get(KEY_ENV, "").strip()
    if not raw:
        raise MissingKeyError(f"{KEY_ENV} missing — refuse encrypt/decrypt")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise MissingKeyError(f"{KEY_ENV} not valid base64") from exc
    if len(key) != 32:
        raise MissingKeyError(f"{KEY_ENV} must decode to 32 bytes, got {len(key)}")
    return key


def encrypt(plaintext: bytes, *, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    """Return (nonce, ciphertext, tag). Fail closed without key."""
    key = require_key()
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("install cryptography for AES-256-GCM") from exc
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct[:-16], ct[-16:]


def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, *, aad: bytes = b"") -> bytes:
    key = require_key()
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("install cryptography for AES-256-GCM") from exc
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)
