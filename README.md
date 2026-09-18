# dogbark-privacy

Privacy lane for **Sheru / Dog Bark** (UC-01 → UC-03, local-first).

## Owns
- Encrypt-at-rest helpers (AES-256-GCM)
- `local_only` egress gate (fail closed)
- `retention_until` / `owner_keep` purge rules (default **7d**, pending Vivek)
- `egress_audit` append-only stub

## Hard rules
- **Upload blocked** in MVP (`upload_disabled=true` by default)
- No Funnel / public tunnels
- **Blink out of path** — Amazon Blink ToS bars reverse engineering; no documented local RTSP/mic API; cloud-mediated clip path breaks local-first fail-closed
- No training corpus writes (Dataset/Privacy dual-gate only; this lib does not open ingest)
- No translation / medical claims (out of scope)

## Key material
Set `DOGBARK_MEDIA_KEY` to a base64-encoded 32-byte key. Missing key → **fail closed**.

Never commit keys. Device provisioning is a Vivek call.

## Contracts consumed
Aligns with `edge.emit.v0.1` context:
- `context.local_only`
- `context.training_consent` (passthrough; does not authorize egress)
- `clip.encrypted_at_rest` must be `true` before any future upload path

## CLI
```bash
pip install -e ".[dev]"
python -m dogbark_privacy check-event path/to/edge_emit.json
pytest
```

## Status
Scaffold for Vivek merge. Upload remains stubbed/blocked until keys + retention freeze.
