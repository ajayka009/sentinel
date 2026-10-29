"""In-memory credential tokens (id, role, issuer, expiry, scope)."""

import json
import time
import uuid

_tokens = {}
_revoked = {}


def issue(role, issuer, scope, ttl_seconds=3600):
    """Issue a credential token, returned as a JSON string."""
    payload = {
        "id": uuid.uuid4().hex,
        "role": role,
        "issuer": issuer,
        "expiry": int(time.time()) + ttl_seconds,
        "scope": scope,
    }
    _tokens[payload["id"]] = payload
    return json.dumps(payload)


def _coerce(token):
    """Return the claimed payload dict, or None if unparseable."""
    if isinstance(token, dict):
        return token
    if isinstance(token, str):
        try:
            payload = json.loads(token)
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None
    return None


def verify_status(token):
    """Return (payload, status) with status valid|unknown|revoked|expired.

    The payload is the stored credential for valid tokens, the claimed
    payload for revoked/expired ones (kept for audit), else None.
    """
    now = time.time()
    claimed = _coerce(token)
    token_id = claimed.get("id") if claimed else None
    if token_id in _revoked:
        return _revoked[token_id], "revoked"
    stored = _tokens.get(token_id) if token_id is not None else None
    if stored is None or stored != claimed:
        return None, "unknown"
    if stored.get("expiry", 0) < now:
        return stored, "expired"
    return stored, "valid"


def verify(token):
    """Return the token payload dict if valid, else None."""
    payload, status = verify_status(token)
    return payload if status == "valid" else None


def revoke(token):
    """Revoke a token (JSON string, dict, or id). Returns True if revoked."""
    claimed = _coerce(token)
    if claimed is not None:
        token_id = claimed.get("id")
    elif isinstance(token, str):
        token_id = token
    else:
        return False
    payload = _tokens.pop(token_id, None)
    if payload is None:
        return False
    _revoked[token_id] = payload
    return True
