"""In-memory credential tokens (id, role, issuer, expiry, scope)."""

import json
import time
import uuid

_tokens = {}


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


def verify(token):
    """Return the token payload dict if valid, else None."""
    try:
        payload = json.loads(token)
    except (TypeError, ValueError):
        return None
    stored = _tokens.get(payload.get("id"))
    if stored is None or stored != payload:
        return None
    if payload.get("expiry", 0) < time.time():
        return None
    return payload


def revoke(token):
    """Revoke a token (JSON string or id). Returns True if revoked."""
    try:
        token_id = json.loads(token).get("id") if isinstance(token, str) and token.strip().startswith("{") else token
    except ValueError:
        return False
    return _tokens.pop(token_id, None) is not None
