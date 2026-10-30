"""Bearer-token authentication and role-based access control.

Tokens are random 256-bit values shown once at creation. Only their SHA-256
digest is stored (a fast hash is appropriate because the tokens are
high-entropy, not human passwords). Comparison is constant-time.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}
NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


class AuthConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Principal:
    name: str
    role: str

    def allows(self, minimum_role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[minimum_role]


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _read(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        entries = json.load(fh)
    if not isinstance(entries, list):
        raise AuthConfigError("token file must contain a JSON list")
    for e in entries:
        if (not isinstance(e, dict) or e.get("role") not in ROLE_RANK
                or not NAME_RE.match(str(e.get("name", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(e.get("sha256", "")))):
            raise AuthConfigError("malformed token entry")
    return entries


def create_token(path: str, name: str, role: str) -> str:
    """Create a token, store its hash, and return the plaintext (shown once)."""
    if role not in ROLE_RANK:
        raise AuthConfigError(f"role must be one of {sorted(ROLE_RANK)}")
    if not NAME_RE.match(name):
        raise AuthConfigError("invalid name")
    entries = _read(path)
    if any(e["name"] == name for e in entries):
        raise AuthConfigError(f"token for '{name}' already exists")
    token = secrets.token_urlsafe(32)
    entries.append({"name": name, "role": role, "sha256": hash_token(token)})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)
    return token


class TokenStore:
    def __init__(self, path: str):
        self._entries = _read(path)

    def authenticate(self, token: str) -> Principal | None:
        digest = hash_token(token)
        match = None
        for e in self._entries:  # no early exit: constant work per attempt
            if hmac.compare_digest(e["sha256"], digest):
                match = Principal(e["name"], e["role"])
        return match


def parse_bearer(header: str | None) -> str | None:
    if not header:
        return None
    parts = header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token if 0 < len(token) <= 256 else None
