"""Authentication and role-based access control for the API.

Roles are ordered: ``viewer`` < ``operator`` < ``admin``.

* ``viewer``   read every dashboard endpoint.
* ``operator`` additionally start/stop simulations, approve, reject and roll
  back mitigation actions.
* ``admin``    additionally read the audit trail and manage users.

Passwords are stored as PBKDF2-HMAC-SHA256 hashes (600,000 iterations, per
OWASP 2023 guidance) with a per-user random salt. Tokens are HS256 JWTs with
an expiry; the signing key comes from ``NETSHIELD_JWT_SECRET`` or is generated
per process (tokens then do not survive a restart, which is the safe default).

Users are loaded from ``config/users.yaml`` (hashes only) or, for local
development, from ``NETSHIELD_DEV_USERS="alice:operator:pw,bob:viewer:pw"``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import jwt

ROLES: tuple[str, ...] = ("viewer", "operator", "admin")
_ITERATIONS = 600_000
ALGORITHM = "HS256"


class AuthError(PermissionError):
    """Raised for bad credentials, bad tokens or insufficient role."""


def role_rank(role: str) -> int:
    if role not in ROLES:
        raise AuthError(f"Unknown role {role!r}")
    return ROLES.index(role)


def hash_password(password: str, salt: bytes | None = None,
                  iterations: int = _ITERATIONS) -> str:
    """Return ``pbkdf2_sha256$<iterations>$<salt>$<hash>``."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    return f"pbkdf2_sha256${iterations}${enc(salt)}${enc(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of *password* against a stored hash."""
    try:
        scheme, iters, salt_b64, hash_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    salt = base64.urlsafe_b64decode(pad(salt_b64))
    expected = base64.urlsafe_b64decode(pad(hash_b64))
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
    return hmac.compare_digest(actual, expected)


@dataclass(slots=True)
class User:
    username: str
    role: str
    password_hash: str
    disabled: bool = False


class UserStore:
    """In-memory user directory loaded from YAML and/or the environment."""

    def __init__(self, users: Mapping[str, User] | None = None) -> None:
        self.users: dict[str, User] = dict(users or {})

    @classmethod
    def from_sources(cls, path: str | Path | None = None,
                     env: Mapping[str, str] | None = None,
                     iterations: int = _ITERATIONS) -> "UserStore":
        env = os.environ if env is None else env
        store = cls()
        if path and Path(path).exists():
            import yaml  # noqa: PLC0415

            doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            for name, entry in (doc.get("users") or {}).items():
                store.users[name] = User(name, str(entry["role"]), str(entry["password_hash"]),
                                         bool(entry.get("disabled", False)))
        for spec in filter(None, (env.get("NETSHIELD_DEV_USERS", "") or "").split(",")):
            name, role, password = spec.split(":", 2)
            store.users[name] = User(name, role, hash_password(password, iterations=iterations))
        for user in store.users.values():
            role_rank(user.role)
        return store

    def authenticate(self, username: str, password: str) -> User:
        user = self.users.get(username)
        # Always run one hash so timing does not reveal whether a user exists.
        stored = user.password_hash if user else hash_password("x", b"0" * 16, 1000)
        ok = verify_password(password, stored)
        if not user or not ok or user.disabled:
            raise AuthError("Invalid username or password")
        return user


class TokenService:
    """Issue and verify signed access tokens."""

    def __init__(self, secret: str | None = None, ttl_s: int = 3600,
                 issuer: str = "netshield-gnn") -> None:
        self.secret = secret or os.environ.get("NETSHIELD_JWT_SECRET") or secrets.token_urlsafe(48)
        self.ttl_s = int(ttl_s)
        self.issuer = issuer

    def issue(self, user: User) -> dict[str, Any]:
        now = int(time.time())
        claims = {"sub": user.username, "role": user.role, "iat": now,
                  "exp": now + self.ttl_s, "iss": self.issuer,
                  "jti": secrets.token_hex(8)}
        token = jwt.encode(claims, self.secret, algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer", "expires_in": self.ttl_s,
                "role": user.role}

    def verify(self, token: str) -> dict[str, Any]:
        try:
            return jwt.decode(token, self.secret, algorithms=[ALGORITHM], issuer=self.issuer,
                              options={"require": ["exp", "sub", "role"]})
        except jwt.PyJWTError as exc:
            raise AuthError(f"Invalid token: {exc}") from exc


#: Minimum role per (method, path-prefix). First match wins; unlisted
#: GET routes need ``viewer``; unlisted mutating routes need ``operator``.
ACCESS_RULES: tuple[tuple[str, str, str], ...] = (
    ("GET", "/api/audit", "admin"),
    ("POST", "/api/auth/token", ""),
    ("GET", "/api/health", ""),
    ("GET", "/metrics", ""),
    ("POST", "/api/approvals", "operator"),
    ("POST", "/api/mitigation", "operator"),
    ("POST", "/api/simulation", "operator"),
    ("POST", "/api/experiment", "operator"),
    ("POST", "/api/attack/preview", "viewer"),
)


def required_role(method: str, path: str) -> str:
    """Return the minimum role for a request ('' = public)."""
    if not path.startswith("/api") and path != "/metrics" and not path.startswith("/ws"):
        return ""            # static dashboard, docs
    for m, prefix, role in ACCESS_RULES:
        if method == m and path.startswith(prefix):
            return role
    return "viewer" if method in ("GET", "HEAD", "OPTIONS") else "operator"
