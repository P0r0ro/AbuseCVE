"""Password hashing helpers — bcrypt via passlib.

Wrapped here so callers don't need to import passlib directly and so we
can swap the algorithm later without touching every route.
"""

from __future__ import annotations

from passlib.context import CryptContext

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    if not plain:
        raise ValueError("password must not be empty")
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    if not plain or not hashed:
        return False
    try:
        return _pwd_ctx.verify(plain, hashed)
    except Exception:
        return False
