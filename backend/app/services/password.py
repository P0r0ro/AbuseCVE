"""Password hashing helpers — bcrypt via passlib.

bcrypt has a hard 72-byte input limit. ``passlib`` used to silently
truncate; the bcrypt 4.x backend refuses to. We truncate explicitly so
both hashing and verification use the same effective input — anything
beyond byte 72 has never been part of a bcrypt comparison anyway.
"""

from __future__ import annotations

from passlib.context import CryptContext

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

_BCRYPT_MAX_BYTES = 72


def _truncate_for_bcrypt(plain: str) -> str:
    """Trim to <=72 bytes UTF-8 without splitting a multibyte char."""
    encoded = plain.encode("utf-8")
    if len(encoded) <= _BCRYPT_MAX_BYTES:
        return plain
    trimmed = encoded[:_BCRYPT_MAX_BYTES]
    while trimmed:
        try:
            return trimmed.decode("utf-8")
        except UnicodeDecodeError:
            trimmed = trimmed[:-1]
    return ""


def hash_password(plain: str) -> str:
    if not plain:
        raise ValueError("password must not be empty")
    return _pwd_ctx.hash(_truncate_for_bcrypt(plain))


def verify_password(plain: str, hashed: str) -> bool:
    if not plain or not hashed:
        return False
    try:
        return _pwd_ctx.verify(_truncate_for_bcrypt(plain), hashed)
    except Exception:
        return False
