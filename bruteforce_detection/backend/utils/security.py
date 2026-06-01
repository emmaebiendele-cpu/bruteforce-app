"""
Auth utilities: password hashing, JWT creation/verification, token JTI
"""
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Passwords ─────────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> tuple[str, str]:
    """
    Returns (token_string, jti).
    jti is stored in ActiveSession for fast revocation.
    FIX: sub is always cast to str before encoding. JWT spec requires sub
    to be a string, and this avoids the int/str mismatch when decoding.
    """
    jti = str(uuid.uuid4())
    to_encode = data.copy()

    # Always store sub as string — JWT spec requirement
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])

    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "jti": jti})
    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, jti


def decode_access_token(token: str) -> Optional[dict]:
    """Returns payload dict or None on failure."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None