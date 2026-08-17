"""Security primitives: password hashing, JWT, API keys."""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt

from app.core.config import settings

# scopes that do not require user auth, only a valid API key
PUBLIC_SCOPES = {"scan", "firewall", "toolcheck", "agentcheck"}


# ---- Passwords ----
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8")[:72], hashed.encode("utf-8"))
    except Exception:
        return False


# ---- JWT ----
def create_access_token(subject: str, expires_minutes: Optional[int] = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {"sub": subject, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


# ---- API keys ----
def generate_api_key() -> tuple[str, str, str]:
    """Return (plaintext, prefix, bcrypt_hash)."""
    raw = secrets.token_urlsafe(24)
    plaintext = f"{settings.API_KEY_PREFIX}{raw}"
    prefix = plaintext[: len(settings.API_KEY_PREFIX) + 8]
    return plaintext, prefix, hash_password(plaintext)


def hash_api_key(plaintext: str) -> str:
    return hash_password(plaintext)


def verify_api_key(plaintext: str, hashed: str) -> bool:
    return verify_password(plaintext, hashed)
