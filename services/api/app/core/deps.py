"""FastAPI dependencies: current user via JWT, current org via API key, rate limiting."""
import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_db
from app.core.security import decode_access_token
from app import models


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize a stored datetime to tz-aware UTC. SQLite (dev) returns naive
    datetimes even for timezone=True columns, so comparing them against an aware
    now() would raise TypeError — treat naive values as UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class AuthError(HTTPException):
    def __init__(self, detail: str, headers: Optional[dict] = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers=headers or {"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    authorization: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> models.User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError("Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    user_id = decode_access_token(token)
    if not user_id:
        raise AuthError("Invalid or expired token")
    user = await db.get(models.User, user_id)
    if not user or not user.is_active:
        raise AuthError("Inactive or unknown user")
    return user


async def get_current_org_from_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> tuple[models.Organization, models.ApiKey]:
    if not x_api_key:
        raise AuthError("Missing X-API-Key header", headers={"WWW-Authenticate": "ApiKey"})
    if not x_api_key.startswith(settings.API_KEY_PREFIX):
        raise AuthError("Invalid API key format", headers={"WWW-Authenticate": "ApiKey"})

    prefix = x_api_key[: len(settings.API_KEY_PREFIX) + 8]
    result = await db.execute(
        select(models.ApiKey).where(models.ApiKey.key_prefix == prefix)
    )
    keys = result.scalars().all()
    # bcrypt compare across matching prefix (rarely >1)
    from app.core.security import verify_api_key

    matched: Optional[models.ApiKey] = None
    for k in keys:
        if verify_api_key(x_api_key, k.key_hash):
            matched = k
            break
    if not matched:
        raise AuthError("Invalid API key", headers={"WWW-Authenticate": "ApiKey"})
    now = datetime.now(timezone.utc)
    if matched.expires_at and _as_utc(matched.expires_at) < now:
        raise AuthError("Expired API key", headers={"WWW-Authenticate": "ApiKey"})

    org = await db.get(models.Organization, matched.org_id)
    if not org:
        raise AuthError("Unknown organization", headers={"WWW-Authenticate": "ApiKey"})

    # Stamp last-used, throttled to at most once/60s to avoid a DB write per request.
    last = _as_utc(matched.last_used_at)
    if last is None or (now - last).total_seconds() > 60:
        matched.last_used_at = now
        await db.commit()
    return org, matched


def require_scope(scope: str):
    """Dependency factory enforcing an API-key scope.

    Backward-compatible model: a key with an EMPTY scopes list is a full-access
    (root) key and passes every check — so existing keys keep working. A key with
    a non-empty scopes list must contain the required scope or the "*" wildcard.
    """

    async def _dep(
        org_key: tuple = Depends(get_current_org_from_api_key),
    ) -> tuple:
        _, key = org_key
        scopes = key.scopes or []
        if scopes and scope not in scopes and "*" not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key missing required scope: {scope}",
            )
        return org_key

    return _dep


# ---- Rate limiting (in-process fixed window; Redis-backed in production) ----
_windows: dict[str, tuple[int, float]] = {}  # key -> (count, window_start)
_window_lock = asyncio.Lock()


async def rate_limit(request: Request) -> None:
    if not settings.RATE_LIMIT_ENABLED:
        return
    ident = request.headers.get("x-api-key") or request.client.host or "anon"
    key = hashlib.sha256(ident.encode()).hexdigest()[:32]
    now = time.monotonic()
    async with _window_lock:
        count, start = _windows.get(key, (0, now))
        if now - start >= settings.RATE_LIMIT_WINDOW_SECONDS:
            count, start = 0, now
        count += 1
        _windows[key] = (count, start)
        if count > settings.RATE_LIMIT_REQUESTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(int(start + settings.RATE_LIMIT_WINDOW_SECONDS - now) + 1)},
            )
