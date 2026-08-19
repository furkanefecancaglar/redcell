"""Auth endpoints: register/login -> JWT, plus API key management."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import models, schemas
from app.core.db import get_db
from app.core.deps import get_current_org_from_api_key, get_current_user
from app.core.security import (
    create_access_token,
    generate_api_key,
    hash_password,
    verify_password,
)

router = APIRouter(tags=["auth"])


@router.post("/register", response_model=schemas.Token, status_code=status.HTTP_201_CREATED)
async def register(payload: schemas.UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(models.User).where(models.User.email == payload.email))
    if existing.scalars().first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    user = models.User(
        email=payload.email,
        name=payload.name,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Every user starts with a personal org (slug = user id).
    org = models.Organization(name=f"{user.email}'s org", slug=user.id, plan="free")
    db.add(org)
    await db.commit()
    await db.refresh(org)
    db.add(models.OrganizationMember(org_id=org.id, user_id=user.id, role="owner"))
    await db.commit()

    return schemas.Token(access_token=create_access_token(user.id))


@router.post("/login", response_model=schemas.Token)
async def login(
    payload: schemas.UserCreate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(models.User).where(models.User.email == payload.email))
    user = result.scalars().first()
    if not user or not user.hashed_password or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")
    return schemas.Token(access_token=create_access_token(user.id))


@router.post("/api-keys", response_model=schemas.ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: schemas.ApiKeyCreate,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key
    plaintext, prefix, key_hash = generate_api_key()
    key = models.ApiKey(
        org_id=org.id,
        name=payload.name,
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=payload.scopes,
        expires_at=payload.expires_at,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return schemas.ApiKeyCreated(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        scopes=key.scopes,
        last_used_at=key.last_used_at,
        expires_at=key.expires_at,
        created_at=key.created_at,
        key=plaintext,
    )


@router.post("/me/api-keys", response_model=schemas.ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_own_api_key(
    payload: schemas.ApiKeyCreate,
    user: models.User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Bootstrap: create an org API key using user (JWT) auth.

    Uses the user's personal org. Once created, the returned plaintext key can be
    used for org-scoped endpoints (X-API-Key header), breaking the chicken-egg.
    """
    member_row = await db.execute(
        select(models.OrganizationMember).where(models.OrganizationMember.user_id == user.id)
    )
    member = member_row.scalars().first()
    if not member:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No organization for this user")
    plaintext, prefix, key_hash = generate_api_key()
    key = models.ApiKey(
        org_id=member.org_id,
        name=payload.name,
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=payload.scopes,
        expires_at=payload.expires_at,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return schemas.ApiKeyCreated(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        scopes=key.scopes,
        last_used_at=key.last_used_at,
        expires_at=key.expires_at,
        created_at=key.created_at,
        key=plaintext,
    )


@router.get("/api-keys", response_model=list[schemas.ApiKeyOut])
async def list_api_keys(
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key
    result = await db.execute(
        select(models.ApiKey).where(models.ApiKey.org_id == org.id)
    )
    return result.scalars().all()


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: str,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    """Revoke (permanently delete) an org API key. A key may revoke itself."""
    org, _ = org_key
    key = await db.get(models.ApiKey, key_id)
    if not key or key.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    await db.delete(key)
    await db.commit()
    return None


@router.get("/me", response_model=schemas.UserOut)
async def me(user: models.User = Depends(get_current_user)):
    return user
