"""Pydantic schemas (request/response) for the RedCell API."""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# ---- Auth ----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: Optional[str] = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    name: Optional[str] = None
    is_active: bool


# ---- Organizations ----
class OrgCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    slug: Optional[str] = None


class OrgOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    plan: str


# ---- API keys ----
class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scopes: list[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    key_prefix: str
    scopes: list[str]
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    """Returned only on creation: includes the plaintext key once."""

    key: str


# ---- Agents ----
def _check_prompt_len(v: Optional[str]) -> Optional[str]:
    """Shared cap so a stored agent prompt can't exceed the scan-time limit
    (a scan can resolve its prompt via agent_id, which would otherwise bypass
    ScanCreate's own length validator)."""
    from app.core.config import settings

    if v and len(v) > settings.MAX_AGENT_PROMPT_CHARS:
        raise ValueError(f"system_prompt exceeds {settings.MAX_AGENT_PROMPT_CHARS} chars")
    return v


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    system_prompt: str = Field(min_length=1)
    description: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("system_prompt")
    @classmethod
    def prompt_length(cls, v: str) -> str:
        return _check_prompt_len(v)


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    system_prompt: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @field_validator("system_prompt")
    @classmethod
    def prompt_length(cls, v: Optional[str]) -> Optional[str]:
        return _check_prompt_len(v)


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    name: str
    system_prompt: str
    description: Optional[str] = None
    agent_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


# ---- Scans ----
class ScanCreate(BaseModel):
    type: str = Field(default="static", pattern="^(static|live|continuous|toolcheck)$")
    agent_id: Optional[str] = None
    system_prompt: Optional[str] = None
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("system_prompt")
    @classmethod
    def prompt_length(cls, v: Optional[str]) -> Optional[str]:
        return _check_prompt_len(v)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    detector_id: str
    owasp: Optional[str] = None
    severity: str
    title: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    exploit_payload: Optional[str] = None


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    agent_id: Optional[str] = None
    type: str
    status: str
    score: Optional[int] = None
    grade: Optional[str] = None
    has_critical: Optional[bool] = None
    result: Optional[dict[str, Any]] = None
    cost_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime


class ScanOutWithFindings(ScanOut):
    findings: list[FindingOut] = Field(default_factory=list)
