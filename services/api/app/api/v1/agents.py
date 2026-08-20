"""Agent CRUD endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import models, schemas
from app.core.db import get_db
from app.core.deps import get_current_org_from_api_key

router = APIRouter(tags=["agents"])


async def _get_org_agent(org_id: str, agent_id: str, db: AsyncSession) -> models.Agent:
    agent = await db.get(models.Agent, agent_id)
    if not agent or agent.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    return agent


@router.post("", response_model=schemas.AgentOut, status_code=status.HTTP_201_CREATED)
async def create_agent(
    payload: schemas.AgentCreate,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key
    agent = models.Agent(
        org_id=org.id,
        name=payload.name,
        system_prompt=payload.system_prompt,
        description=payload.description,
        agent_metadata=payload.metadata,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return agent


@router.get("", response_model=list[schemas.AgentOut])
async def list_agents(
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    org, _ = org_key
    result = await db.execute(
        select(models.Agent)
        .where(models.Agent.org_id == org.id)
        .order_by(models.Agent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return result.scalars().all()


@router.get("/{agent_id}", response_model=schemas.AgentOut)
async def get_agent(
    agent_id: str,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key
    return await _get_org_agent(org.id, agent_id, db)


@router.patch("/{agent_id}", response_model=schemas.AgentOut)
async def update_agent(
    agent_id: str,
    payload: schemas.AgentUpdate,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key
    agent = await _get_org_agent(org.id, agent_id, db)
    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(agent, field, value)
    await db.commit()
    await db.refresh(agent)
    return agent


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_id: str,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key
    agent = await _get_org_agent(org.id, agent_id, db)
    await db.delete(agent)
    await db.commit()
    return None
