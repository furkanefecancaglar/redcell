"""Scan endpoints: create/trigger scans and fetch results + findings."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import models, schemas
from app.core.db import get_db
from app.core.deps import get_current_org_from_api_key, require_scope
from app.services.scan_service import run_static_scan, run_toolcheck_scan

router = APIRouter(tags=["scans"])


async def _get_org_scan(org_id: str, scan_id: str, db: AsyncSession) -> models.Scan:
    scan = await db.get(models.Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


@router.post("", response_model=schemas.ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: schemas.ScanCreate,
    org_key: tuple = Depends(require_scope("scans:write")),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key

    # toolcheck: gate a proposed tool/function call (0-API tool firewall).
    if payload.type == "toolcheck":
        if not payload.tool_call or not payload.tool_call.get("name"):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "tool_call with a 'name' is required for a toolcheck scan",
            )
        return await run_toolcheck_scan(
            db, org.id, payload.agent_id, payload.tool_call, payload.config
        )

    # live/continuous need the engine/infra and aren't wired yet — reject
    # explicitly rather than silently running static and mislabeling the result.
    if payload.type != "static":
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            f"Scan type '{payload.type}' is not implemented yet; use 'static' or 'toolcheck'",
        )

    # Resolve prompt source: explicit system_prompt, or an agent's stored prompt.
    prompt = payload.system_prompt
    agent_id = payload.agent_id
    if not prompt and agent_id:
        agent = await db.get(models.Agent, agent_id)
        if not agent or agent.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
        prompt = agent.system_prompt
    if not prompt:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "system_prompt or agent_id required")

    scan = await run_static_scan(db, org.id, agent_id, prompt, payload.config)
    return scan


@router.get("", response_model=list[schemas.ScanOut])
async def list_scans(
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    type: Optional[str] = Query(None, pattern="^(static|live|continuous|toolcheck)$"),
    status_: Optional[str] = Query(None, alias="status"),
):
    org, _ = org_key
    stmt = select(models.Scan).where(models.Scan.org_id == org.id)
    if type:
        stmt = stmt.where(models.Scan.type == type)
    if status_:
        stmt = stmt.where(models.Scan.status == status_)
    stmt = stmt.order_by(models.Scan.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{scan_id}.sarif")
async def get_scan_sarif(
    scan_id: str,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key
    scan = await db.execute(
        select(models.Scan)
        .where(models.Scan.id == scan_id, models.Scan.org_id == org.id)
        .options(selectinload(models.Scan.findings))
    )
    scan = scan.scalars().first()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    from fastapi.responses import JSONResponse

    rules = []
    results = []
    for f in scan.findings:
        rules.append(
            {
                "id": f.detector_id,
                "name": f.title or f.detector_id,
                "shortDescription": {"text": f.description or f.title or f.detector_id},
            }
        )
        results.append(
            {
                "ruleId": f.detector_id,
                "level": "error",
                "message": {"text": f.title or f.detector_id},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "system_prompt.txt"},
                            "region": {"snippet": {"text": f.evidence or ""}},
                        }
                    }
                ],
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "RedCell", "rules": rules}}, "results": results}],
    }
    return JSONResponse(sarif, media_type="application/sarif+json")


@router.get("/{scan_id}", response_model=schemas.ScanOutWithFindings)
async def get_scan(
    scan_id: str,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key
    scan = await db.execute(
        select(models.Scan)
        .where(models.Scan.id == scan_id, models.Scan.org_id == org.id)
        .options(selectinload(models.Scan.findings))
    )
    scan = scan.scalars().first()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan
