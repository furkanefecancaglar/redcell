"""Scan endpoints: create/trigger scans and fetch results + findings."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import models, schemas
from app.core.db import get_db
from app.core.deps import get_current_org_from_api_key
from app.services.scan_service import run_static_scan

router = APIRouter(tags=["scans"])


async def _get_org_scan(org_id: str, scan_id: str, db: AsyncSession) -> models.Scan:
    scan = await db.get(models.Scan, scan_id)
    if not scan or scan.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


@router.post("", response_model=schemas.ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: schemas.ScanCreate,
    org_key: tuple = Depends(get_current_org_from_api_key),
    db: AsyncSession = Depends(get_db),
):
    org, _ = org_key

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
):
    org, _ = org_key
    result = await db.execute(
        select(models.Scan)
        .where(models.Scan.org_id == org.id)
        .order_by(models.Scan.created_at.desc())
        .limit(100)
    )
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
