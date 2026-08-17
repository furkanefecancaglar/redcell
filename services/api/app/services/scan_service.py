"""Scan orchestration service.

Wraps the existing 0-API static scanner (redcell_static) and the live engine.
Lives in services/api/app; imports the shared Python core from the repo root.
"""
import asyncio
import os
import sys
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app import models
from app.core.config import settings

# Make repo-root core modules importable (redcell_static, redcell_engine, ...).
_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Normalize redcell_static severity tokens -> OWASP-ish label + DB enum.
_SEV_NORM = {"crit": "critical", "high": "high", "med": "medium", "low": "low"}


def _import_static():
    import redcell_static
    return redcell_static


async def run_static_scan(
    db: AsyncSession,
    org_id: str,
    agent_id: Optional[str],
    prompt: str,
    config: dict,
) -> models.Scan:
    """Run the 0-API static scanner and persist the result."""
    scan = models.Scan(
        org_id=org_id,
        agent_id=agent_id,
        type="static",
        status="running",
        input_snapshot={"system_prompt": prompt, "config": config},
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        static = _import_static()
        report = await asyncio.to_thread(static.analyze, prompt)
        scan.score = int(report.score)
        scan.grade = report.grade
        scan.has_critical = report.has_critical
        scan.result = {
            "score": report.score,
            "grade": report.grade,
            "passed": report.passed,
            "finding_count": len(report.findings),
        }
        scan.status = "completed"
        for i, f in enumerate(report.findings):
            db.add(
                models.Finding(
                    scan_id=scan.id,
                    detector_id=f"{f.id}-{i:02d}",
                    owasp=f.id,
                    severity=_SEV_NORM.get(f.sev, f.sev),
                    title=f.title,
                    description=f.cat,
                    evidence=(f.evidence or "")[:2000],
                )
            )
    except Exception as exc:  # pragma: no cover - defensive
        scan.status = "failed"
        scan.error = str(exc)[:2000]
    finally:
        scan.finished_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(scan)
    return scan


def find_core_modules() -> list[str]:
    """List the shared core modules present at repo root (used by /health)."""
    names = ["redcell_static", "redcell_firewall", "redcell_toolcheck", "redcell_engine"]
    return [n for n in names if os.path.exists(os.path.join(_REPO_ROOT, f"{n}.py"))]
