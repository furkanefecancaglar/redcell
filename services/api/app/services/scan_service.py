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


def _import_toolcheck():
    import redcell_toolcheck
    return redcell_toolcheck


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


async def run_toolcheck_scan(
    db: AsyncSession,
    org_id: str,
    agent_id: Optional[str],
    tool_call: dict,
    config: dict,
) -> models.Scan:
    """Gate a proposed agent tool/function call via the 0-API tool firewall."""
    name = str(tool_call.get("name", ""))
    arguments = tool_call.get("arguments", {})

    scan = models.Scan(
        org_id=org_id,
        agent_id=agent_id,
        type="toolcheck",
        status="running",
        input_snapshot={"tool_call": tool_call, "config": config},
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        toolcheck = _import_toolcheck()
        verdict = await asyncio.to_thread(toolcheck.check, name, arguments)
        action = verdict.get("action", "allow")
        # Normalize the tool-firewall RISK score (higher = worse) to a 0-100
        # SAFETY score (higher = safer) so it reads like the static resilience score.
        safety = max(0, 100 - int(verdict.get("score", 0)))
        scan.score = safety
        scan.grade = {"block": "Blocked", "flag": "Flagged", "allow": "Clean"}.get(action, action)
        scan.has_critical = action == "block"
        scan.result = verdict
        scan.status = "completed"
        severity = "high" if action == "block" else "medium" if action == "flag" else "low"
        evidence = (name + " " + str(arguments))[:2000]
        for i, reason in enumerate(verdict.get("reasons", [])):
            db.add(
                models.Finding(
                    scan_id=scan.id,
                    detector_id=f"toolcheck-{reason}-{i:02d}",
                    owasp=reason,
                    severity=severity,
                    title=reason,
                    description=f"tool-call risk: {verdict.get('risk', 'none')}",
                    evidence=evidence,
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
