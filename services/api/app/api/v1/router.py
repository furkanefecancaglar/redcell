"""API v1 router: aggregates all resource routers."""
from fastapi import APIRouter

from app.api.v1 import agents, auth, edge, scans
from app.services.scan_service import find_core_modules

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth")
api_router.include_router(agents.router, prefix="/agents")
api_router.include_router(scans.router, prefix="/scans")
api_router.include_router(edge.router, prefix="")


@api_router.get("/health", tags=["health"])
async def health():
    return {
        "status": "healthy",
        "service": "redcell-api-v1",
        "version": "1.0.0",
        "core_modules": find_core_modules(),
    }
