"""API v1 router: aggregates all resource routers."""
from fastapi import APIRouter, Depends

from app.api.v1 import agents, auth, edge, scans
from app.core.deps import rate_limit
from app.services.scan_service import find_core_modules

api_router = APIRouter()

# Rate limiting applies to every resource router (per API key, falling back to
# client IP for unauthenticated auth calls). /health is intentionally left
# unlimited so load balancers / uptime probes never get 429'd.
_rl = [Depends(rate_limit)]

api_router.include_router(auth.router, prefix="/auth", dependencies=_rl)
api_router.include_router(agents.router, prefix="/agents", dependencies=_rl)
api_router.include_router(scans.router, prefix="/scans", dependencies=_rl)
api_router.include_router(edge.router, prefix="", dependencies=_rl)


@api_router.get("/health", tags=["health"])
async def health():
    return {
        "status": "healthy",
        "service": "redcell-api-v1",
        "version": "1.0.0",
        "core_modules": find_core_modules(),
    }
