"""Edge proxy endpoints: firewall/toolcheck/agentcheck forwarded to Worker.

These keep the 0-API surfaces on Cloudflare (cheap, viral) while the backend
exposes an authenticated proxy so SDK/API clients get a single base URL.
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from app.core.deps import get_current_org_from_api_key
from app.services.edge_proxy import proxy_edge

router = APIRouter(tags=["edge-proxy"])


@router.post("/firewall")
async def firewall(
    request: Request,
    _: tuple = Depends(get_current_org_from_api_key),
):
    body = await request.json()
    status_code, data = await proxy_edge("firewall", body)
    return JSONResponse(data, status_code=status_code)


@router.post("/toolcheck")
async def toolcheck(
    request: Request,
    _: tuple = Depends(get_current_org_from_api_key),
):
    body = await request.json()
    status_code, data = await proxy_edge("toolcheck", body)
    return JSONResponse(data, status_code=status_code)


@router.post("/agentcheck")
async def agentcheck(
    request: Request,
    _: tuple = Depends(get_current_org_from_api_key),
):
    body = await request.json()
    status_code, data = await proxy_edge("agentcheck", body)
    return JSONResponse(data, status_code=status_code)
