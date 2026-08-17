"""Edge proxy service: forward firewall/toolcheck/agentcheck to the Cloudflare Worker.

Keeps the 0-API surfaces on the edge (cheap/fast), while the backend exposes an
authenticated proxy so SDK clients get a single base URL.
"""
import httpx

from app.core.config import settings


async def proxy_edge(path: str, payload: dict | None = None, timeout: float = 15.0) -> tuple[int, dict]:
    """Forward a JSON request to the Cloudflare Worker.

    Returns (status_code, response_json). Never raises on upstream errors;
    returns 502 with a structured error instead.
    """
    url = f"{settings.CLOUDFLARE_WORKER_URL.rstrip('/')}/{path.lstrip('/')}"
    headers = {"User-Agent": "redcell-api-proxy"}
    if settings.CLOUDFLARE_WORKER_API_KEY:
        headers["Authorization"] = f"Bearer {settings.CLOUDFLARE_WORKER_API_KEY}"
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            r = await client.post(url, json=payload or {}, headers=headers)
            try:
                return r.status_code, r.json()
            except Exception:
                return r.status_code, {"detail": r.text[:2000] or "Empty upstream response"}
        except httpx.TimeoutException:
            return 504, {"detail": "Edge upstream timeout"}
        except httpx.RequestError as exc:
            return 502, {"detail": f"Edge upstream unreachable: {exc}"}
