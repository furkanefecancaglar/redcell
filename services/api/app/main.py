"""FastAPI application entrypoint for the RedCell API service.

Run from services/api/:  uvicorn app.main:app --reload
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.db import Base, engine
from app.core.logging import setup_logging

_DASHBOARD = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging("DEBUG" if settings.DEBUG else "INFO")
    if settings.DATABASE_URL.startswith("sqlite"):
        # dev/test convenience: create tables if missing. Production uses Alembic.
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="RedCell AI Security Platform API — scan, gate, red-team, and firewall LLM agents.",
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", include_in_schema=False)
async def dashboard():
    """Serve the single-file dashboard SPA (talks to the same-origin /api/v1)."""
    return FileResponse(_DASHBOARD, media_type="text/html")
