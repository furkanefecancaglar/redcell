# RedCell API service.
# Build context MUST be the repo root so the shared 0-API core modules
# (redcell_static.py etc., imported by app/services/scan_service.py from the
# repo root) are available inside the image:
#
#   docker build -f services/api/Dockerfile -t redcell-api .
#   docker run -p 8000:8000 -e SECRET_KEY=... -e DATABASE_URL=... redcell-api
#
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for layer caching.
COPY services/api/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Shared core modules live at repo root; scan_service resolves them relative to
# /app (repo root) via a four-level-up path, so the app must sit at
# /app/services/api/app and the core .py files directly under /app.
COPY redcell_static.py redcell_firewall.py redcell_toolcheck.py redcell_engine.py nim_client.py ./
COPY services/api/app ./services/api/app
# Alembic migrations (run `alembic upgrade head` before boot on Postgres).
COPY services/api/alembic.ini ./services/api/alembic.ini
COPY services/api/migrations ./services/api/migrations

# Non-root runtime user.
RUN useradd --create-home --uid 10001 redcell && chown -R redcell:redcell /app
USER redcell

WORKDIR /app/services/api

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health').status==200 else 1)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
