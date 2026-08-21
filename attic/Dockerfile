# REDCELL — full-stack AI-agent security server
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py console.html ./
# Container must bind 0.0.0.0; supply keys via REDCELL_NIM_KEYS at runtime.
# /scan-config and /firewall are 0-API and work with no keys; /scan needs keys.
# NOTE: put auth/a reverse proxy in front — /scan holds provider keys.
ENV REDCELL_HOST=0.0.0.0 REDCELL_PORT=8770
EXPOSE 8770
CMD ["python", "server.py"]
