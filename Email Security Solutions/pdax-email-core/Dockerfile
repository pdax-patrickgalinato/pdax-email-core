FROM python:3.12-slim

WORKDIR /opt/segs

# Install system deps needed by some Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x entrypoint.sh

# Absolute spool/data paths — EFS volumes mount here in ECS
ENV SEG_QUARANTINE_ROOT=/opt/segs/gateway/spool
# Secure cookies — ALB always terminates TLS before reaching the container
ENV SEG_COOKIE_SECURE=1

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8765/api/health || exit 1

CMD ["sh", "entrypoint.sh", "server.main:app", "8765"]
