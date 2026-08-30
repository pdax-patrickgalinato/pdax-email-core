FROM python:3.12-slim

WORKDIR /opt/segs

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# uid/gid 1000 matches infra efs_posix_uid so EFS writes (profiles, heartbeats) succeed.
RUN groupadd --gid 1000 segs \
    && useradd --uid 1000 --gid segs --no-create-home --shell /usr/sbin/nologin segs

COPY requirements.txt pyproject.toml README.md ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=segs:segs backend ./backend
COPY --chown=segs:segs workers ./workers
COPY --chown=segs:segs cli ./cli
COPY --chown=segs:segs deploy/docker/entrypoint.sh /opt/segs/entrypoint.sh
COPY --chown=segs:segs deploy/docker/tls-env.sh /opt/segs/tls-env.sh

RUN chmod +x /opt/segs/entrypoint.sh \
    && mkdir -p /opt/segs/data /opt/segs/email/spool /opt/segs/tls \
    && chown segs:segs /opt/segs \
    && chown -R segs:segs /opt/segs/data /opt/segs/email /opt/segs/tls

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/segs \
    SEG_QUARANTINE_ROOT=/opt/segs/email/spool \
    SEG_COOKIE_SECURE=1 \
    SEG_PROFILE_WORKER=1 \
    SEG_INCONCLUSIVE_RETRY=1 \
    SEG_CORRELATION_STORE=1 \
    SEG_SERVE_SPA=0

USER segs

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fk https://localhost:8765/api/health || curl -f http://localhost:8765/api/health || exit 1

# --workers 1: profile ingest is an in-process thread.
CMD ["sh", "/opt/segs/entrypoint.sh", "backend.api.main:app", "8765"]
