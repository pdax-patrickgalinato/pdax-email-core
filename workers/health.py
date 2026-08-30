"""Per-worker health for the internal ALB (HTTPS when SEG_TLS_* is set).

Each ``python -m workers <name>`` process binds :8766 and serves
``GET /health`` (target-group check) plus ``GET /<name>/health`` (path
the API hits on the internal ALB). The all-in-one receiver already owns
:8766 and is skipped.

This module must not import ``workers.runtime`` or ``backend.config`` at
load time — those pull Postgres and settings and would delay the bind.
"""
from __future__ import annotations

import json
import logging
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_log = logging.getLogger("workers.health")

DEFAULT_PORT = 8766
_SKIP = frozenset({"", "unknown", "gmail_receiver", "api"})
_SLOT = {
    "gmail_poll": "gmail_poll",
    "static": "static",
    "content_ai": "gmail_llm",
    "thread_ai": "thread_ai",
    "retry": "inconclusive_retry",
    "campaign": "campaign",
    "profile": "profile",
    "sender_risk": "sender_risk",
    "sender": "profile",
}
_MULTI_SLOTS = {
    "sender": ("profile", "sender_risk"),
}
_ALIAS_HEALTH = {
    "sender": ("/profile/health", "/sender_risk/health"),
}

_server: ThreadingHTTPServer | None = None
_thread: threading.Thread | None = None
_lock = threading.Lock()


def _process_name() -> str:
    mod = sys.modules.get("workers.runtime")
    if mod is not None:
        try:
            name = str(mod.process_name() or "").strip()
            if name:
                return name
        except Exception:
            pass
    return (os.environ.get("SEG_WORKER") or "").strip() or "unknown"


def _listen_port(port: int | None) -> int:
    if port is not None:
        return int(port)
    for key in ("SEG_WORKER_HEALTH_PORT", "WORKER_HEALTH_PORT"):
        raw = (os.environ.get(key) or "").strip()
        if not raw:
            continue
        try:
            n = int(raw)
        except ValueError:
            continue
        if n > 0:
            return n
    return DEFAULT_PORT


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        _log.debug(fmt, *args)

    def do_GET(self) -> None:
        path = (self.path or "/").split("?", 1)[0]
        path = path.rstrip("/") or "/"
        name = _process_name()
        allowed = {"/health", "/status", f"/{name}/health"}
        allowed.update(_ALIAS_HEALTH.get(name, ()))
        if path not in allowed:
            self._send(404, {"ok": False, "error": "not found"})
            return
        # Never call worker_status() here. That path imports Vertex / hits
        # Postgres and would stall the ALB/docker health check.
        snap = {"process": name}
        for slot in _MULTI_SLOTS.get(name) or ((_SLOT.get(name),) if _SLOT.get(name) else ()):
            if slot:
                snap[slot] = {"alive": True, "enabled": True, "running": True}
        snap["ok"] = True
        snap["reachable"] = True
        snap["source"] = "probe"
        self._send(200, snap)

    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)


def listen_port() -> int | None:
    srv = _server
    if srv is None:
        return None
    return int(srv.server_address[1])


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True


def _server_ssl_context() -> ssl.SSLContext | None:
    cert = (os.environ.get("SEG_TLS_CERT_PATH") or "").strip() or "/opt/segs/tls/server.crt"
    key = (os.environ.get("SEG_TLS_KEY_PATH") or "").strip() or "/opt/segs/tls/server.key"
    if not (os.path.isfile(cert) and os.path.isfile(key)):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx


def start_health_server(port: int | None = None) -> ThreadingHTTPServer | None:
    """Bind a daemon HTTP server. No-op if this process is the receiver/API."""
    global _server, _thread
    if _process_name() in _SKIP:
        return None
    with _lock:
        if _server is not None:
            return _server
        bind = _listen_port(port)
        ctx = None
        try:
            httpd = _Server(("0.0.0.0", bind), _Handler)
            ctx = _server_ssl_context()
            if ctx is not None:
                httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        except OSError as exc:
            _log.warning("worker health server did not bind :%s (%s)", bind, exc)
            print(f"[workers.health] bind failed :{bind} ({exc})", file=sys.stderr, flush=True)
            return None
        _server = httpd
        _thread = threading.Thread(
            target=httpd.serve_forever,
            name="worker-health",
            daemon=True,
        )
        _thread.start()
        bound = httpd.server_address[1]
        who = _process_name()
        tls = "https" if ctx is not None else "http"
        print(f"[workers.health] listening on {tls}://0.0.0.0:{bound} for {who}", file=sys.stderr, flush=True)
        _log.info("worker health listening on %s :%s for %s", tls, bound, who)
        return httpd


def stop_health_server() -> None:
    global _server, _thread
    with _lock:
        srv, th = _server, _thread
        _server = None
        _thread = None
    if srv is not None:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    if th is not None and th.is_alive():
        th.join(timeout=2)
