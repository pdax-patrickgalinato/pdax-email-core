"""Dashboard backend — a fourth consumer of app/pipeline/runner.py::run_pipeline(),
at the same architectural layer as the CLI (analyze.py) and the gateway
(gateway/hold_consumer.py), not part of the transport-agnostic core itself.

Serves dashboard/index.html and its supporting JS/JSON API endpoints:
policy read/write (server/routers/policy.py), the real-data feed
(server/routers/feed.py), and RBAC login/session management
(server/routers/auth.py).

Run: uvicorn server.main:app --reload
"""
