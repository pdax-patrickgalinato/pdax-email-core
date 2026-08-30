"""python -m workers dispatcher."""
from pathlib import Path

from workers.__main__ import WORKERS, main

_ROOT = Path(__file__).resolve().parents[3]


def test_entrypoint_prefers_seg_worker_over_image_cmd():
    # Fargate passes image CMD as $1 when the task omits command; that CMD
    # used to be `static`, so every split worker started as static.
    script = (_ROOT / "deploy/docker/entrypoint-worker.sh").read_text()
    assert 'WORKER="${SEG_WORKER:-${1:-}}"' in script
    dockerfile = (_ROOT / "deploy/docker/Dockerfile.worker").read_text()
    assert "CMD [\"static\"]" not in dockerfile


def test_workers_main_requires_a_known_name():
    assert main([]) == 2
    assert main(["not-a-worker"]) == 2
    assert "static" in WORKERS
    assert "gmail_poll" in WORKERS
    assert "content_ai" in WORKERS
    assert "sender" in WORKERS
    assert "identity" not in WORKERS
    src = Path(__file__).resolve().parents[3] / "workers" / "__main__.py"
    text = src.read_text(encoding="utf-8")
    body = text.split("def main", 1)[1]
    assert body.index("start_health_server()") < body.index("import workers.runtime")
    assert body.index("start_health_server()") < body.index("fn = _main_for(name)")


def test_workers_package_does_not_import_workers_at_load():
    # python -m workers runs __init__ before health binds. Eager imports of
    # content_ai / gmail_poll pull Vertex and the Gmail client and fail the ALB.
    text = (_ROOT / "workers" / "__init__.py").read_text(encoding="utf-8")
    assert "from workers.content_ai import" not in text
    assert "from workers.gmail_poll import" not in text
    assert "def __getattr__" in text
    assert "_LAZY" in text


def test_health_module_does_not_import_runtime_or_settings():
    text = (_ROOT / "workers" / "health.py").read_text(encoding="utf-8")
    assert "import workers.runtime as runtime" not in text
    assert "from workers.runtime import" not in text
    assert "from backend.config import" not in text
