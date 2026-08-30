"""Spotlight search: natural language → validated SELECT on ``copies``.

The model writes a single ``SELECT queue_id FROM copies WHERE …`` statement.
That SQL is parsed and allow-listed before it ever reaches the database so a
prompt cannot jump to another table or run DML. When no LLM is configured,
a deterministic compiler still produces the same shape of SQL.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Callable, Optional

from workers.pipeline.content_ai import (
    FallbackProvider,
    GeminiProvider,
    GLMProvider,
    HeuristicProvider,
    NullProvider,
    OllamaProvider,
    _json_object_text,
    get_default_provider,
)

_log = logging.getLogger("backend.api.nl_search")

SEARCH_LIMIT = 200
_MAX_SQL_CHARS = 4000

_ALLOWED_COLUMNS = frozenset({
    "queue_id", "dest", "mailbox", "gmail_message_id", "gmail_thread_id",
    "from_addr", "subject", "to_addr", "verdict", "score", "disposition",
    "ai_provider", "ai_summary", "ai_model",
    "identity_done", "reputation_done", "static_done", "sandbox_done",
    "ai_done", "thread_ai_done", "status", "rfc_message_id", "last_error",
    "updated_at",
})
_ALLOWED_FUNCS = frozenset({
    "lower", "upper", "coalesce", "trim", "length", "ifnull",
})
_ALLOWED_KEYWORDS = frozenset({
    "and", "or", "not", "like", "in", "is", "null", "between", "escape",
    "true", "false", "asc", "desc",
})
_ALLOWED_IDENTS = _ALLOWED_COLUMNS | _ALLOWED_FUNCS | _ALLOWED_KEYWORDS

_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|attach|pragma|union|except|"
    r"intersect|into|execute|copy|grant|revoke|vacuum|replace|returning|"
    r"window|lateral|having|join|using|comment|truncate|merge|call|do|"
    r"listen|notify|load|save|declare|cursor|with)\b",
    re.I,
)
_COMMENTS = re.compile(r"/\*.*?\*/|--[^\n]*", re.S)
_STRING = re.compile(r"'(?:''|[^'])*'")
_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_SHAPE = re.compile(
    r"^SELECT\s+queue_id\s+FROM\s+copies\s+WHERE\s+(.+?)\s+"
    r"ORDER\s+BY\s+updated_at\s+DESC\s+LIMIT\s+(\d+)\s*;?\s*$",
    re.I | re.S,
)

_SCHEMA_PROMPT = """You translate an analyst's natural-language mail search into SQL.

Return JSON only:
{"sql":"SELECT queue_id FROM copies WHERE <predicate> ORDER BY updated_at DESC LIMIT 200","labels":["short filter chips"]}

Rules:
- One SELECT. Table must be copies. Select only queue_id.
- Always ORDER BY updated_at DESC LIMIT 200 (or a smaller positive limit).
- Predicate may use AND/OR/NOT, parentheses, LIKE, IN, IS NULL, BETWEEN,
  LOWER/UPPER/COALESCE/TRIM/LENGTH, and these columns only:
  queue_id, dest, mailbox, gmail_message_id, gmail_thread_id, from_addr,
  subject, to_addr, verdict, score, disposition, ai_provider, ai_summary,
  ai_model, identity_done, reputation_done, static_done, sandbox_done,
  ai_done, thread_ai_done, status, rfc_message_id, last_error, updated_at
- verdict values: CLEAN, LOW, SUSPICIOUS, MALICIOUS, PENDING, INCONCLUSIVE
- thread_ai_done = 0 means no thread assessment yet; = 1 means it exists
- ai_done = 0 means content AI is still pending
- status timed_out / last_error mentioning timeout → AI timed out
- dest may contain gmail, quarantine, rejected, released
- LIKE is case-insensitive via LOWER(column) LIKE '%term%'
- No joins, subqueries, UNION, comments, semicolons, or other tables.
"""

LlmComplete = Callable[[str, str], Optional[str]]


class SearchSqlError(ValueError):
    """Rejected or unusable search SQL."""


def validate_search_sql(sql: str) -> str:
    """Return a canonical SELECT … LIMIT n or raise SearchSqlError."""
    raw = (sql or "").strip()
    if not raw or len(raw) > _MAX_SQL_CHARS:
        raise SearchSqlError("empty or oversized SQL")
    if "$" in raw or ";" in raw.rstrip().rstrip(";"):
        raise SearchSqlError("unsupported SQL punctuation")
    stripped = _COMMENTS.sub(" ", raw)
    stripped = re.sub(r"\s+", " ", stripped).strip().rstrip(";")
    if _FORBIDDEN.search(_STRING.sub(" ", stripped)):
        raise SearchSqlError("SQL contains a forbidden keyword")
    m = _SHAPE.match(stripped)
    if not m:
        raise SearchSqlError("SQL must be SELECT queue_id FROM copies WHERE … ORDER BY updated_at DESC LIMIT n")
    where, limit_s = m.group(1).strip(), m.group(2)
    limit_n = int(limit_s)
    if limit_n < 1 or limit_n > SEARCH_LIMIT:
        raise SearchSqlError("LIMIT out of range")
    _assert_where_idents(where)
    return (
        "SELECT queue_id FROM copies WHERE " + where
        + " ORDER BY updated_at DESC LIMIT " + str(limit_n)
    )


def _assert_where_idents(where: str) -> None:
    masked = _STRING.sub("''", where)
    if re.search(r"[;`\\]|--|/\*", masked):
        raise SearchSqlError("unsafe token in WHERE")
    for tok in _IDENT.findall(masked):
        if tok.lower() not in _ALLOWED_IDENTS:
            raise SearchSqlError(f"identifier not allowed: {tok}")


def fallback_sql(query: str) -> tuple[str, list[str]]:
    """Keyword compiler used when the LLM is offline or returns invalid SQL."""
    rest = " " + (query or "").strip().lower() + " "
    clauses: list[str] = []
    labels: list[str] = []

    def add(clause: str, label: str) -> None:
        clauses.append(clause)
        if label not in labels:
            labels.append(label)

    def take(pattern: str) -> bool:
        nonlocal rest
        m = re.search(pattern, rest, re.I)
        if not m:
            return False
        rest = rest[: m.start()] + " " + rest[m.end() :]
        return True

    if take(r"\b(?:without|w/o|no|missing|pending|awaiting|not\s+yet).{0,40}thread.{0,24}(?:assess\w*|ai)\b") or take(
        r"\bthread.{0,24}(?:assess\w*|ai).{0,24}(?:pending|missing|yet|none|await|not\s+done)\b"
    ) or take(r"\b(?:no|without)\s+thread\s+(?:assess\w*|ai)\b"):
        add("COALESCE(thread_ai_done, 0) = 0", "No thread assessment")
    elif take(r"\bthread.{0,16}(?:assess\w*|ai).{0,16}(?:done|complete|finished|ready|present)\b") or take(
        r"\bwith\s+thread\s+(?:assess\w*|ai)\b"
    ):
        add("COALESCE(thread_ai_done, 0) = 1", "Has thread assessment")

    if take(r"\b(?:timed\s*out|timeout|inconclusive)\b"):
        add(
            "(UPPER(COALESCE(verdict, '')) = 'INCONCLUSIVE' OR LOWER(COALESCE(status, '')) = 'timed_out')",
            "AI timed out",
        )
    elif take(r"\b(?:without|w/o|no|missing|pending|awaiting|not\s+yet).{0,32}(?:content|llm|ai|assess\w*)\b") or take(
        r"\b(?:pending|awaiting|not\s+yet\s+assessed)\b"
    ):
        add("COALESCE(ai_done, 0) = 0", "Awaiting content AI")

    if take(r"\bmalicious\b"):
        add("UPPER(COALESCE(verdict, '')) = 'MALICIOUS'", "Malicious")
    if take(r"\bsuspicious\b"):
        add("UPPER(COALESCE(verdict, '')) = 'SUSPICIOUS'", "Suspicious")
    if take(r"\b(?:clean|safe|benign)\b"):
        add("UPPER(COALESCE(verdict, '')) IN ('CLEAN', 'LOW')", "Safe")

    if take(r"\bblocked\b"):
        add("UPPER(COALESCE(verdict, '')) = 'MALICIOUS'", "Blocked")
    if take(r"\bquarantined?\b"):
        add(
            "(LOWER(COALESCE(dest, '')) LIKE '%quarantine%' OR UPPER(COALESCE(verdict, '')) = 'SUSPICIOUS')",
            "Quarantined",
        )
    if take(r"\breleased\b"):
        add("LOWER(COALESCE(dest, '')) LIKE '%released%'", "Released")

    from_m = re.search(r"\bfrom\s+(\S+)", rest)
    if from_m and from_m.group(1) not in {"the", "all", "my", "our"}:
        token = _like_literal(from_m.group(1))
        rest = rest.replace(from_m.group(0), " ", 1)
        add("LOWER(COALESCE(from_addr, '')) LIKE " + token, "From " + from_m.group(1).strip("\"'"))

    to_m = re.search(r"\bto\s+(\S*@\S+|\S+\.\S+)", rest)
    if to_m:
        token = _like_literal(to_m.group(1))
        rest = rest.replace(to_m.group(0), " ", 1)
        add(
            "(LOWER(COALESCE(to_addr, '')) LIKE "
            + token
            + " OR LOWER(COALESCE(mailbox, '')) LIKE "
            + token
            + ")",
            "To " + to_m.group(1).strip("\"'"),
        )

    leftover = re.sub(
        r"\b(?:i|i'd|i'm|me|want|wanna|like|need|please|would|could|can|you|we|"
        r"let's|show|see|find|list|get|give|bring|pull|display|open|look(?:ing)?|"
        r"all|the|emails?|e-?mails?|messages?|mails?|items?|ones?|that|which|who|"
        r"what|are|is|was|be|been|being|have|has|had|a|an|of|for|in|on|at|to|my|"
        r"our|this|those|these|here|there|still|yet|just|also|only|some|any|every)\b",
        " ",
        rest,
        flags=re.I,
    )
    leftover = re.sub(r"[?.,!;:()[\]{}]", " ", leftover)
    leftover = re.sub(r"\s+", " ", leftover).strip()
    if leftover:
        token = _like_literal(leftover)
        add(
            "(LOWER(COALESCE(subject, '')) LIKE "
            + token
            + " OR LOWER(COALESCE(from_addr, '')) LIKE "
            + token
            + " OR LOWER(COALESCE(to_addr, '')) LIKE "
            + token
            + " OR LOWER(COALESCE(mailbox, '')) LIKE "
            + token
            + " OR LOWER(COALESCE(ai_summary, '')) LIKE "
            + token
            + ")",
            leftover,
        )

    where = " AND ".join(clauses) if clauses else "1 = 1"
    sql = (
        "SELECT queue_id FROM copies WHERE " + where
        + " ORDER BY updated_at DESC LIMIT " + str(SEARCH_LIMIT)
    )
    return validate_search_sql(sql), labels


def _like_literal(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9@._+\- ]+", "", (raw or "").strip("\"'"))[:80]
    escaped = cleaned.replace("'", "''").replace("%", "").replace("_", "")
    return "'%" + escaped.lower() + "%'"


def parse_llm_plan(text: str) -> tuple[str, list[str]]:
    blob = _json_object_text(text or "")
    data = json.loads(blob)
    if not isinstance(data, dict):
        raise SearchSqlError("model did not return an object")
    sql = str(data.get("sql") or "").strip()
    if sql and not re.match(r"SELECT\s", sql, re.I):
        sql = (
            "SELECT queue_id FROM copies WHERE " + sql
            + " ORDER BY updated_at DESC LIMIT " + str(SEARCH_LIMIT)
        )
    labels = data.get("labels") or []
    if not isinstance(labels, list):
        labels = []
    chips = [str(x).strip() for x in labels if str(x).strip()][:8]
    return validate_search_sql(sql), chips


def default_llm_complete(system: str, user: str) -> Optional[str]:
    """Ask the configured content provider for JSON. None if offline/heuristic."""
    from concurrent.futures import ThreadPoolExecutor

    def _run() -> Optional[str]:
        provider = get_default_provider()
        slots = list(getattr(provider, "_providers", None) or [provider])
        for slot in slots:
            if isinstance(slot, (HeuristicProvider, NullProvider)):
                continue
            try:
                text = _complete_slot(slot, system, user)
            except Exception:
                _log.exception("spotlight LLM slot failed (%s)", type(slot).__name__)
                continue
            if text and text.strip():
                return text
        return None

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(_run).result(timeout=15)
    except Exception:
        _log.exception("spotlight LLM complete failed")
        return None


def _complete_slot(slot, system: str, user: str) -> Optional[str]:
    if isinstance(slot, GeminiProvider):
        client = slot._get_client()
        response = client.models.generate_content(
            model=slot.model_id,
            contents=user,
            config={
                "system_instruction": system,
                "temperature": 0,
                "max_output_tokens": 500,
                "response_mime_type": "application/json",
            },
        )
        return GeminiProvider._extract_text(response)
    if isinstance(slot, (GLMProvider, OllamaProvider)):
        client = slot._get_client()
        response = slot._generate(
            client,
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return slot._extract_text(response)
    return None


def compile_search(
    query: str,
    *,
    llm_complete: Optional[LlmComplete] = None,
) -> dict:
    """Turn natural language into validated SQL.

    ``source`` is ``ai`` when the model produced usable SQL, otherwise
    ``fallback``.
    """
    q = (query or "").strip()
    if not q:
        raise SearchSqlError("empty query")
    if len(q) > 500:
        raise SearchSqlError("query too long")
    complete = default_llm_complete if llm_complete is None else llm_complete
    source = "fallback"
    labels: list[str] = []
    sql = ""
    try:
        raw = complete(_SCHEMA_PROMPT, "Search request:\n" + q)
        if raw:
            sql, labels = parse_llm_plan(raw)
            source = "ai"
    except Exception:
        _log.exception("spotlight LLM plan rejected")
        sql = ""
    if not sql:
        sql, labels = fallback_sql(q)
        source = "fallback"
    return {"sql": sql, "labels": labels, "source": source, "q": q}


def apply_verdict_filter(sql: str, verdict_filter: str) -> str:
    """AND an overview tile (safe / suspicious / malicious) onto validated SQL."""
    from backend.stores.assessments import verdicts_for_filter

    wanted = verdicts_for_filter(verdict_filter)
    if not wanted:
        return sql
    m = _SHAPE.match(sql.strip().rstrip(";"))
    if not m:
        raise SearchSqlError("cannot combine verdict filter")
    where, limit_s = m.group(1), m.group(2)
    listed = ", ".join("'" + v.replace("'", "") + "'" for v in wanted)
    combined = "(" + where + ") AND UPPER(COALESCE(verdict, '')) IN (" + listed + ")"
    return validate_search_sql(
        "SELECT queue_id FROM copies WHERE " + combined
        + " ORDER BY updated_at DESC LIMIT " + limit_s
    )
