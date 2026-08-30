"""Typed process configuration.

All SEG_* / SEGS_* / a few adjacent env vars are declared here. Call sites
read `get_settings()` instead of `os.environ.get`. Settings are built from
the process environment on each call so tests that monkeypatch `os.environ`
keep working.

`.env` is not loaded here. `start_server.sh` and the Docker entrypoint
already export variables into the process; auto-loading `.env` would leak
operator secrets into pytest.
"""
from __future__ import annotations

from typing import Annotated, Optional

from pydantic import BeforeValidator, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _opt_in(v: object) -> bool:
    if isinstance(v, bool):
        return v
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _not_disabled(v: object) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return True
    return str(v).strip().lower() not in ("0", "false", "no", "off")


def _int_or(default: int):
    def _parse(v: object) -> int:
        try:
            return int(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return default
    return _parse


OptIn = Annotated[bool, BeforeValidator(_opt_in)]
DefaultOn = Annotated[bool, BeforeValidator(_not_disabled)]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        extra="ignore",
        populate_by_name=True,
        case_sensitive=False,
        env_file=None,
    )

    # Core
    enforce: str = Field(default="shadow", validation_alias="SEG_ENFORCE")
    cookie_secure: OptIn = Field(default=False, validation_alias="SEG_COOKIE_SECURE")
    public_origin: str = Field(default="", validation_alias="SEG_PUBLIC_ORIGIN")
    serve_spa: DefaultOn = Field(default=True, validation_alias="SEG_SERVE_SPA")
    dashboard_samples: OptIn = Field(default=False, validation_alias="SEG_DASHBOARD_SAMPLES")
    quarantine_root: str = Field(default="email/spool", validation_alias="SEG_QUARANTINE_ROOT")
    max_body_bytes: Annotated[int, BeforeValidator(_int_or(16 * 1024 * 1024))] = Field(
        default=16 * 1024 * 1024, validation_alias="SEG_MAX_BODY_BYTES",
    )

    # Gmail / Path A
    gmail_credentials: Optional[str] = Field(default=None, validation_alias="SEG_GMAIL_CREDENTIALS")
    gmail_topic: str = Field(default="", validation_alias="SEG_GMAIL_TOPIC")
    gmail_domain: str = Field(default="pdax.ph", validation_alias="SEG_GMAIL_DOMAIN")
    gmail_users: str = Field(default="", validation_alias="SEG_GMAIL_USERS")
    gmail_poll_seconds: Annotated[int, BeforeValidator(_int_or(30))] = Field(
        default=30, validation_alias="SEG_GMAIL_POLL_SECONDS",
    )
    receiver_health_url: str = Field(
        default="", validation_alias="SEG_RECEIVER_HEALTH_URL",
    )
    worker_health_base_url: str = Field(
        default="", validation_alias="SEG_WORKER_HEALTH_BASE_URL",
    )
    worker_health_port: Annotated[int, BeforeValidator(_int_or(8766))] = Field(
        default=8766, validation_alias="SEG_WORKER_HEALTH_PORT",
    )
    pubsub_token: str = Field(default="", validation_alias="SEG_PUBSUB_TOKEN")
    email_scan_timeout_seconds: Annotated[int, BeforeValidator(_int_or(300))] = Field(
        default=300, validation_alias="SEG_EMAIL_SCAN_TIMEOUT_SECONDS",
    )
    analyze_timeout_seconds: Annotated[int, BeforeValidator(_int_or(300))] = Field(
        default=300, validation_alias="SEG_ANALYZE_TIMEOUT_SECONDS",
    )
    llm_assess_timeout_seconds: Annotated[int, BeforeValidator(_int_or(120))] = Field(
        default=120, validation_alias="SEG_LLM_ASSESS_TIMEOUT_SECONDS",
    )
    llm_model_timeout_seconds: Annotated[int, BeforeValidator(_int_or(25))] = Field(
        default=25, validation_alias="SEG_LLM_MODEL_TIMEOUT_SECONDS",
    )
    profile_worker: DefaultOn = Field(default=True, validation_alias="SEG_PROFILE_WORKER")
    profile_worker_seconds: Annotated[int, BeforeValidator(_int_or(45))] = Field(
        default=45, validation_alias="SEG_PROFILE_WORKER_SECONDS",
    )
    profile_workers: Annotated[int, BeforeValidator(_int_or(4))] = Field(
        default=4, validation_alias="SEG_PROFILE_WORKERS",
    )
    inconclusive_retry: DefaultOn = Field(default=True, validation_alias="SEG_INCONCLUSIVE_RETRY")
    inconclusive_retry_seconds: Annotated[int, BeforeValidator(_int_or(30))] = Field(
        default=30, validation_alias="SEG_INCONCLUSIVE_RETRY_SECONDS",
    )
    inconclusive_retry_batch: Annotated[int, BeforeValidator(_int_or(25))] = Field(
        default=25, validation_alias="SEG_INCONCLUSIVE_RETRY_BATCH",
    )
    inconclusive_retry_max: Annotated[int, BeforeValidator(_int_or(12))] = Field(
        default=12, validation_alias="SEG_INCONCLUSIVE_RETRY_MAX",
    )
    static_workers: Annotated[int, BeforeValidator(_int_or(2))] = Field(
        default=2, validation_alias="SEG_STATIC_WORKERS",
    )
    intel_workers: Annotated[int, BeforeValidator(_int_or(1))] = Field(
        default=1, validation_alias="SEG_INTEL_WORKERS",
    )
    content_ai_workers: Annotated[int, BeforeValidator(_int_or(4))] = Field(
        default=4, validation_alias="SEG_CONTENT_AI_WORKERS",
    )
    thread_ai_workers: Annotated[int, BeforeValidator(_int_or(1))] = Field(
        default=1, validation_alias="SEG_THREAD_AI_WORKERS",
    )
    job_lease_seconds: Annotated[int, BeforeValidator(_int_or(360))] = Field(
        default=360, validation_alias="SEG_JOB_LEASE_SECONDS",
    )
    gmail_fetch_workers: Annotated[int, BeforeValidator(_int_or(4))] = Field(
        default=4, validation_alias="SEG_GMAIL_FETCH_WORKERS",
    )
    llm_backfill_limit: Annotated[int, BeforeValidator(_int_or(200))] = Field(
        default=200, validation_alias="SEG_LLM_BACKFILL_LIMIT",
    )
    inline_workers: DefaultOn = Field(default=True, validation_alias="SEG_INLINE_WORKERS")
    job_max_attempts: Annotated[int, BeforeValidator(_int_or(8))] = Field(
        default=8, validation_alias="SEG_JOB_MAX_ATTEMPTS",
    )
    campaign_worker: DefaultOn = Field(default=True, validation_alias="SEG_CAMPAIGN_WORKER")
    campaign_worker_seconds: Annotated[int, BeforeValidator(_int_or(90))] = Field(
        default=90, validation_alias="SEG_CAMPAIGN_WORKER_SECONDS",
    )
    campaign_workers: Annotated[int, BeforeValidator(_int_or(4))] = Field(
        default=4, validation_alias="SEG_CAMPAIGN_WORKERS",
    )
    sender_risk_worker: DefaultOn = Field(default=True, validation_alias="SEG_SENDER_RISK_WORKER")
    sender_risk_seconds: Annotated[int, BeforeValidator(_int_or(60))] = Field(
        default=60, validation_alias="SEG_SENDER_RISK_SECONDS",
    )
    sender_risk_batch: Annotated[int, BeforeValidator(_int_or(5))] = Field(
        default=5, validation_alias="SEG_SENDER_RISK_BATCH",
    )
    sender_risk_workers: Annotated[int, BeforeValidator(_int_or(2))] = Field(
        default=2, validation_alias="SEG_SENDER_RISK_WORKERS",
    )

    # Content AI
    content_provider: str = Field(default="heuristic", validation_alias="SEG_CONTENT_PROVIDER")
    bedrock_model_id: str = Field(
        default="anthropic.claude-3-5-sonnet-20241022-v2:0",
        validation_alias="SEG_BEDROCK_MODEL_ID",
    )
    aws_region: str = Field(default="ap-southeast-1", validation_alias="AWS_REGION")
    gemini_model_id: str = Field(default="gemini-flash-latest", validation_alias="SEG_GEMINI_MODEL_ID")
    gemini_api_key: Optional[str] = Field(default=None, validation_alias="SEG_GEMINI_API_KEY")
    gemini_api_key_alt: Optional[str] = Field(default=None, validation_alias="GEMINI_API_KEY")
    glm_location: str = Field(default="us-central1", validation_alias="SEG_GLM_LOCATION")
    glm_model_id: str = Field(
        default="deepseek-ai/deepseek-r1-0528-maas", validation_alias="SEG_GLM_MODEL_ID",
    )
    glm_api_key: Optional[str] = Field(default=None, validation_alias="SEG_GLM_API_KEY")
    glm_credentials_path: Optional[str] = Field(default=None, validation_alias="SEG_GLM_CREDENTIALS_PATH")
    google_application_credentials: Optional[str] = Field(
        default=None, validation_alias="GOOGLE_APPLICATION_CREDENTIALS",
    )
    glm_project_id: str = Field(default="", validation_alias="SEG_GLM_PROJECT_ID")
    glm_fallback1_model_id: str = Field(
        default="zai-org/glm-5.2-maas", validation_alias="SEG_GLM_FALLBACK1_MODEL_ID",
    )
    glm_fallback1_location: str = Field(
        default="global", validation_alias="SEG_GLM_FALLBACK1_LOCATION",
    )
    glm_fallback2_model_id: str = Field(
        default="moonshotai/kimi-k3-maas", validation_alias="SEG_GLM_FALLBACK2_MODEL_ID",
    )
    glm_fallback2_location: str = Field(default="global", validation_alias="SEG_GLM_FALLBACK2_LOCATION")
    glm_fallback3_model_id: str = Field(
        default="google/gemini-2.5-flash", validation_alias="SEG_GLM_FALLBACK3_MODEL_ID",
    )
    glm_fallback3_location: str = Field(
        default="us-central1", validation_alias="SEG_GLM_FALLBACK3_LOCATION",
    )
    ollama_host: str = Field(default="http://localhost:11434", validation_alias="SEG_OLLAMA_HOST")
    ollama_model_id: Optional[str] = Field(default=None, validation_alias="SEG_OLLAMA_MODEL_ID")
    ollama_api_key: Optional[str] = Field(default=None, validation_alias="SEG_OLLAMA_API_KEY")
    deep_max_tokens: Optional[str] = Field(default=None, validation_alias="SEG_DEEP_MAX_TOKENS")

    # Intel
    intel_client: str = Field(default="local", validation_alias="SEG_INTEL_CLIENT")
    vt_api_key: Optional[str] = Field(default=None, validation_alias="SEG_VT_API_KEY")
    abuseipdb_api_key: Optional[str] = Field(default=None, validation_alias="SEG_ABUSEIPDB_API_KEY")
    vt_max_indicators_per_email: Annotated[int, BeforeValidator(_int_or(8))] = Field(
        default=8, validation_alias="SEG_VT_MAX_INDICATORS_PER_EMAIL",
    )
    vt_time_budget_seconds: float = Field(default=90.0, validation_alias="SEG_VT_TIME_BUDGET_SECONDS")

    # Sandbox / ClamAV
    sandbox_provider: str = Field(default="null", validation_alias="SEG_SANDBOX_PROVIDER")
    clamd_socket: str = Field(default="", validation_alias="SEG_CLAMD_SOCKET")
    clamd_host: str = Field(default="localhost", validation_alias="SEG_CLAMD_HOST")
    clamd_port: Annotated[int, BeforeValidator(_int_or(3310))] = Field(
        default=3310, validation_alias="SEG_CLAMD_PORT",
    )

    # Pipeline flags
    landing_fetch: OptIn = Field(default=False, validation_alias="SEG_LANDING_FETCH")
    rdap_lookup: OptIn = Field(default=False, validation_alias="SEG_RDAP_LOOKUP")
    origin_ip_search: DefaultOn = Field(default=True, validation_alias="SEG_ORIGIN_IP_SEARCH")
    origin_ip_geo: DefaultOn = Field(default=True, validation_alias="SEG_ORIGIN_IP_GEO")
    expected_mail_countries: str = Field(default="", validation_alias="SEG_EXPECTED_MAIL_COUNTRIES")
    llm_triage: OptIn = Field(default=False, validation_alias="SEG_LLM_TRIAGE")
    llm_triage_margin: float = Field(default=15.0, validation_alias="SEG_LLM_TRIAGE_MARGIN")
    correlation_store: OptIn = Field(default=False, validation_alias="SEG_CORRELATION_STORE")
    ai_verdict_floor_conf: Optional[str] = Field(
        default=None, validation_alias="SEG_AI_VERDICT_FLOOR_CONF",
    )

    # Dashboard
    dashboard_llm: DefaultOn = Field(default=True, validation_alias="SEG_DASHBOARD_LLM")
    dashboard_deep: DefaultOn = Field(default=True, validation_alias="SEG_DASHBOARD_DEEP")

    # Notify (SEGS_ prefix — historical)
    notify_smtp_pass: str = Field(default="", validation_alias="SEGS_NOTIFY_SMTP_PASS")

    # SSO / JumpCloud OIDC (ALB authenticate-oidc; see docs/jumpcloud-sso.md)
    sso_provider: str = Field(default="", validation_alias="SEG_SSO_PROVIDER")
    oidc_client_id: str = Field(default="", validation_alias="SEG_OIDC_CLIENT_ID")
    oidc_client_secret: str = Field(default="", validation_alias="SEG_OIDC_CLIENT_SECRET")
    oidc_issuer: str = Field(default="", validation_alias="SEG_OIDC_ISSUER")

    # Stateful JWT (RFC 7519 / RFC 9068) + SCIM 2.0 provisioning
    jwt_secret: str = Field(default="", validation_alias="SEG_JWT_SECRET")
    jwt_issuer: str = Field(default="", validation_alias="SEG_JWT_ISSUER")
    scim_bearer_token: str = Field(default="", validation_alias="SEG_SCIM_BEARER_TOKEN")

    # S3 / Wazuh
    s3_bucket: str = Field(default="", validation_alias="SEG_S3_BUCKET")
    s3_prefix: str = Field(default="segs/logs", validation_alias="SEG_S3_PREFIX")
    s3_region: str = Field(default="", validation_alias="SEG_S3_REGION")
    s3_ship_interval: Annotated[int, BeforeValidator(_int_or(60))] = Field(
        default=60, validation_alias="SEG_S3_SHIP_INTERVAL",
    )
    kms_key_arn: str = Field(default="", validation_alias="SEG_KMS_KEY_ARN")
    database_url: str = Field(default="", validation_alias="SEG_DATABASE_URL")
    sqs_static_url: str = Field(default="", validation_alias="SEG_SQS_STATIC_URL")
    sqs_content_ai_url: str = Field(default="", validation_alias="SEG_SQS_CONTENT_AI_URL")
    sqs_thread_ai_url: str = Field(default="", validation_alias="SEG_SQS_THREAD_AI_URL")
    sqs_campaign_url: str = Field(default="", validation_alias="SEG_SQS_CAMPAIGN_URL")
    sqs_profile_url: str = Field(default="", validation_alias="SEG_SQS_PROFILE_URL")


def get_settings() -> Settings:
    """Fresh read of the process environment. Not cached — tests mutate env."""
    return Settings()
