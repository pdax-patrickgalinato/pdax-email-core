"""Link-only first-contact detection.

Live FN: gmail-1a04f455f057ed83 — first-time Gmail sender, body was the
Workspace EXTERNAL banner + a WhatsApp FAQ URL + a signature. GLM named
minimal_body_with_link_only, scored 12, nlu=none, verdict CLEAN 13.
"""
from email.mime.text import MIMEText

from backend.models import PipelineResult, StageResult, Verdict
from workers.pipeline import content_ai, runner, verdict as verdict_mod
from workers.pipeline.content_ai import is_minimal_link_only_body


def _eml(body, *, subject="Help", frm="new.sender@gmail.com", reply=False):
    msg = MIMEText(body)
    msg["From"] = frm
    msg["To"] = "support@pdax.ph"
    msg["Subject"] = subject
    msg["Message-ID"] = "<id@mail.gmail.com>"
    if reply:
        msg["In-Reply-To"] = "<prev@mail.gmail.com>"
        msg["References"] = "<prev@mail.gmail.com>"
    return msg.as_bytes()


def test_detects_external_banner_plus_url_plus_signature():
    body = (
        "EXTERNAL: Please be cautious in opening the contents of this email.\n"
        "https://faq.whatsapp.com/854037192262196/?cms_platform=android&locale=en_US\n"
        "\n\nMonabarcena\n"
    )
    assert is_minimal_link_only_body(body) is True


def test_paragraph_plus_link_is_not_link_only():
    body = (
        "Hi, I cannot log in to the app. I followed this article but still fail:\n"
        "https://faq.whatsapp.com/854037192262196/\n"
        "Can you help?"
    )
    assert is_minimal_link_only_body(body) is False


def test_reply_with_only_a_link_is_not_link_only():
    body = "https://faq.whatsapp.com/854037192262196/\n"
    assert is_minimal_link_only_body(body, is_reply=True) is False


def test_run_emits_hard_flag_and_does_not_cap():
    from backend.parsed_email import ParsedEmail

    class _Low:
        def analyze(self, subject, body, context):
            return 12.0, [], {"provider": "glm", "nlu_intent": "none", "summary": "fine"}

    pe = ParsedEmail(_eml(
        "EXTERNAL: Please be cautious in opening the contents of this email.\n"
        "https://faq.whatsapp.com/854037192262196/\nMonabarcena\n"
    ))
    result = content_ai.run(pe, _Low(), {"headers": {"spf": "pass"}})
    assert "minimal_body_with_link_only" in result.red_flags
    assert result.sub_score >= 50.0
    assert result.facts.get("score_capped") is not True


def test_trusted_channel_skips_link_only_flag():
    from backend.parsed_email import ParsedEmail

    class _Low:
        def analyze(self, subject, body, context):
            return 5.0, [], {"provider": "glm"}

    pe = ParsedEmail(_eml("https://support.google.com/mail\n", frm="noreply@google.com"))
    result = content_ai.run(
        pe, _Low(),
        {"headers": {"spf": "pass"}, "sender": {"trusted_channel": True}},
    )
    assert "minimal_body_with_link_only" not in result.red_flags
    assert result.sub_score == 5.0


def test_first_contact_link_only_floors_to_suspicious():
    weights, thresholds = runner.load_config()[0]["weights"], runner.load_config()[0]["thresholds"]
    result = PipelineResult(stages=[
        StageResult(stage="intel", sub_score=8.0, red_flags=["first_time_sender"]),
        StageResult(stage="content_ai", sub_score=12.0,
                    red_flags=["minimal_body_with_link_only"],
                    facts={"provider": "glm", "nlu_intent": "none"}),
    ])
    verdict_mod.score_and_verdict(result, weights, thresholds)
    assert result.verdict == Verdict.SUSPICIOUS
    assert "first_contact_link_only" in result.reasons


def test_known_sender_link_only_does_not_floor():
    weights, thresholds = runner.load_config()[0]["weights"], runner.load_config()[0]["thresholds"]
    result = PipelineResult(stages=[
        StageResult(stage="intel", sub_score=0.0, red_flags=[]),
        StageResult(stage="content_ai", sub_score=50.0,
                    red_flags=["minimal_body_with_link_only"],
                    facts={"provider": "glm"}),
    ])
    verdict_mod.score_and_verdict(result, weights, thresholds)
    assert result.verdict in (Verdict.CLEAN, Verdict.LOW)
    assert "first_contact_link_only" not in result.reasons
