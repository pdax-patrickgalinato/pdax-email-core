# Link-only first-contact FN (gmail-1a04f455f057ed83)

Live copy: first-time Gmail sender to `support@pdax.ph`, body was the
Workspace EXTERNAL banner + one WhatsApp Help Center URL + a one-word
signature. GLM named `minimal_body_with_link_only`, scored 12, `nlu_intent=none`,
composite **13 CLEAN**. Analyst expectation: **SUSPICIOUS**.

## What actually happened

| Stage | Score | Flags | Notes |
|---|---|---|---|
| headers | 0 | none | SPF pass; `dkim=neutral (body hash did not verify)` is **not** scored (Google EXTERNAL banner breaks the body hash — do not treat as `dkim_fail`) |
| urls | 0 | none | `faq.whatsapp.com` is a real brand host, not a lookalike |
| intel | 8 | `first_time_sender` | Novelty is a weak weighted signal only |
| content_ai | 12 | `minimal_body_with_link_only`, `first_time_sender_to_support` | GLM described the shape, then called it non-hostile because the URL host is WhatsApp |
| verdict | 13 CLEAN | those three flags | max-plus: content 12×0.75 + intel 8×0.5 ≈ 13. Soft-tag cap (40) would have blocked a higher LLM score anyway |

Root causes:

1. **LLM treated “real brand URL” as clean.** Prompt said keep score <40 unless a clear lure. A famous-domain link with no ask is a lure wrapper; the model did the opposite.
2. **Unknown/custom tags are soft.** `_is_soft_finding` treats anything not in `_HARD_CONTENT_TAGS` as soft, so even a high GLM score would cap at 40 → still LOW.
3. **No deterministic detector** for URL-only bodies. HeuristicProvider has urgency/BEC/credential regexes only.
4. **`first_time_sender` is +8 intel**, not a combination rule. Detection rules are display-only; they do not change verdict.
5. **AI verdict floor** only applies to `ransomware` / `extortion` / `malware_delivery` / `bec` at ≥0.8 confidence. This copy was `none` / 0.0.

Out of scope (do not do): scoring `dkim=neutral` as fail — that would FP most external Gmail into Workspace after the EXTERNAL banner.

## Corrective actions (done in this change)

1. Deterministic `is_minimal_link_only_body()` — strip EXTERNAL banner, require ≥1 URL, residual words ≤4, skip replies and trusted channels.
2. `content_ai.run()` always emits `minimal_body_with_link_only` (hard tag, score ≥50) so GLM cannot talk it down.
3. `score_and_verdict` upward floor: `first_time_sender` + `minimal_body_with_link_only` → **SUSPICIOUS** (`first_contact_link_only`). Never MALICIOUS on this combo.
4. Prompt: famous-domain URL + no ask is not “no hostile intent.”
5. Named detection rule + report copy for the analyst UI.

## FP control

- Known senders: flag may still fire; **no** SUSPICIOUS floor without `first_time_sender`.
- Replies / In-Reply-To: skipped.
- Trusted-channel From: skipped.
- A real customer question plus a link: residual words >4 → skipped.

## Follow-up (not in this change)

- Redeploy **content_ai** (and static only if detection_rules.yaml is baked into that image — it is worker-side YAML; content_ai + any worker that loads `rules/detection`). Verdict lives in the content_ai worker path after static stages. Ship **content_ai** image at minimum; static does not re-score.
- Re-assess `gmail-1a04f455f057ed83` after deploy (replay copy or wait for a similar send).
- Optional later: fan-out to an unrelated third-party envelope address (this copy also listed a Shopee newsletter) as a weighted reinforcer, not a floor.
