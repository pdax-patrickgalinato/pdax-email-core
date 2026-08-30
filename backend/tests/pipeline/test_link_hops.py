"""Link-hop chains for the assessment-flow graph (encoded unwraps + HTTP)."""
from workers.pipeline.urls import build_link_hops, unwrap_embedded
from workers.pipeline.stage_summary import compact_stages
from backend.models import StageResult, StageStatus


def test_unwrap_nested_tracker_and_safelinks():
    wrapped = (
        "https://nam.safelinks.protection.outlook.com/?url="
        "https%3A%2F%2Fbit.ly%2Fx%3Furl%3Dhttps%253A%252F%252Fsecure-login.account-verify.top%252F"
    )
    hops = unwrap_embedded(wrapped)
    targets = [h["target"] for h in hops]
    assert any("bit.ly" in t for t in targets)
    assert any("account-verify.top" in t for t in targets)


def test_build_link_hops_encoded_chain():
    url = (
        "https://ddec1-0-en-ctp.trendmicro.com/wis/clicktime/v1/query"
        "?url=https%3A%2F%2Fbit.ly%2Fabc%3Furl%3Dhttps%253A%252F%252Fphish.example%252Flogin"
    )
    chains = build_link_hops([url])
    assert chains
    hosts = chains[0]["hosts"]
    assert "trendmicro.com" in hosts[0] or hosts[0].endswith("trendmicro.com")
    assert any("bit.ly" in h for h in hosts)
    assert any("phish.example" in h for h in hosts)
    assert chains[0]["hop_count"] >= 3
    assert chains[0]["kind"] == "embedded"
    assert chains[0]["suspicious"] is True


def test_build_link_hops_skips_single_host():
    assert build_link_hops(["https://pdax.ph/help"]) == []


def test_build_link_hops_merges_http_redirects():
    landing = [{
        "requested_url": "https://bit.ly/x",
        "final_url": "https://evil.example/gate",
        "redirect_chain": ["https://bit.ly/x", "https://tracker.cdn.example/r"],
    }]
    chains = build_link_hops(["https://pdax.ph/"], landing)
    http = [c for c in chains if c["kind"] == "http"]
    assert http
    assert http[0]["hosts"][0] == "bit.ly"
    assert http[0]["final"] == "evil.example"
    assert http[0]["hop_count"] >= 3


def test_summarize_context_includes_link_hops():
    from workers.pipeline.content_ai import _summarize_context
    summary = _summarize_context({
        "urls": {
            "link_hops": [{
                "hosts": ["nam.safelinks.protection.outlook.com", "bit.ly", "evil.example"],
                "hop_count": 3,
            }]
        }
    })
    assert "link hops:" in summary
    assert "bit.ly" in summary
    assert "evil.example" in summary


def test_compact_stages_keeps_link_hops():
    hops = [{"hosts": ["a.example", "b.example"], "hop_count": 2, "final": "b.example",
             "kind": "embedded", "suspicious": False, "urls": []}]
    st = StageResult(stage="urls", status=StageStatus.OK, sub_score=5.0,
                     red_flags=[], facts={"link_hops": hops, "link_hop_count": 2})
    snap = compact_stages(type("R", (), {"stages": [st]})())
    assert snap["urls"]["link_hops"][0]["hosts"] == ["a.example", "b.example"]
    assert snap["urls"]["link_hop_count"] == 2
