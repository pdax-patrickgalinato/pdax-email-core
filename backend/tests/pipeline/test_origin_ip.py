"""Originating MTA IP extraction, RDAP/OSINT enrichment, and LLM prompt facts."""
from email.mime.text import MIMEText

from workers.pipeline.origin_ip import classify_network, enrich, geo_lookup, stage_result, visual_score
from backend.parsed_email import ParsedEmail
from workers.pipeline.content_ai import _summarize_context
from workers.pipeline.stage_summary import compact_stages
from workers.pipeline.rdap_client import _sanitize_ip, ip_rdap_summary


def _raw(received, extra_headers=""):
    hops = received if isinstance(received, (list, tuple)) else [received]
    lines = [f"Received: {h}" for h in hops]
    if extra_headers:
        lines.append(extra_headers.rstrip("\n"))
    lines += ["From: vendor@gitex.example", "To: jan@pdax.ph", "Subject: test", "", "hello"]
    return "\r\n".join(lines).encode()


# Newest-first chain modeled on live Workspace mail (Trend TMES + Google).
_GITEX_HOPS = [
    "from mx.google.com (mx.google.com. [142.250.4.27]) by mail.pdax.ph with ESMTPS",
    "from tmes.trendmicro.com (unknown [18.208.22.101]) by mx.google.com with ESMTPS id abc",
    "from inpre01.tmes.trendmicro.com (unknown [192.168.1.10]) by tmes.trendmicro.com",
    "from mail02.mktg.gitex.com (unknown [129.145.22.244]) by inpre01.tmes.trendmicro.com with SMTP",
    "from c04snj602 (10.50.136.32) by mail02.mktg.gitex.com with ESMTP",
]


def test_originating_hop_skips_trend_and_private():
    pe = ParsedEmail(_raw(_GITEX_HOPS))
    hop = pe.originating_hop()
    assert hop["ip"] == "129.145.22.244"
    assert hop["hostname"] == "mail02.mktg.gitex.com"
    assert "18.208.22.101" in hop["all_public_ips"]
    assert "10.50.136.32" not in hop["all_public_ips"]
    assert "192.168.1.10" not in hop["all_public_ips"]


def test_originating_ips_keeps_every_public_hop():
    pe = ParsedEmail(_raw(_GITEX_HOPS))
    ips = pe.originating_ips()
    assert ips[0] == "142.250.4.27"
    assert "18.208.22.101" in ips
    assert "129.145.22.244" in ips
    assert "10.50.136.32" not in ips


def test_x_originating_ip_is_distinct():
    pe = ParsedEmail(_raw(
        "from smtp.sendgrid.net (unknown [167.89.1.2]) by mx.google.com with ESMTPS",
        extra_headers="X-Originating-IP: [8.8.4.4]",
    ))
    hop = pe.originating_hop()
    assert hop["ip"] == "167.89.1.2"
    assert hop["x_originating_ip"] == "8.8.4.4"


def test_x_originating_ip_alone():
    msg = MIMEText("hi")
    msg["From"] = "a@b.com"
    msg["X-Originating-IP"] = "[8.8.8.8]"
    pe = ParsedEmail(msg.as_bytes())
    hop = pe.originating_hop()
    assert hop["ip"] == "8.8.8.8"


def test_no_public_hop():
    pe = ParsedEmail(_raw("from localhost (unknown [127.0.0.1]) by mx.internal"))
    assert pe.originating_hop() == {}
    assert pe.originating_ips() == []


def test_gemini_ip_search_is_cached(monkeypatch):
    from workers.pipeline import origin_ip as origin_mod
    origin_mod._SEARCH_CACHE.clear()
    calls = []

    def generate(prompt):
        calls.append(prompt)
        return "SendGrid cloud IP in the US."

    first = origin_mod._gemini_ip_search("1.2.3.4", "smtp.sendgrid.net", generate=generate)
    second = origin_mod._gemini_ip_search("1.2.3.4", "smtp.sendgrid.net", generate=generate)
    assert first == second == "SendGrid cloud IP in the US."
    assert len(calls) == 1


def test_enrich_rdap_and_search(monkeypatch):
    monkeypatch.setenv("SEG_RDAP_LOOKUP", "1")
    monkeypatch.setenv("SEG_ORIGIN_IP_SEARCH", "1")
    monkeypatch.setenv("SEG_GEMINI_API_KEY", "test-key")
    hop = {"ip": "129.145.22.244", "hostname": "mail02.mktg.gitex.com", "x_originating_ip": ""}

    def rdap_get(url):
        assert "rdap.org/ip/129.145.22.244" in url
        return 200, {
            "name": "ORACLE-CLOUD",
            "country": "US",
            "type": "ALLOCATED",
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Oracle Cloud"]]],
            }],
        }

    facts = enrich(hop, rdap_get=rdap_get, search_fn=lambda ip, host: f"{host} is Oracle Cloud IaaS")
    assert facts["org"] == "Oracle Cloud"
    assert facts["country"] == "US"
    assert facts["network_role"] == "cloud_hosting"
    assert facts["hosting"] is True
    assert facts["vpn"] is False
    assert facts["suspicion"] == "none"
    assert facts["search_used"] is True
    assert "Oracle Cloud IaaS" in facts["search_summary"]
    assert "129.145.22.244" in facts["summary"]
    st = stage_result(facts)
    assert st.stage == "origin_ip"
    assert st.sub_score == visual_score(facts) == 0.0
    assert any(f.startswith("origin_ip:129.145.22.244") for f in st.red_flags)
    assert "origin_ip_search" in st.red_flags
    assert "origin_ip_hosting" in st.red_flags


def test_enrich_without_network_still_has_ip(monkeypatch):
    monkeypatch.setenv("SEG_RDAP_LOOKUP", "0")
    monkeypatch.setenv("SEG_ORIGIN_IP_SEARCH", "0")
    facts = enrich({"ip": "1.2.3.4", "hostname": "mail.example.com"})
    assert facts["ip"] == "1.2.3.4"
    assert facts["search_used"] is False
    assert facts["org"] == ""


def test_sanitize_ip_rejects_private_and_junk():
    assert _sanitize_ip("8.8.8.8") == "8.8.8.8"
    assert _sanitize_ip("127.0.0.1") is None
    assert _sanitize_ip("10.0.0.1") is None
    assert _sanitize_ip("8.8.8.8/../admin") is None
    assert _sanitize_ip("not-an-ip") is None


def test_ip_rdap_summary_parses_network():
    http = lambda url: (200, {"name": "NET-1", "country": "PH", "type": "ASSIGNED"})
    rec = ip_rdap_summary("1.2.3.4", http_get=http)
    assert rec["name"] == "NET-1"
    assert rec["country"] == "PH"


def test_ip_rdap_summary_skips_private():
    assert ip_rdap_summary("10.1.1.1", http_get=lambda url: (200, {"name": "nope"})) is None


def test_geo_lookup_parses_ip_api():
    def http(url):
        assert "ip-api.com/json/8.8.8.8" in url
        return 200, {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "regionName": "Virginia",
            "city": "Ashburn",
            "lat": 39.04,
            "lon": -77.49,
            "isp": "Google LLC",
            "org": "Google Public DNS",
            "as": "AS15169 Google LLC",
            "asname": "GOOGLE",
            "proxy": False,
            "hosting": False,
            "mobile": False,
        }
    geo = geo_lookup("8.8.8.8", http_get=http)
    assert geo["city"] == "Ashburn"
    assert geo["isp"] == "Google LLC"
    assert geo["asn"] == "AS15169"
    assert geo["country"] == "US"
    assert geo["lat"] == 39.04
    assert geo["lon"] == -77.49


def test_classify_vpn_is_high_suspicion():
    out = classify_network({
        "isp": "M247 Ltd", "org": "NordVPN", "country": "RO",
        "country_name": "Romania", "city": "Bucharest", "proxy": True,
    }, "finance.pdax.ph")
    assert out["vpn"] is True
    assert out["network_role"] == "vpn_proxy"
    assert out["suspicion"] == "high"
    assert out["geo_mismatch"] is True


def test_classify_geo_mismatch_residential():
    out = classify_network({
        "isp": "MTN Nigeria", "org": "MTN", "country": "NG",
        "country_name": "Nigeria", "city": "Lagos",
    }, "vendor.ph")
    assert out["network_role"] == "isp"
    assert out["geo_mismatch"] is True
    assert out["suspicion"] == "elevated"


def test_classify_cloud_hosting_is_informational_not_a_finding():
    out = classify_network({
        "isp": "Oracle Cloud", "org": "Oracle Cloud", "country": "US",
        "country_name": "United States", "city": "Ashburn", "hosting": True,
    }, "gitex.example")
    assert out["network_role"] == "cloud_hosting"
    assert out["hosting"] is True
    assert out["vpn"] is False
    assert out["suspicion"] == "none"
    assert visual_score(out) == 0.0


def test_classify_cloud_hosting_geo_mismatch_still_elevated():
    out = classify_network({
        "isp": "DigitalOcean", "org": "DigitalOcean", "country": "NG",
        "country_name": "Nigeria", "city": "Lagos", "hosting": True,
    }, "vendor.ph")
    assert out["network_role"] == "cloud_hosting"
    assert out["geo_mismatch"] is True
    assert out["suspicion"] == "elevated"
    assert visual_score(out) == 30.0


def test_classify_google_esp_is_not_suspicious():
    out = classify_network({
        "isp": "Google LLC", "org": "Google LLC", "country": "US",
        "country_name": "United States", "city": "Mountain View",
    }, "gmail.com")
    assert out["network_role"] == "esp"
    assert out["vpn"] is False
    assert out["suspicion"] == "none"
    assert out["geo_mismatch"] is False


def test_classify_yahoo_hostname_is_esp_not_vpn():
    out = classify_network({
        "hostname": "sonic302-2.consmr.mail.bf2.yahoo.com",
    }, "yahoo.com")
    assert out["network_role"] == "esp"
    assert out["vpn"] is False
    assert out["hosting"] is False


def test_classify_yahoo_ipapi_hosting_flag_is_still_esp():
    out = classify_network({
        "hostname": "sonic302-2.consmr.mail.bf2.yahoo.com",
        "isp": "Oath Holdings Inc.",
        "org": "Oath Holdings Inc",
        "as_name": "YAHOO-BF1",
        "country": "US",
        "country_name": "United States",
        "city": "Lockport",
        "hosting": True,
        "proxy": False,
    }, "yahoo.com")
    assert out["network_role"] == "esp"
    assert out["vpn"] is False
    assert out["hosting"] is False
    assert out["suspicion"] == "none"


def test_enrich_geo_and_isp(monkeypatch):
    monkeypatch.setenv("SEG_RDAP_LOOKUP", "0")
    hop = {"ip": "1.2.3.4", "hostname": "mail.example.ph"}

    def geo_get(url):
        return 200, {
            "status": "success",
            "country": "Philippines",
            "countryCode": "PH",
            "regionName": "Metro Manila",
            "city": "Makati",
            "isp": "PLDT",
            "org": "PLDT",
            "as": "AS9299 Philippine Long Distance Telephone",
            "asname": "IPG",
            "proxy": False,
            "hosting": False,
        }

    facts = enrich(hop, geo_get=geo_get, sender_domain="example.ph")
    assert facts["city"] == "Makati"
    assert facts["isp"] == "PLDT"
    assert facts["asn"] == "AS9299"
    assert facts["network_role"] == "isp"
    assert facts["vpn"] is False
    assert facts["geo_mismatch"] is False
    assert facts["suspicion"] == "none"
    st = stage_result(facts)
    assert any(f.startswith("origin_ip_geo:PH") for f in st.red_flags)
    assert any(f.startswith("origin_ip_isp:PLDT") for f in st.red_flags)


def test_summarize_context_includes_origin_ip():
    summary = _summarize_context({
        "origin_ip": {
            "ip": "129.145.22.244",
            "hostname": "mail02.mktg.gitex.com",
            "org": "Oracle Cloud",
            "country": "US",
            "city": "Ashburn",
            "isp": "Oracle Cloud",
            "asn": "AS31898",
            "network_role_label": "Cloud / VPS hosting",
            "hosting": True,
            "suspicion": "elevated",
            "suspicion_reason": "origin is a cloud/VPS network",
            "search_summary": "Oracle Cloud infrastructure in Ashburn.",
        }
    })
    assert "Originating mail IP" in summary
    assert "129.145.22.244" in summary
    assert "not a verdict" in summary
    assert "Ashburn" in summary
    assert "Oracle Cloud" in summary
    assert "VPN/proxy" not in summary or "Cloud / VPS" in summary
    assert "Oracle Cloud infrastructure" in summary


def test_compact_stages_keeps_origin_ip_extras():
    st = stage_result({
        "ip": "1.2.3.4", "hostname": "mta.example", "org": "Example ISP",
        "country": "PH", "city": "Makati", "isp": "PLDT", "asn": "AS9299",
        "lat": 14.55, "lon": 121.03,
        "search_summary": "Residential ISP.", "search_used": True,
        "summary": "1.2.3.4 (mta.example) — Makati, PH",
        "x_originating_ip": "", "network_role": "isp",
        "network_role_label": "ISP (residential or business)",
        "vpn": False, "hosting": False, "geo_mismatch": False,
        "suspicion": "none", "suspicion_reason": "conventional ISP allocation",
    })
    snap = compact_stages(type("R", (), {"stages": [st]})())
    assert snap["origin_ip"]["ip"] == "1.2.3.4"
    assert snap["origin_ip"]["hostname"] == "mta.example"
    assert snap["origin_ip"]["city"] == "Makati"
    assert snap["origin_ip"]["isp"] == "PLDT"
    assert snap["origin_ip"]["lat"] == 14.55
    assert snap["origin_ip"]["lon"] == 121.03
    assert snap["origin_ip"]["search_summary"] == "Residential ISP."
