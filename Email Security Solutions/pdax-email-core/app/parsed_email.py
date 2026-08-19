"""Thin wrapper over the stdlib email parser so every stage sees a consistent
view. Pure stdlib — runs anywhere."""
from __future__ import annotations

import email
import hashlib
import ipaddress
import re
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr, getaddresses
from html.parser import HTMLParser
from typing import Optional

from .domainutils import registrable_domain

_URL_RE = re.compile(r'(?:https?|ftps?)://[^\s"\'<>)\]]+', re.IGNORECASE)
_BRACKETED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
_AUTH_SENDER_RE = re.compile(r"Authenticated sender:\s*([\w.+-]+@[\w.-]+\.\w+)", re.I)
_BODY_EMAIL_RE = re.compile(r'\b([\w.+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b')


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Private/loopback/link-local/reserved hops are internal infrastructure
    # noise (a mail gateway's own relay chain), not attacker-controlled
    # indicators worth handing to an analyst or a blocklist.
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast)


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []   # (href, anchor_text)
        self.originalsrc_links: list[str] = []   # Outlook Safe Links original URLs
        self._href: Optional[str] = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attr_dict = dict(attrs)
            self._href = attr_dict.get("href")
            self._text = []
            orig = attr_dict.get("originalsrc", "")
            if orig and orig.lower().startswith(("http://", "https://")):
                self.originalsrc_links.append(orig)

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


_BEACON_ATTRS = ("src", "background", "data-src", "poster")
_SKIP_SCHEMES = ("cid:", "data:", "blob:", "#", "javascript:")


class _BeaconExtractor(HTMLParser):
    """Extracts resource-loading URLs from HTML attributes — tracking pixels/beacons."""

    def __init__(self) -> None:
        super().__init__()
        self.beacons: list[dict] = []   # {url, tag, attr}

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        for attr_name in _BEACON_ATTRS:
            val = (attr_dict.get(attr_name) or "").strip()
            if not val:
                continue
            low = val.lower()
            if not (low.startswith("http://") or low.startswith("https://")):
                continue
            if any(low.startswith(s) for s in _SKIP_SCHEMES):
                continue
            self.beacons.append({"url": val, "tag": tag, "attr": attr_name})


class Attachment:
    def __init__(self, filename: str, content_type: str, payload: bytes):
        self.filename = filename or ""
        self.content_type = content_type or ""
        self.payload = payload or b""
        self.sha256 = hashlib.sha256(self.payload).hexdigest()
        self.size = len(self.payload)

    @property
    def extension(self) -> str:
        return self.filename.rsplit(".", 1)[-1].lower() if "." in self.filename else ""


class ParsedEmail:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.msg: Message = email.message_from_bytes(raw)

    def header(self, name: str, default: str = "") -> str:
        """Return a header, decoding any RFC 2047 MIME encoding.

        Important for detection, not just display: attackers base64-encode
        subjects (=?utf-8?b?...?=) specifically to slip past keyword matching.
        Decoding here means every downstream stage sees the real text.
        """
        raw = self.msg.get(name)
        if raw is None:
            return default
        try:
            return str(make_header(decode_header(raw)))
        except Exception:
            return raw

    # --- addresses -------------------------------------------------------
    @property
    def from_display(self) -> str:
        return parseaddr(self.header("From"))[0]

    @property
    def from_addr(self) -> str:
        return parseaddr(self.header("From"))[1].lower()

    @property
    def from_domain(self) -> str:
        addr = self.from_addr
        return addr.split("@", 1)[1] if "@" in addr else ""

    def _addr_domain(self, header: str) -> str:
        addr = parseaddr(self.header(header))[1].lower()
        return addr.split("@", 1)[1] if "@" in addr else ""

    @property
    def return_path_domain(self) -> str:
        return self._addr_domain("Return-Path")

    @property
    def reply_to_domain(self) -> str:
        return self._addr_domain("Reply-To")

    @property
    def message_id_domain(self) -> str:
        mid = self.header("Message-ID")
        m = re.search(r"@([^>]+)>", mid)
        return m.group(1).lower() if m else ""

    @property
    def to_addrs(self) -> list[str]:
        return [a.lower() for _, a in getaddresses([self.header("To")]) if a]

    # --- bodies ----------------------------------------------------------
    def _parts(self):
        if self.msg.is_multipart():
            yield from self.msg.walk()
        else:
            yield self.msg

    def text_body(self) -> str:
        chunks = []
        for part in self._parts():
            if part.get_content_type() == "text/plain":
                try:
                    chunks.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    chunks.append(payload.decode("utf-8", "replace"))
        return "\n".join(chunks)

    def html_body(self) -> str:
        chunks = []
        for part in self._parts():
            if part.get_content_type() == "text/html":
                try:
                    chunks.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    chunks.append(payload.decode("utf-8", "replace"))
        return "\n".join(chunks)

    # --- transport metadata (Received chain) ------------------------------
    def originating_ips(self) -> list[str]:
        """Public IPv4 addresses pulled from the Received header chain (mail
        transport hops, not visible in the body). Private/loopback/reserved
        hops — a mail gateway's own internal relay infrastructure — are
        filtered out; they're noise, not attacker-controlled indicators."""
        ips: set[str] = set()
        for received in self.msg.get_all("Received", []):
            for ip in _BRACKETED_IP_RE.findall(received):
                if _is_public_ip(ip):
                    ips.add(ip)
        return sorted(ips)

    def authenticated_relay_senders(self) -> list[str]:
        """Email addresses used to authenticate against a relay/SMTP host,
        e.g. "(Authenticated sender: info@transfer.example.com)" in a
        Received header — a real, pivotable IOC distinct from the visible
        From address (the relay account is often the actually-compromised
        or attacker-registered credential, not the spoofed display name)."""
        senders: set[str] = set()
        for received in self.msg.get_all("Received", []):
            senders.update(m.lower() for m in _AUTH_SENDER_RE.findall(received))
        return sorted(senders)

    # --- extracted artifacts --------------------------------------------
    def urls(self) -> list[str]:
        found: set[str] = set()
        found.update(_URL_RE.findall(self.text_body()))
        html = self.html_body()
        if html:
            found.update(_URL_RE.findall(html))
            ex = _LinkExtractor()
            try:
                ex.feed(html)
            except Exception:
                pass
            for href, _ in ex.links:
                low = href.lower()
                if low.startswith("http") or low.startswith("ftp"):
                    found.add(href)
            # Include Safe Links original URLs so the real destination is analyzed
            for orig in ex.originalsrc_links:
                found.add(orig)
        return sorted(found)

    def tracking_beacons(self) -> list[dict]:
        """External resource-loading URLs (tracking pixels/beacons) from the HTML body.
        Returns [{url, tag, attr}]. These load automatically when the email is opened."""
        html = self.html_body()
        if not html:
            return []
        ex = _BeaconExtractor()
        try:
            ex.feed(html)
        except Exception:
            pass
        return ex.beacons

    def safe_links_originals(self) -> list[str]:
        """Original URLs from Outlook Safe Links rewritten hrefs (originalsrc attribute)."""
        html = self.html_body()
        if not html:
            return []
        ex = _LinkExtractor()
        try:
            ex.feed(html)
        except Exception:
            pass
        return ex.originalsrc_links

    def body_email_addrs(self) -> list[str]:
        """Email addresses found in the message body (text + HTML), excluding From/To headers.
        These are often IOCs in phishing: spoofed contact addresses, attacker mailboxes."""
        found: set[str] = set()
        for text in (self.text_body(), self.html_body()):
            for addr in _BODY_EMAIL_RE.findall(text):
                found.add(addr.lower())
        # Remove legitimate envelope addresses — they're not "found in body" IOCs
        found.discard(self.from_addr)
        for addr in self.to_addrs:
            found.discard(addr)
        return sorted(found)

    def anchor_mismatches(self) -> list[dict]:
        """Links whose visible text names one domain but href points elsewhere —
        classic display-vs-target deception."""
        html = self.html_body()
        if not html:
            return []
        ex = _LinkExtractor()
        try:
            ex.feed(html)
        except Exception:
            return []
        out = []
        for href, text in ex.links:
            text_urls = _URL_RE.findall(text)
            if not href.lower().startswith("http") or not text_urls:
                continue
            href_dom = registrable_domain(re.sub(r"^https?://", "", href).split("/")[0])
            txt_dom = registrable_domain(re.sub(r"^https?://", "", text_urls[0]).split("/")[0])
            if href_dom and txt_dom and href_dom != txt_dom:
                out.append({"anchor_text_domain": txt_dom, "href_domain": href_dom, "href": href})
        return out

    def attachments(self) -> list[Attachment]:
        out = []
        for part in self._parts():
            disp = (part.get("Content-Disposition") or "").lower()
            filename = part.get_filename()
            if "attachment" in disp or filename:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                out.append(Attachment(filename or "", part.get_content_type(), payload))
        return out
