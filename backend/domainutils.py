"""Offline domain helpers. No network, no tldextract (which fetches the PSL
on first use). A small multi-label TLD set covers the cases PDAX cares about;
extend as needed."""
from __future__ import annotations

# Registrable-domain resolution for the common multi-label public suffixes we
# actually see. Not the full PSL — deliberately small and offline.
MULTI_LABEL_TLDS = {
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "com.sg", "com.hk", "co.jp", "com.my",
}

HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s", "|": "l",
}


def registrable_domain(domain: str) -> str:
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return domain
    labels = domain.split(".")
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:]) if len(labels) >= 3 else ""
    if last_two in MULTI_LABEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def normalize_confusables(s: str) -> str:
    s = (s or "").lower()
    out = "".join(HOMOGLYPHS.get(ch, ch) for ch in s)
    out = out.replace("rn", "m").replace("vv", "w")
    return out


def levenshtein(a: str, b: str, cap: int = 2) -> int:
    """Bounded edit distance. Returns cap+1 if distance exceeds cap."""
    la, lb = len(a), len(b)
    if abs(la - lb) > cap:
        return cap + 1
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        ai = a[i - 1]
        best = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            best = min(best, cur[j])
        if best > cap:
            return cap + 1
        prev = cur
    return prev[lb]
