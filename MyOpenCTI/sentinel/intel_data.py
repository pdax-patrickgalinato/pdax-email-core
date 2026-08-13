"""Industry profiles, ATT&CK/IOC signals, and threat-actor alias tables."""
from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

from sentinel.config import (
    IND_FINTECH, IND_VASP, IND_BANKING, IND_HEALTH, IND_RETAIL, IND_CI, IND_SAAS,
    IND_MFG, IND_GOV, IND_ENERGY, IND_TELCO, IND_EDU, IND_PH, IND_GENERAL,
)

INDUSTRY_PROFILES: Dict[str, List[str]] = {
    IND_FINTECH: [
        "fintech", "banking trojan", "payment", "card", "swift", "pci dss", "atm",
        "mobile banking", "account takeover", "fraud", "money laundering", "kyc",
        "e-wallet", "remittance", "open banking", "api abuse", "otp bypass",
    ],
    IND_VASP: [
        "crypto", "cryptocurrency", "exchange", "wallet", "seed phrase", "private key",
        "defi", "bridge", "smart contract", "drainer", "cold storage", "custody",
        "blockchain", "web3", "bitcoin", "ethereum", "lazarus", "dprk", "north korea",
        "virtual asset", "stablecoin", "aml", "travel rule",
    ],
    IND_BANKING: [
        "bank", "banking", "financial institution", "swift", "core banking", "atm",
        "wire transfer", "fraud", "pci dss", "trading", "brokerage", "insider trading",
        "regulator", "basel", "banking trojan",
    ],
    IND_HEALTH: [
        "healthcare", "hospital", "hipaa", "phi", "ehr", "emr", "patient", "medical device",
        "clinic", "pharma", "health system", "hl7", "dicom", "telehealth",
    ],
    IND_RETAIL: [
        "retail", "e-commerce", "magecart", "point of sale", "pos malware", "skimmer",
        "checkout", "loyalty", "gift card", "shopify", "magento", "card-not-present",
    ],
    IND_CI: [
        "ics", "scada", "plc", "ot network", "modbus", "dnp3", "operational technology",
        "critical infrastructure", "water utility", "power grid", "purdue", "hmi",
        "safety instrumented", "rockwell", "siemens s7",
    ],
    IND_SAAS: [
        "saas", "api", "oauth", "multi-tenant", "kubernetes", "container", "ci/cd",
        "supply chain", "npm", "pypi", "github actions", "iam", "s3 bucket", "serverless",
        "terraform", "devops", "sso", "saml",
    ],
    IND_MFG: [
        "manufacturing", "erp", "sap", "mes", "plc", "factory", "logistics", "shipping",
        "supply chain", "warehouse", "industrial",
    ],
    IND_GOV: [
        "government", "public sector", "state-sponsored", "espionage", "apt", "election",
        "defence", "defense", "municipal", "federal agency", "diplomatic",
    ],
    IND_ENERGY: [
        "energy", "oil and gas", "pipeline", "power grid", "utility", "substation",
        "renewable", "nuclear", "smart meter",
    ],
    IND_TELCO: [
        "telecom", "telecommunications", "5g", "sim swap", "ss7", "diameter", "isp",
        "mobile network", "roaming", "salt typhoon",
    ],
    IND_EDU: [
        "university", "education", "student data", "ferpa", "research institution",
        "academic", "school district",
    ],
    IND_PH: [
        "philippines", "philippine", "gcash", "paymaya", "maya", "e-wallet", "pesonet",
        "instapay", "unionbank", "bdo", "bpi", "metrobank", "landbank", "philsys",
        "national id", "fake id", "counterfeit id", "sim registration", "sim swap",
        "investment scam", "online lending app", "lending app", "pig butchering",
        "romance scam", "money mule", "phishing", "smishing", "vishing",
        "bangko sentral", "bsp", "national privacy commission", "data privacy act",
        "anti-cybercrime", "pnp", "pdax", "coins.ph", "crypto scam",
    ],
    IND_GENERAL: [],
}

# Signal phrases that indicate real, imminent operational risk.
EXPLOIT_SIGNALS = [
    "actively exploited", "exploited in the wild", "under active exploitation",
    "known exploited", "kev catalog", "added to kev", "in-the-wild exploitation",
    "zero-day", "0-day", "public exploit", "proof-of-concept exploit", "poc exploit",
    "exploit code available", "mass exploitation", "emergency patch", "out-of-band patch",
]

SEVERITY_SIGNALS = [
    "unauthenticated", "remote code execution", "pre-auth", "privilege escalation",
    "authentication bypass", "critical severity", "cvss 10", "cvss 9", "wormable",
    "sandbox escape", "kernel", "supply chain compromise", "backdoor",
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CVSS_RE = re.compile(r"CVSS[^0-9]{0,12}(\d{1,2}(?:\.\d)?)", re.IGNORECASE)

# MITRE ATT&CK technique IDs, e.g. T1566 or T1566.001.
MITRE_TECHNIQUE_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")

# MITRE ATT&CK tactics — the "TTPs" a story is reporting on. (match phrase, display name)
MITRE_TACTICS = [
    ("reconnaissance", "Reconnaissance"), ("resource development", "Resource Development"),
    ("initial access", "Initial Access"), ("execution", "Execution"),
    ("persistence", "Persistence"), ("privilege escalation", "Privilege Escalation"),
    ("defense evasion", "Defense Evasion"), ("credential access", "Credential Access"),
    ("discovery", "Discovery"), ("lateral movement", "Lateral Movement"),
    ("collection", "Collection"), ("command and control", "Command and Control"),
    ("exfiltration", "Exfiltration"), ("impact", "Impact"),
]

# Indicator-of-compromise patterns. Hash lengths don't overlap thanks to \b on both ends.
IOC_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("SHA-256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("SHA-1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("MD5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("IPv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")),
    ("Defanged indicator", re.compile(r"\b[a-zA-Z0-9-]+(?:\[\.\][a-zA-Z0-9-]+)+\b")),
    ("URL", re.compile(r"\bhxxps?://[^\s<>\"')]+|\bhttps?://[^\s<>\"')]+", re.IGNORECASE)),
]

# Phrases that point to a concrete remediation action rather than just background reading.
CTA_SIGNALS = [
    "patch immediately", "apply the patch", "update to version", "upgrade to version",
    "apply mitigation", "apply the following mitigations", "apply the workaround",
    "rotate credentials", "rotate keys", "reset passwords", "enable mfa",
    "enable multi-factor", "block the following", "block these indicators",
    "isolate affected", "disable the affected", "review logs for", "hunt for",
    "restrict access", "no patch is available", "monitor for",
]

# Canonical name → aliases. Longer aliases are matched first so "APT 38" beats "APT".
THREAT_ACTOR_ALIASES: Dict[str, Tuple[str, ...]] = {
    "Lazarus Group": ("lazarus group", "lazarus", "apt38", "apt 38", "bluenoroff",
                      "hidden cobra", "guardians of peace"),
    "Andariel": ("andariel", "silent chollima"),
    "APT29 (Cozy Bear)": ("apt29", "apt 29", "cozy bear", "cozybear", "the dukes", "nobelium", "midnight blizzard"),
    "APT28 (Fancy Bear)": ("apt28", "apt 28", "fancy bear", "fancybear", "sofacy", "sednit", "forest blizzard"),
    "APT41": ("apt41", "apt 41", "double dragon", "barium", "winnti group"),
    "APT40": ("apt40", "apt 40", "leviathan", "gadolinium"),
    "Volt Typhoon": ("volt typhoon", "bronze silhouette", "vanguard panda"),
    "Salt Typhoon": ("salt typhoon", "ghostEmperor", "ghost emperor"),
    "Mustang Panda": ("mustang panda", "bronze president", "reddelta", "red delta"),
    "FIN7": ("fin7", "carbanak", "carbon spider"),
    "FIN11": ("fin11",),
    "Scattered Spider": ("scattered spider", "unc3944", "0ktapus", "oktapus"),
    "Lapsus$": ("lapsus$", "lapsus", "dev-0537"),
    "Sandworm": ("sandworm", "voodoo bear", "iridium", "seashell blizzard"),
    "Turla": ("turla", "uroburos", "venomous bear"),
    "Kimsuky": ("kimsuky", "velvet chollima", "black bansa"),
    "TA505": ("ta505", "graceful spider"),
    "Evil Corp": ("evil corp", "indrik spider", "unc2165"),
    "AlphV / BlackCat": ("alphv", "blackcat ransomware", "blackcat", "noberus"),
    "LockBit": ("lockbit", "lockbit gang"),
    "Cl0p": ("cl0p", "clop ransomware", "clop gang", "ta505 clop"),
    "Akira": ("akira ransomware", "akira gang"),
    "REvil / Sodinokibi": ("revil", "sodinokibi", "sodin"),
    "Conti": ("conti ransomware", "conti gang", "wizard spider"),
    "Play Ransomware": ("play ransomware", "play crypt"),
    "Black Basta": ("black basta",),
    "Royal / BlackSuit": ("royal ransomware", "blacksuit"),
    "Qilin / Agenda": ("qilin ransomware", "agenda ransomware"),
    "UNC2452 / SolarWinds": ("unc2452", "dark halo", "solarwinds attackers"),
}

MALWARE_ALIASES: Dict[str, Tuple[str, ...]] = {
    "Emotet": ("emotet",),
    "QakBot / Qbot": ("qakbot", "qbot", "pinkslipbot"),
    "TrickBot": ("trickbot", "trick bot"),
    "IcedID": ("icedid", "bokbot"),
    "Cobalt Strike": ("cobalt strike", "cobaltstrike"),
    "Mimikatz": ("mimikatz",),
    "Agent Tesla": ("agent tesla", "agentesla"),
    "RedLine Stealer": ("redline stealer", "redline"),
    "Raccoon Stealer": ("raccoon stealer", "raccoon"),
    "Vidar": ("vidar stealer", "vidar"),
    "Lumma Stealer": ("lumma stealer", "lumma"),
    "FormBook": ("formbook", "xloader"),
    "AsyncRAT": ("asyncrat", "async rat"),
    "Remcos": ("remcos",),
    "PlugX": ("plugx", "korplug"),
    "ShadowPad": ("shadowpad",),
    "QUIETEXIT": ("quietexit",),
    "Truebot": ("truebot",),
    "SystemBC": ("systembc", "socks5 systembc"),
    "Sliver": ("sliver c2", "sliver framework"),
    "Brute Ratel": ("brute ratel", "brc4"),
    "Metasploit": ("metasploit", "meterpreter"),
    "SocGholish": ("socgholish", "fakeupdates"),
    "Gootloader": ("gootloader",),
    "Bumblebee": ("bumblebee loader", "bumblebee"),
    "Pikabot": ("pikabot",),
    "DarkGate": ("darkgate",),
    "Latrodectus": ("latrodectus", "icedid successor"),
}

RANSOMWARE_ALIASES: Dict[str, Tuple[str, ...]] = {
    "LockBit": ("lockbit 3.0", "lockbit 2.0", "lockbit"),
    "Cl0p": ("cl0p", "clop"),
    "Akira": ("akira",),
    "BlackCat / ALPHV": ("blackcat", "alphv"),
    "REvil": ("revil", "sodinokibi"),
    "Conti": ("conti",),
    "Black Basta": ("black basta",),
    "Play": ("play ransomware",),
    "Royal": ("royal ransomware",),
    "BlackSuit": ("blacksuit",),
    "Qilin": ("qilin", "agenda ransomware"),
    "8Base": ("8base",),
    "Medusa": ("medusa ransomware", "medusa locker"),
    "RansomHub": ("ransomhub",),
    "Hunters International": ("hunters international",),
    "BianLian": ("bianlian",),
    "Rhysida": ("rhysida",),
    "Cactus": ("cactus ransomware",),
    "Phobos": ("phobos ransomware",),
    "STOP / Djvu": ("stop ransomware", "djvu"),
}


def _compile_alias_table(table: Dict[str, Tuple[str, ...]]) -> List[Tuple[str, re.Pattern]]:
    """Flatten alias table into (canonical, pattern) pairs sorted by alias length desc."""
    pairs: List[Tuple[str, str]] = []
    for canonical, aliases in table.items():
        for alias in aliases:
            pairs.append((canonical, alias))
    pairs.sort(key=lambda p: len(p[1]), reverse=True)
    compiled: List[Tuple[str, re.Pattern]] = []
    for canonical, alias in pairs:
        escaped = re.escape(alias)
        # Word-ish boundaries; allow $ at end of Lapsus$ etc.
        pat = re.compile(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", re.IGNORECASE)
        compiled.append((canonical, pat))
    return compiled


THREAT_ACTOR_COMPILED = _compile_alias_table(THREAT_ACTOR_ALIASES)
MALWARE_COMPILED = _compile_alias_table(MALWARE_ALIASES)
RANSOMWARE_COMPILED = _compile_alias_table(RANSOMWARE_ALIASES)


def _match_aliases(text: str, compiled: List[Tuple[str, re.Pattern]]) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()
    for canonical, pat in compiled:
        if canonical in seen:
            continue
        if pat.search(text):
            seen.add(canonical)
            found.append(canonical)
    return found

