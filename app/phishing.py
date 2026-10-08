from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "banking", "signin", "password", "confirm", "wallet", "invoice",
    "gift", "bonus", "free", "support", "security", "unlock"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
}


def _normalize(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if "://" not in url:
        return "https://" + url
    return url


def analyze_phishing(url: str) -> dict:
    raw = url.strip()
    normalized = _normalize(raw)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()

    score = 0
    reasons: list[str] = []

    if not host:
        return {
            "url": raw,
            "risk_score": 100,
            "risk": "high",
            "reasons": ["Invalid or incomplete URL."]
        }

    if len(raw) > 75:
        score += 15
        reasons.append("The URL is unusually long.")

    if raw.count("-") >= 3:
        score += 10
        reasons.append("The URL contains many hyphens.")

    if host.count(".") >= 3:
        score += 12
        reasons.append("The hostname contains many subdomains.")

    if "@" in raw:
        score += 20
        reasons.append("The URL contains an @ symbol, which can obscure the destination.")

    if parsed.scheme != "https":
        score += 12
        reasons.append("The URL is not using HTTPS.")

    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("The hostname is a raw IP address.")
    except ValueError:
        pass

    if host in SHORTENERS:
        score += 15
        reasons.append("The URL uses a link-shortening service.")

    tokens = set(re.split(r"[^a-z0-9]+", raw.lower()))
    suspicious_hits = sorted(tokens.intersection(SUSPICIOUS_WORDS))
    if suspicious_hits:
        add = min(25, len(suspicious_hits) * 5)
        score += add
        reasons.append("Suspicious keywords detected: " + ", ".join(suspicious_hits[:5]))

    # Punycode can be legitimate, but it deserves extra attention.
    if "xn--" in host:
        score += 15
        reasons.append("The hostname uses punycode/IDN encoding.")

    score = min(score, 100)
    risk = "low" if score < 30 else "medium" if score < 60 else "high"

    if not reasons:
        reasons.append("No strong phishing indicators were found by the heuristic model.")

    return {
        "url": raw,
        "normalized_url": normalized,
        "risk_score": score,
        "risk": risk,
        "reasons": reasons
    }
