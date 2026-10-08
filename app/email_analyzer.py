from __future__ import annotations

import re
from email.parser import Parser


def _auth_result(text: str, key: str) -> str:
    m = re.search(rf"\b{re.escape(key)}\s*=\s*([a-zA-Z0-9_-]+)", text, re.I)
    return m.group(1).lower() if m else "unknown"


def analyze_email_headers(raw_headers: str) -> dict:
    if not raw_headers.strip():
        raise ValueError("Email headers are required.")

    msg = Parser().parsestr(raw_headers)
    auth = " ".join(msg.get_all("Authentication-Results", []))
    spf = _auth_result(auth, "spf")
    dkim = _auth_result(auth, "dkim")
    dmarc = _auth_result(auth, "dmarc")

    from_addr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    received = msg.get_all("Received", [])

    risk = 0
    findings = []
    for label, value in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)):
        if value in {"fail", "softfail", "temperror", "permerror"}:
            risk += 25
            findings.append(f"{label} result is {value}.")
        elif value == "unknown":
            risk += 8
            findings.append(f"{label} result was not found in Authentication-Results.")

    if reply_to and from_addr and reply_to.lower() not in from_addr.lower():
        risk += 12
        findings.append("Reply-To differs from the visible From header; review it carefully.")

    if return_path and from_addr:
        m1 = re.search(r"@([^>\s]+)", from_addr)
        m2 = re.search(r"@([^>\s]+)", return_path)
        if m1 and m2 and m1.group(1).lower() != m2.group(1).lower():
            risk += 10
            findings.append("Return-Path domain differs from From domain.")

    if len(received) == 0:
        risk += 10
        findings.append("No Received headers were found.")

    risk = min(risk, 100)
    level = "low" if risk < 30 else "medium" if risk < 60 else "high"
    if not findings:
        findings.append("No obvious authentication-header problems were found.")

    return {
        "risk_score": risk,
        "risk": level,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "from": from_addr,
        "return_path": return_path,
        "reply_to": reply_to,
        "received_hops": len(received),
        "findings": findings,
        "note": "Header analysis is advisory and cannot prove whether a message is safe by itself.",
    }
