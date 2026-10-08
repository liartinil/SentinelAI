from __future__ import annotations

REMEDIATIONS = {
    "HSTS": ("medium", "Enable Strict-Transport-Security after HTTPS is working everywhere. Start with a conservative max-age, then increase it."),
    "Content-Security-Policy": ("high", "Deploy a Content-Security-Policy tailored to the site's real resource origins. Avoid unsafe-inline where possible."),
    "X-Content-Type-Options": ("low", "Add X-Content-Type-Options: nosniff."),
    "X-Frame-Options": ("medium", "Use CSP frame-ancestors and/or X-Frame-Options to reduce clickjacking exposure."),
    "Referrer-Policy": ("low", "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."),
    "Permissions-Policy": ("low", "Set Permissions-Policy to disable browser capabilities the site does not need."),
    "HTTPS": ("high", "Redirect all HTTP traffic to HTTPS and keep certificates valid."),
    "TLS Certificate": ("high", "Renew or fix the certificate chain before expiry and monitor certificate health."),
    "CORS": ("medium", "Restrict Access-Control-Allow-Origin to trusted origins for sensitive APIs; avoid broad wildcard policies with credentials."),
    "Mixed Content": ("high", "Serve every subresource over HTTPS and replace hard-coded http:// asset URLs."),
}


def build_remediation(scan: dict) -> dict:
    payload = scan.get("payload", {})
    recommendations = []
    for finding in payload.get("findings", []):
        if finding.get("status") == "pass":
            continue
        name = finding.get("name", "Finding")
        severity, fix = REMEDIATIONS.get(name, ("medium", "Review this finding and harden the affected configuration following vendor and OWASP guidance."))
        recommendations.append({
            "finding": name,
            "severity": severity,
            "evidence": finding.get("detail", "Review required"),
            "recommendation": fix,
        })

    order = {"high": 0, "medium": 1, "low": 2}
    recommendations.sort(key=lambda x: order.get(x["severity"], 9))
    return {
        "scan_id": scan["id"],
        "url": scan["url"],
        "score": scan["score"],
        "risk": scan["risk"],
        "recommendations": recommendations,
        "summary": "No remediation actions are currently suggested." if not recommendations else f"{len(recommendations)} remediation action(s) suggested, ordered by severity.",
        "mode": "local-rule-based-remediation",
    }
