from __future__ import annotations

import re

KB = [
    (
        ["sql injection", "sqli"],
        "SQL injection happens when untrusted input is mixed into database queries. Defend with parameterized queries, safe ORM APIs, input validation, least-privilege database accounts, and security testing."
    ),
    (
        ["xss", "cross site scripting", "cross-site scripting"],
        "Cross-site scripting occurs when untrusted content is rendered as executable browser code. Defend with output encoding, safe templating, sanitization where needed, Content-Security-Policy, and avoiding dangerous DOM APIs."
    ),
    (
        ["csrf", "cross site request forgery", "cross-site request forgery"],
        "CSRF tricks an authenticated browser into sending an unwanted request. Use SameSite cookies, anti-CSRF tokens for state-changing actions, origin checks, and avoid changing state through GET requests."
    ),
    (
        ["csp", "content security policy"],
        "Content-Security-Policy limits where scripts, styles, frames, and other resources may load from. A well-designed CSP can reduce XSS impact and should be tested carefully before enforcing."
    ),
    (
        ["hsts", "strict transport security"],
        "HSTS tells browsers to use HTTPS only for a site. Enable it only after HTTPS works correctly everywhere, and consider includeSubDomains carefully."
    ),
    (
        ["password"],
        "For passwords, prioritize uniqueness and length. A password manager plus long randomly generated passwords is stronger than short complex patterns reused across accounts."
    ),
    (
        ["phishing"],
        "Phishing detection should combine URL/domain reputation, authentication signals, message context, user awareness, and safe browsing controls. A single heuristic should never be treated as proof."
    ),
    (
        ["security headers", "headers"],
        "Useful defensive headers include Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, and frame protections such as CSP frame-ancestors."
    ),
    (
        ["https", "tls", "ssl"],
        "HTTPS protects data in transit and authenticates the server through certificates. Keep TLS libraries current, redirect HTTP to HTTPS, monitor certificate expiry, and disable obsolete protocol versions."
    ),
]


def answer(question: str) -> dict:
    q = re.sub(r"\s+", " ", question.strip().lower())
    for keywords, response in KB:
        if any(k in q for k in keywords):
            return {"answer": response, "mode": "local-knowledge-base"}

    return {
        "answer": (
            "I can help with defensive cybersecurity topics such as phishing, HTTPS/TLS, "
            "security headers, password hygiene, XSS, SQL injection prevention, CSRF, "
            "and secure web-development practices. Ask about a specific risk or protection."
        ),
        "mode": "local-knowledge-base"
    }
