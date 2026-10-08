from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", 12),
    "content-security-policy": ("Content-Security-Policy", 16),
    "x-content-type-options": ("X-Content-Type-Options", 8),
    "x-frame-options": ("X-Frame-Options", 8),
    "referrer-policy": ("Referrer-Policy", 8),
    "permissions-policy": ("Permissions-Policy", 8),
}

class UnsafeTargetError(ValueError):
    pass


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL is required.")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Invalid URL.")
    return url


async def _resolve_public_ips(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(None, lambda: socket.getaddrinfo(host, None))
    except socket.gaierror as exc:
        raise ValueError("Could not resolve the hostname.") from exc
    ips: list[str] = []
    for item in infos:
        ip = item[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise ValueError("No IP address was found for the hostname.")
    for ip in ips:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved or obj.is_multicast or obj.is_unspecified:
            raise UnsafeTargetError("Private, local, reserved, and special-use targets are blocked.")
    return ips


def _tls_info(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=4) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as sock:
            cert = sock.getpeercert()
            cipher = sock.cipher()
            version = sock.version()
    expires_raw = cert.get("notAfter")
    expires_at = None
    days_left = None
    if expires_raw:
        expires = datetime.strptime(expires_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        expires_at = expires.isoformat()
        days_left = (expires - datetime.now(timezone.utc)).days
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    return {
        "protocol": version,
        "cipher": cipher[0] if cipher else None,
        "expires_at": expires_at,
        "days_until_expiry": days_left,
        "subject_common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("commonName"),
    }


def _cookie_checks(headers: httpx.Headers) -> dict:
    cookies = headers.get_list("set-cookie")
    if not cookies:
        return {"count": 0, "secure": None, "httponly": None, "samesite": None}
    lower = [c.lower() for c in cookies]
    return {
        "count": len(cookies),
        "secure": all("secure" in c for c in lower),
        "httponly": all("httponly" in c for c in lower),
        "samesite": all("samesite" in c for c in lower),
    }


def _mixed_content(html: str, final_url: str) -> int:
    if not final_url.startswith("https://"):
        return 0
    refs = re.findall(r'''(?:src|href)=["'](http://[^"']+)''', html, flags=re.I)
    return len(refs)


async def scan_website(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    ips = await _resolve_public_ips(host)

    headers = {"User-Agent": "SentinelAI-DefensiveScanner/4.0", "Accept": "text/html,application/xhtml+xml"}
    async with httpx.AsyncClient(follow_redirects=True, timeout=httpx.Timeout(7.0, connect=4.0), headers=headers) as client:
        response = await client.get(normalized)
        redirect_chain = [{"status": r.status_code, "url": str(r.url)} for r in response.history]
        redirect_chain.append({"status": response.status_code, "url": str(response.url)})
        base = f"{response.url.scheme}://{response.url.host}"
        robots_resp, sitemap_resp = await asyncio.gather(
            client.get(urljoin(base, "/robots.txt")),
            client.get(urljoin(base, "/sitemap.xml")),
            return_exceptions=True,
        )

    score = 18
    findings = []
    response_headers = {k.lower(): v for k, v in response.headers.items()}

    for key, (label, points) in SECURITY_HEADERS.items():
        present = key in response_headers
        findings.append({"name": label, "status": "pass" if present else "warning", "detail": "Present" if present else "Missing"})
        if present:
            score += points

    https = response.url.scheme == "https"
    findings.append({"name": "HTTPS", "status": "pass" if https else "warning", "detail": "Enabled" if https else "Not enabled on final URL"})
    if https:
        score += 10

    cookies = _cookie_checks(response.headers)
    if cookies["count"]:
        if cookies["secure"]:
            score += 4
        if cookies["httponly"]:
            score += 3
        if cookies["samesite"]:
            score += 3

    tls = None
    if https:
        try:
            tls = await asyncio.to_thread(_tls_info, response.url.host)
            if tls.get("days_until_expiry") is not None and tls["days_until_expiry"] < 30:
                findings.append({"name": "TLS Certificate", "status": "warning", "detail": f"Expires in {tls['days_until_expiry']} days"})
            else:
                findings.append({"name": "TLS Certificate", "status": "pass", "detail": "Valid and not near expiry"})
                score += 5
        except Exception:
            findings.append({"name": "TLS Certificate", "status": "warning", "detail": "Could not inspect certificate details"})

    cors = response_headers.get("access-control-allow-origin")
    if cors == "*":
        findings.append({"name": "CORS", "status": "warning", "detail": "Wildcard origin detected"})
    else:
        findings.append({"name": "CORS", "status": "pass", "detail": "No wildcard origin observed"})
        score += 3

    server = response.headers.get("server")
    if server:
        findings.append({"name": "Server Header", "status": "warning", "detail": f"Exposed: {server}"})
    else:
        findings.append({"name": "Server Header", "status": "pass", "detail": "Not exposed"})
        score += 2

    html = response.text[:1_000_000] if "text/html" in response.headers.get("content-type", "").lower() else ""
    mixed = _mixed_content(html, str(response.url))
    findings.append({"name": "Mixed Content", "status": "warning" if mixed else "pass", "detail": f"{mixed} insecure resource(s)" if mixed else "None detected"})
    if not mixed:
        score += 3

    robots_ok = not isinstance(robots_resp, Exception) and robots_resp.status_code < 400
    sitemap_ok = not isinstance(sitemap_resp, Exception) and sitemap_resp.status_code < 400

    score = max(0, min(score, 100))
    risk = "low" if score >= 80 else "medium" if score >= 55 else "high"
    now = datetime.now(timezone.utc).isoformat()

    return {
        "requested_url": url,
        "final_url": str(response.url),
        "hostname": response.url.host,
        "resolved_ips": ips,
        "http_status": response.status_code,
        "server": server,
        "security_score": score,
        "risk": risk,
        "findings": findings,
        "cookies": cookies,
        "tls": tls,
        "redirect_chain": redirect_chain,
        "robots_txt": robots_ok,
        "sitemap_xml": sitemap_ok,
        "cors_allow_origin": cors,
        "mixed_content_count": mixed,
        "scanned_at": now,
        "scope_note": "Passive configuration scan only. No exploitation, brute forcing, payload injection, or port scanning is performed.",
    }
