from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlparse

import dns.reversename
import dns.resolver


def _host(value: str) -> str:
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    host = urlparse(value).hostname
    if not host:
        raise ValueError("Invalid domain or URL.")
    return host.rstrip(".")


def _query(name: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, record_type, lifetime=4)
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


def _lookup(host: str) -> dict:
    a = _query(host, "A")
    aaaa = _query(host, "AAAA")
    txt = _query(host, "TXT")
    mx = _query(host, "MX")
    ns = _query(host, "NS")
    caa = _query(host, "CAA")
    dnskey = _query(host, "DNSKEY")
    spf = [x for x in txt if x.lower().startswith("v=spf1")]
    dmarc = _query(f"_dmarc.{host}", "TXT")

    ptr = []
    for ip in a[:3]:
        try:
            ipaddress.ip_address(ip)
            rev = dns.reversename.from_address(ip)
            ptr.extend(_query(str(rev), "PTR"))
        except Exception:
            pass

    mail_security_score = 0
    if spf:
        mail_security_score += 35
    if dmarc:
        mail_security_score += 45
    if mx:
        mail_security_score += 20

    return {
        "host": host,
        "a": a,
        "aaaa": aaaa,
        "mx": mx,
        "ns": ns,
        "txt": txt,
        "spf": spf,
        "dmarc": dmarc,
        "caa": caa,
        "dnskey": dnskey,
        "dnssec_indicator": bool(dnskey),
        "ptr": ptr,
        "mail_security_score": mail_security_score,
    }


async def domain_intelligence(value: str) -> dict:
    host = _host(value)
    return await asyncio.to_thread(_lookup, host)
