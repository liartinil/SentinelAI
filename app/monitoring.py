from __future__ import annotations

import time
from datetime import datetime, timezone

import httpx

from .scanner import _resolve_public_ips, normalize_url


async def monitor_url(url: str) -> dict:
    target = normalize_url(url)
    host = httpx.URL(target).host
    if not host:
        raise ValueError("Invalid URL")
    await _resolve_public_ips(host)

    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(8.0, connect=4.0),
            headers={"User-Agent": "SentinelAI-UptimeMonitor/1.0"},
        ) as client:
            response = await client.get(target)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "online": 200 <= response.status_code < 500,
            "http_status": response.status_code,
            "response_ms": elapsed_ms,
            "final_url": str(response.url),
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "error": None,
        }
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return {
            "online": False,
            "http_status": None,
            "response_ms": elapsed_ms,
            "final_url": target,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        }
