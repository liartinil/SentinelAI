from __future__ import annotations

import asyncio
import csv
import sqlite3
from io import BytesIO, StringIO
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

from .assistant import answer
from .auth import (
    change_password as auth_change_password,
    edit_profile as auth_edit_profile,
    login as auth_login,
    logout as auth_logout,
    register as auth_register,
    user_from_token,
)
from .database import (
    add_asset,
    add_notification,
    delete_asset,
    get_asset,
    get_due_assets,
    get_history,
    get_recent_scans_for_url,
    get_scan,
    get_uptime_history,
    get_user_stats,
    init_db,
    list_assets,
    list_notifications,
    mark_notifications_read,
    save_scan,
    save_uptime_check,
    set_asset_enabled,
)
from .domain_intel import domain_intelligence
from .email_analyzer import analyze_email_headers
from .file_analyzer import analyze_file_bytes
from .monitoring import monitor_url
from .password_analyzer import analyze_password
from .phishing import analyze_phishing
from .remediation import build_remediation
from .reports import build_scan_pdf
from .scanner import UnsafeTargetError, normalize_url, scan_website

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="SentinelAI",
    description="Defensive web security analysis, monitoring, and intelligence platform",
    version="5.0.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class AssistantRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ProfileUpdateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class AssetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=2048)
    interval_minutes: int = Field(default=60, ge=5, le=10080)


class AssetToggleRequest(BaseModel):
    enabled: bool


class EmailHeadersRequest(BaseModel):
    headers: str = Field(min_length=1, max_length=50000)


_monitor_task: asyncio.Task | None = None


@app.on_event("startup")
async def startup() -> None:
    global _monitor_task
    init_db()
    if _monitor_task is None or _monitor_task.done():
        _monitor_task = asyncio.create_task(_background_monitor())


@app.on_event("shutdown")
async def shutdown() -> None:
    global _monitor_task
    if _monitor_task:
        _monitor_task.cancel()
        try:
            await _monitor_task
        except asyncio.CancelledError:
            pass
        _monitor_task = None


async def _run_asset_check(asset: dict) -> dict:
    previous = asset.get("last_status")
    result = await monitor_url(asset["url"])
    save_uptime_check(asset, result)

    if not result["online"]:
        add_notification(
            asset["user_id"],
            "high",
            f"{asset['name']} is offline",
            result.get("error") or "The monitor could not reach this asset.",
            asset["id"],
        )
    elif previous == "offline":
        add_notification(
            asset["user_id"],
            "info",
            f"{asset['name']} recovered",
            f"The site is reachable again with HTTP {result.get('http_status')}.",
            asset["id"],
        )
    elif (result.get("response_ms") or 0) > 2500:
        add_notification(
            asset["user_id"],
            "medium",
            f"{asset['name']} is responding slowly",
            f"Latest response time: {result.get('response_ms')} ms.",
            asset["id"],
        )
    return result


async def _background_monitor() -> None:
    while True:
        try:
            for asset in get_due_assets(limit=10):
                try:
                    await _run_asset_check(asset)
                except Exception as exc:
                    add_notification(
                        asset["user_id"],
                        "high",
                        f"Monitor failed for {asset['name']}",
                        str(exc),
                        asset["id"],
                    )
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            raise
        except Exception:
            await asyncio.sleep(30)


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SentinelAI", "version": "5.0.0"}


def current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")
    token = authorization.split(" ", 1)[1].strip()
    user = user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")
    return user


def current_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")
    return authorization.split(" ", 1)[1].strip()


@app.post("/api/auth/register")
def register(body: RegisterRequest):
    try:
        user, token = auth_register(body.email, body.name, body.password)
        return {"user": user, "token": token}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.post("/api/auth/login")
def login(body: LoginRequest):
    try:
        user, token = auth_login(body.email, body.password)
        return {"user": user, "token": token}
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


@app.get("/api/auth/me")
def me(user: dict = Depends(current_user)):
    return {"user": user, "stats": get_user_stats(user["id"])}


@app.put("/api/auth/profile")
def update_profile(body: ProfileUpdateRequest, user: dict = Depends(current_user)):
    try:
        updated = auth_edit_profile(user["id"], body.name, body.email)
        return {"user": updated, "stats": get_user_stats(user["id"])}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="That email address is already in use.")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.post("/api/auth/change-password")
def change_password(body: ChangePasswordRequest, user: dict = Depends(current_user)):
    try:
        auth_change_password(user["id"], body.current_password, body.new_password)
        return {"ok": True}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/auth/logout")
def logout(token: str = Depends(current_token)):
    auth_logout(token)
    return {"ok": True}


@app.post("/api/scan")
async def website_scan(body: URLRequest, user: dict = Depends(current_user)):
    try:
        result = await scan_website(body.url)
        scan_id = save_scan(
            user["id"], result["final_url"], result["security_score"], result["risk"], result["scanned_at"], result
        )
        result["scan_id"] = scan_id
        return result
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Scan failed: {exc}")


@app.get("/api/remediation/{scan_id}")
def remediation(scan_id: int, user: dict = Depends(current_user)):
    scan = get_scan(user["id"], scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return build_remediation(scan)


@app.post("/api/domain-intel")
async def domain_intel(body: URLRequest, _user: dict = Depends(current_user)):
    try:
        return await domain_intelligence(body.url)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Domain lookup failed: {exc}")


@app.post("/api/phishing")
def phishing(body: URLRequest, _user: dict = Depends(current_user)):
    return analyze_phishing(body.url)


@app.post("/api/password")
def password(body: PasswordRequest, _user: dict = Depends(current_user)):
    return analyze_password(body.password)


@app.post("/api/assistant")
def assistant(body: AssistantRequest, _user: dict = Depends(current_user)):
    return answer(body.question)


@app.post("/api/email-headers")
def email_headers(body: EmailHeadersRequest, _user: dict = Depends(current_user)):
    try:
        return analyze_email_headers(body.headers)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/file-scan")
async def file_scan(file: UploadFile = File(...), _user: dict = Depends(current_user)):
    data = await file.read(10 * 1024 * 1024 + 1)
    try:
        return analyze_file_bytes(file.filename or "uploaded-file", file.content_type, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/history")
def history(limit: int = Query(default=20, ge=1, le=200), user: dict = Depends(current_user)):
    return {"items": get_history(user["id"], limit)}


@app.get("/api/history/export.csv")
def export_history_csv(user: dict = Depends(current_user)):
    items = get_history(user["id"], 200)
    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "url", "score", "risk", "created_at"])
    for item in items:
        writer.writerow([item["id"], item["url"], item["score"], item["risk"], item["created_at"]])
    return Response(
        content=out.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="sentinelai-scan-history.csv"'},
    )


@app.get("/api/compare/{scan_id}")
def compare_scan(scan_id: int, user: dict = Depends(current_user)):
    current = get_scan(user["id"], scan_id)
    if not current:
        raise HTTPException(status_code=404, detail="Scan not found.")
    scans = get_recent_scans_for_url(user["id"], current["url"], 2)
    if len(scans) < 2:
        return {"available": False, "message": "Run another scan of the same URL to compare changes."}
    latest, previous = scans[0], scans[1]
    latest_findings = {x["name"]: x for x in latest["payload"].get("findings", [])}
    previous_findings = {x["name"]: x for x in previous["payload"].get("findings", [])}
    changed = []
    fixed = []
    new_issues = []
    for name in sorted(set(latest_findings) | set(previous_findings)):
        before = previous_findings.get(name)
        after = latest_findings.get(name)
        if before != after:
            changed.append({"name": name, "before": before, "after": after})
        if before and before.get("status") != "pass" and after and after.get("status") == "pass":
            fixed.append(name)
        if before and before.get("status") == "pass" and after and after.get("status") != "pass":
            new_issues.append(name)
    return {
        "available": True,
        "current": {"id": latest["id"], "score": latest["score"], "risk": latest["risk"], "created_at": latest["created_at"]},
        "previous": {"id": previous["id"], "score": previous["score"], "risk": previous["risk"], "created_at": previous["created_at"]},
        "score_delta": latest["score"] - previous["score"],
        "changed_findings": changed,
        "fixed_findings": fixed,
        "new_issues": new_issues,
    }


@app.get("/api/threats")
def threats(user: dict = Depends(current_user)):
    history_items = get_history(user["id"], 100)
    totals = {"low": 0, "medium": 0, "high": 0}
    trend = []
    for item in reversed(history_items[:16]):
        risk = item.get("risk", "medium")
        totals[risk] = totals.get(risk, 0) + 1
        trend.append({"score": item["score"], "created_at": item["created_at"]})
    return {"scan_risk_distribution": totals, "stats": get_user_stats(user["id"]), "score_trend": trend}


@app.post("/api/assets")
def create_asset(body: AssetCreateRequest, user: dict = Depends(current_user)):
    try:
        normalized = normalize_url(body.url)
        return add_asset(user["id"], body.name, normalized, body.interval_minutes)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/assets")
def assets(user: dict = Depends(current_user)):
    return {"items": list_assets(user["id"])}


@app.delete("/api/assets/{asset_id}")
def remove_asset(asset_id: int, user: dict = Depends(current_user)):
    if not delete_asset(user["id"], asset_id):
        raise HTTPException(status_code=404, detail="Asset not found.")
    return {"ok": True}


@app.put("/api/assets/{asset_id}/enabled")
def toggle_asset(asset_id: int, body: AssetToggleRequest, user: dict = Depends(current_user)):
    asset = set_asset_enabled(user["id"], asset_id, body.enabled)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return asset


@app.post("/api/assets/{asset_id}/check")
async def check_asset(asset_id: int, user: dict = Depends(current_user)):
    asset = get_asset(user["id"], asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    try:
        result = await _run_asset_check(asset)
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Monitor check failed: {exc}")


@app.get("/api/assets/{asset_id}/uptime")
def uptime(asset_id: int, limit: int = Query(30, ge=1, le=200), user: dict = Depends(current_user)):
    asset = get_asset(user["id"], asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")
    rows = get_uptime_history(user["id"], asset_id, limit)
    if rows:
        online_count = sum(1 for r in rows if r["online"])
        uptime_pct = round((online_count / len(rows)) * 100, 1)
        avg_ms = round(sum((r["response_ms"] or 0) for r in rows) / len(rows))
    else:
        uptime_pct = 0
        avg_ms = 0
    return {"asset": asset, "checks": rows, "uptime_percent": uptime_pct, "average_response_ms": avg_ms}


@app.get("/api/notifications")
def notifications(user: dict = Depends(current_user)):
    return {"items": list_notifications(user["id"], 40)}


@app.post("/api/notifications/read")
def notifications_read(user: dict = Depends(current_user)):
    mark_notifications_read(user["id"])
    return {"ok": True}


@app.get(
    "/api/reports/{scan_id}.pdf",
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "PDF security report",
        }
    },
)
def report_pdf(
    scan_id: int,
    user: dict = Depends(current_user)
):
    scan = get_scan(user["id"], scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan report not found."
        )

    try:
        pdf_bytes = build_scan_pdf(scan, user)

        if not pdf_bytes:
            raise ValueError("Generated PDF is empty.")

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not generate PDF report: {str(exc)}"
        )

    filename = f"SentinelAI_Security_Report_{scan_id}.pdf"

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )
