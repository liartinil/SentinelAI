from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "sentinelai.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                interval_minutes INTEGER NOT NULL DEFAULT 60,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_checked_at TEXT,
                next_check_at TEXT,
                last_status TEXT,
                last_http_status INTEGER,
                last_response_ms INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS uptime_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                online INTEGER NOT NULL,
                http_status INTEGER,
                response_ms INTEGER,
                error TEXT,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                asset_id INTEGER,
                level TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL
            );
            """
        )
        conn.commit()


def create_user(email: str, name: str, password_hash: str, created_at: str) -> dict[str, Any]:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (email, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (email.lower().strip(), name.strip(), password_hash, created_at),
        )
        conn.commit()
        user_id = int(cur.lastrowid)
    return get_user_by_id(user_id)  # type: ignore[return-value]


def get_user_by_email(email: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, email, name, password_hash, created_at FROM users WHERE email = ?",
            (email.lower().strip(),),
        ).fetchone()
    return dict(row) if row else None


def get_user_auth_by_id(user_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, email, name, password_hash, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, email, name, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def update_user_profile(user_id: int, name: str, email: str) -> dict[str, Any]:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET name = ?, email = ? WHERE id = ?",
            (name.strip(), email.lower().strip(), user_id),
        )
        conn.commit()
    return get_user_by_id(user_id)  # type: ignore[return-value]


def update_user_password(user_id: int, password_hash: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()


def create_session(user_id: int, token_hash: str, created_at: str, expires_at: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (user_id, token_hash, created_at, expires_at),
        )
        conn.commit()


def get_session_user(token_hash: str, now_iso: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.email, u.name, u.created_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.expires_at > ?
            """,
            (token_hash, now_iso),
        ).fetchone()
    return dict(row) if row else None


def delete_session(token_hash: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.commit()


def delete_other_sessions(user_id: int, keep_token_hash: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?", (user_id, keep_token_hash))
        conn.commit()


def save_scan(user_id: int, url: str, score: int, risk: str, created_at: str, payload: dict[str, Any]) -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (user_id, url, score, risk, created_at, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, url, score, risk, created_at, json.dumps(payload, ensure_ascii=False)),
        )
        conn.commit()
        return int(cur.lastrowid)


def get_history(user_id: int, limit: int = 20) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 200))
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, url, score, risk, created_at FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(user_id: int, scan_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, url, score, risk, created_at, payload FROM scans WHERE user_id = ? AND id = ?",
            (user_id, scan_id),
        ).fetchone()
    if not row:
        return None
    item = dict(row)
    item["payload"] = json.loads(item["payload"])
    return item


def get_recent_scans_for_url(user_id: int, url: str, limit: int = 2) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, url, score, risk, created_at, payload FROM scans WHERE user_id = ? AND url = ? ORDER BY id DESC LIMIT ?",
            (user_id, url, limit),
        ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        out.append(item)
    return out


def get_user_stats(user_id: int) -> dict[str, Any]:
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM scans WHERE user_id = ?", (user_id,)).fetchone()["c"]
        avg = conn.execute("SELECT AVG(score) AS a FROM scans WHERE user_id = ?", (user_id,)).fetchone()["a"]
        high = conn.execute("SELECT COUNT(*) AS c FROM scans WHERE user_id = ? AND risk = 'high'", (user_id,)).fetchone()["c"]
        best = conn.execute("SELECT MAX(score) AS m FROM scans WHERE user_id = ?", (user_id,)).fetchone()["m"]
        last = conn.execute("SELECT created_at FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT 1", (user_id,)).fetchone()
        assets = conn.execute("SELECT COUNT(*) AS c FROM assets WHERE user_id = ?", (user_id,)).fetchone()["c"]
        unread = conn.execute("SELECT COUNT(*) AS c FROM notifications WHERE user_id = ? AND is_read = 0", (user_id,)).fetchone()["c"]
    return {
        "total_scans": total,
        "average_score": round(avg or 0),
        "high_risk": high,
        "best_score": int(best or 0),
        "last_scan_at": last["created_at"] if last else None,
        "assets": assets,
        "unread_notifications": unread,
    }


def add_asset(user_id: int, name: str, url: str, interval_minutes: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    interval_minutes = max(5, min(interval_minutes, 10080))
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO assets (user_id, name, url, interval_minutes, enabled, created_at, next_check_at)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (user_id, name.strip() or url, url.strip(), interval_minutes, now.isoformat(), now.isoformat()),
        )
        conn.commit()
        asset_id = int(cur.lastrowid)
    return get_asset(user_id, asset_id)  # type: ignore[return-value]


def get_asset(user_id: int, asset_id: int) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM assets WHERE user_id = ? AND id = ?", (user_id, asset_id)).fetchone()
    return dict(row) if row else None


def list_assets(user_id: int) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM assets WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]


def delete_asset(user_id: int, asset_id: int) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM assets WHERE user_id = ? AND id = ?", (user_id, asset_id))
        conn.commit()
    return cur.rowcount > 0


def set_asset_enabled(user_id: int, asset_id: int, enabled: bool) -> dict[str, Any] | None:
    with _connect() as conn:
        conn.execute("UPDATE assets SET enabled = ? WHERE user_id = ? AND id = ?", (1 if enabled else 0, user_id, asset_id))
        conn.commit()
    return get_asset(user_id, asset_id)


def get_due_assets(limit: int = 10) -> list[dict[str, Any]]:
    now = _utcnow()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT * FROM assets
            WHERE enabled = 1 AND (next_check_at IS NULL OR next_check_at <= ?)
            ORDER BY COALESCE(next_check_at, created_at) ASC
            LIMIT ?
            """,
            (now, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def save_uptime_check(asset: dict[str, Any], result: dict[str, Any]) -> None:
    checked_at = result["checked_at"]
    next_check = (datetime.fromisoformat(checked_at) + timedelta(minutes=int(asset["interval_minutes"]))).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO uptime_checks (asset_id, user_id, checked_at, online, http_status, response_ms, error)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset["id"], asset["user_id"], checked_at, 1 if result["online"] else 0,
                result.get("http_status"), result.get("response_ms"), result.get("error"),
            ),
        )
        conn.execute(
            """
            UPDATE assets SET last_checked_at = ?, next_check_at = ?, last_status = ?,
                last_http_status = ?, last_response_ms = ? WHERE id = ?
            """,
            (
                checked_at, next_check, "online" if result["online"] else "offline",
                result.get("http_status"), result.get("response_ms"), asset["id"],
            ),
        )
        conn.commit()


def get_uptime_history(user_id: int, asset_id: int, limit: int = 30) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT checked_at, online, http_status, response_ms, error
            FROM uptime_checks WHERE user_id = ? AND asset_id = ?
            ORDER BY id DESC LIMIT ?
            """,
            (user_id, asset_id, max(1, min(limit, 200))),
        ).fetchall()
    return [dict(r) for r in rows]


def add_notification(user_id: int, level: str, title: str, message: str, asset_id: int | None = None) -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO notifications (user_id, asset_id, level, title, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, asset_id, level, title, message, _utcnow()),
        )
        conn.commit()
        return int(cur.lastrowid)


def list_notifications(user_id: int, limit: int = 30) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, max(1, min(limit, 100))),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_notifications_read(user_id: int) -> None:
    with _connect() as conn:
        conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (user_id,))
        conn.commit()
