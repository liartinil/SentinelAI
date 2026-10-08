from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from .database import (
    create_session,
    create_user,
    delete_session,
    get_session_user,
    get_user_auth_by_id,
    get_user_by_email,
    update_user_password,
    update_user_profile,
)

PBKDF2_ITERATIONS = 260_000
SESSION_DAYS = 7


def _now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_b64, digest_b64 = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def register(email: str, name: str, password: str) -> tuple[dict, str]:
    if get_user_by_email(email):
        raise ValueError("An account with this email already exists.")
    now = _now()
    user = create_user(email, name, hash_password(password), now.isoformat())
    token = secrets.token_urlsafe(32)
    create_session(user["id"], token_hash(token), now.isoformat(), (now + timedelta(days=SESSION_DAYS)).isoformat())
    return user, token


def login(email: str, password: str) -> tuple[dict, str]:
    user = get_user_by_email(email)
    if not user or not verify_password(password, user["password_hash"]):
        raise ValueError("Invalid email or password.")
    now = _now()
    token = secrets.token_urlsafe(32)
    create_session(user["id"], token_hash(token), now.isoformat(), (now + timedelta(days=SESSION_DAYS)).isoformat())
    safe_user = {k: user[k] for k in ("id", "email", "name", "created_at")}
    return safe_user, token


def user_from_token(token: str) -> dict | None:
    if not token:
        return None
    return get_session_user(token_hash(token), _now().isoformat())


def logout(token: str) -> None:
    if token:
        delete_session(token_hash(token))


def edit_profile(user_id: int, name: str, email: str) -> dict:
    existing = get_user_by_email(email)
    if existing and int(existing["id"]) != int(user_id):
        raise ValueError("That email address is already in use.")
    return update_user_profile(user_id, name, email)


def change_password(user_id: int, current_password: str, new_password: str) -> None:
    user = get_user_auth_by_id(user_id)
    if not user or not verify_password(current_password, user["password_hash"]):
        raise ValueError("Current password is incorrect.")
    if current_password == new_password:
        raise ValueError("New password must be different from the current password.")
    update_user_password(user_id, hash_password(new_password))
