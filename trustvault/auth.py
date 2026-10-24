"""Authentication: server-side sessions (so revocation is instant), hashed passwords,
login throttling, CSRF token per session."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app
from werkzeug.security import check_password_hash, generate_password_hash

from .util import now

COOKIE = "tv_session"
MAX_FAILS_PER_EMAIL = 5
MAX_FAILS_PER_IP = 30
LOCK_WINDOW_MIN = 15
_dummy_cache: dict[str, str] = {}


def hash_password(pw: str) -> str:
    return generate_password_hash(pw, method=current_app.config["HASH_METHOD"])


def verify_password(user, password: str) -> bool:
    """Always burns one hash verification so unknown users are not distinguishable by timing."""
    if user is None or not user["active"]:
        m = current_app.config["HASH_METHOD"]
        if m not in _dummy_cache:
            _dummy_cache[m] = generate_password_hash("dummy-password", method=m)
        check_password_hash(_dummy_cache[m], password)
        return False
    return check_password_hash(user["password_hash"], password)


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _ago(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")


def is_locked(db, email: str, ip: str | None) -> bool:
    since = _ago(LOCK_WINDOW_MIN)
    e = db.execute("SELECT COUNT(*) c FROM login_attempts WHERE email=? AND ok=0 AND ts>?", (email, since)).fetchone()["c"]
    i = db.execute("SELECT COUNT(*) c FROM login_attempts WHERE ip=? AND ok=0 AND ts>?", (ip, since)).fetchone()["c"]
    return e >= MAX_FAILS_PER_EMAIL or i >= MAX_FAILS_PER_IP


def record_attempt(db, email, ip, ok):
    db.execute("INSERT INTO login_attempts(email,ip,ts,ok) VALUES(?,?,?,?)", (email, ip, now(), int(ok)))
    if ok:
        db.execute("DELETE FROM login_attempts WHERE email=? AND ok=0", (email,))


def create_session(db, user_id: int):
    """A fresh random token on every login: a client-supplied session id is never accepted."""
    db.execute("DELETE FROM sessions WHERE expires_at<?", (now(),))
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    hours = current_app.config["SESSION_HOURS"]
    exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds")
    db.execute("INSERT INTO sessions(token_hash,user_id,csrf,created_at,expires_at) VALUES(?,?,?,?,?)",
               (_sha(token), user_id, csrf, now(), exp))
    return token, csrf


def load_user(db, token: str | None):
    """Looked up in the DB on every request: role, active flag and session are never cached."""
    if not token:
        return None
    row = db.execute(
        "SELECT u.id,u.email,u.name,u.phone,u.role,u.active,s.csrf,s.token_hash FROM sessions s "
        "JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1",
        (_sha(token), now())).fetchone()
    return dict(row) if row else None


def end_session(db, token: str | None):
    if token:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (_sha(token),))


def end_all_sessions(db, user_id: int):
    db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
