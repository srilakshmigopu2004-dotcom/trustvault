"""Tamper-evident audit trail.

Every row stores prev_hash and hash = HMAC-SHA256(server_key, prev_hash || canonical(row)).
 - SQL triggers reject UPDATE/DELETE on the table.
 - Someone who gets DB write access but not the server key cannot recompute a valid chain.
 - Truncating the tail is only detectable against an externally recorded head
   (see GET /api/admin/audit/head and README).
Rows are written inside the same transaction as the action they describe, and refused
attempts are written by the error handler, so a refusal is on the record too.
"""
import hashlib
import hmac
import json

from flask import current_app, g, has_request_context, request

from .util import now

GENESIS = "0" * 64
FIELDS = ("ts", "actor_id", "actor_email", "action", "outcome", "doc_id", "doc_name", "detail", "ip")


def _digest(key: bytes, prev: str, payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key, (prev + blob).encode(), hashlib.sha256).hexdigest()


def append(db, actor, action, outcome="ok", doc_id=None, doc_name=None, detail=None):
    key = current_app.config["AUDIT_KEY"]
    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else GENESIS
    payload = {
        "ts": now(),
        "actor_id": actor["id"] if actor else None,
        "actor_email": actor["email"] if actor else None,
        "action": action,
        "outcome": outcome,
        "doc_id": doc_id,
        "doc_name": doc_name,
        "detail": json.dumps(detail or {}, sort_keys=True, ensure_ascii=True),
        "ip": request.remote_addr if has_request_context() else None,
    }
    h = _digest(key, prev, payload)
    db.execute(
        "INSERT INTO audit_log(ts,actor_id,actor_email,action,outcome,doc_id,doc_name,detail,ip,prev_hash,hash)"
        " VALUES(:ts,:actor_id,:actor_email,:action,:outcome,:doc_id,:doc_name,:detail,:ip,:prev,:hash)",
        {**payload, "prev": prev, "hash": h},
    )


def log(action, outcome="ok", doc=None, doc_id=None, doc_name=None, detail=None, actor=None):
    """Used by routes: the actor defaults to the current user."""
    if doc is not None:
        doc_id, doc_name = doc["id"], doc["name"]
    append(g.db, actor if actor is not None else g.get("user"), action, outcome, doc_id, doc_name, detail)


def verify(db):
    key = current_app.config["AUDIT_KEY"]
    prev, count = GENESIS, 0
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        payload = {k: r[k] for k in FIELDS}
        if r["prev_hash"] != prev or not hmac.compare_digest(r["hash"], _digest(key, prev, payload)):
            return {"ok": False, "checked": count, "first_bad_id": r["id"]}
        prev, count = r["hash"], count + 1
    return {"ok": True, "checked": count, "head": prev}
