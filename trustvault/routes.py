"""HTTP API. Every route is wrapped in @requires(...) and every document route calls
authorize() before touching the document. See README for the endpoint/role table."""
import hmac
import json
import re
from datetime import date, timedelta

from flask import Blueprint, current_app, g, jsonify, request

from . import audit, auth, files
from .authz import RANK, access_level, authorize, fetch_doc_unchecked, requires  # noqa: F401
from .util import ApiError, now

bp = Blueprint("api", __name__, url_prefix="/api")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
LEVEL_NAME = {1: "read", 2: "edit", 3: "manage"}


# ---------------------------------------------------------------- request lifecycle
@bp.before_request
def _begin():
    from . import db as dbm
    g.post_commit = []
    g.db = dbm.connect(current_app.config["DB_PATH"])
    g.db.execute("BEGIN IMMEDIATE")  # serialises writers; keeps the audit chain linear
    g.user = auth.load_user(g.db, request.cookies.get(auth.COOKIE))
    if g.user and request.endpoint != "api.login" and request.method not in ("GET", "HEAD", "OPTIONS"):
        if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), g.user["csrf"]):
            raise ApiError(403, "missing or invalid CSRF token")


# ---------------------------------------------------------------- helpers
def json_body(allowed, required=()):
    """Strict whitelist: unknown fields are rejected, never silently applied (mass assignment)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "JSON object body required")
    extra = set(data) - set(allowed)
    if extra:
        raise ApiError(400, "unknown fields: " + ", ".join(sorted(map(str, extra)))[:200])
    for k in required:
        if k not in data:
            raise ApiError(400, f"missing field: {k}")
    return data


def reply(payload, status=200):
    return jsonify(payload), status


def doc_json(row, level: int):
    return {"id": row["id"], "name": row["name"], "category": row["category"], "mime": row["mime"],
            "size": row["size"], "sha256": row["sha256"], "owner_id": row["owner_id"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "deleted_at": row["deleted_at"], "my_access": LEVEL_NAME[level]}


def get_upload():
    f = request.files.get("file")
    if f is None:
        raise ApiError(400, "multipart field 'file' required")
    limit = current_app.config["MAX_UPLOAD_BYTES"]
    data = f.read(limit + 1)
    if len(data) > limit:
        raise ApiError(413, f"file too large (max {limit // (1024 * 1024)} MB)")
    return f.filename, data


def int_arg(name, default, lo, hi):
    try:
        v = int(request.args.get(name, default))
    except ValueError:
        raise ApiError(400, f"{name} must be an integer")
    return max(lo, min(hi, v))


def like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def parse_date(name):
    v = request.args.get(name)
    if not v:
        return None
    try:
        return date.fromisoformat(v)
    except ValueError:
        raise ApiError(400, f"{name} must be YYYY-MM-DD")


# ---------------------------------------------------------------- auth
@bp.post("/auth/login")
@requires("public")
def login():
    body = json_body({"email", "password"}, {"email", "password"})
    email, password, ip = str(body["email"]).strip().lower(), str(body["password"]), request.remote_addr
    if auth.is_locked(g.db, email, ip):
        audit.log("login_locked", "denied", detail={"email": email[:100]}, actor=None)
        return reply({"error": "too many failed attempts; try again later"}, 429)
    row = g.db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not auth.verify_password(row, password):
        auth.record_attempt(g.db, email, ip, False)
        audit.log("login_failed", "denied", detail={"email": email[:100]}, actor=None)
        return reply({"error": "invalid credentials"}, 401)  # same answer for unknown / wrong / inactive
    auth.record_attempt(g.db, email, ip, True)
    token, csrf = auth.create_session(g.db, row["id"])
    audit.log("login", actor=dict(row))
    resp, _ = reply({"id": row["id"], "email": row["email"], "name": row["name"], "role": row["role"], "csrf": csrf})
    resp.set_cookie(auth.COOKIE, token, httponly=True, samesite="Strict",
                    secure=current_app.config["COOKIE_SECURE"], max_age=current_app.config["SESSION_HOURS"] * 3600)
    return resp, 200


@bp.post("/auth/logout")
@requires("user")
def logout():
    auth.end_session(g.db, request.cookies.get(auth.COOKIE))
    audit.log("logout")
    resp, _ = reply({"ok": True})
    resp.delete_cookie(auth.COOKIE)
    return resp, 200


@bp.get("/auth/me")
@requires("user")
def me():
    u = g.user
    return reply({"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"], "csrf": u["csrf"]})


# ---------------------------------------------------------------- documents: create / search
@bp.post("/documents")
@requires("owner")
def upload():
    filename, data = get_upload()
    try:
        name = files.clean_name(filename)
        category = files.clean_category(request.form.get("category", "general"))
        mime = files.validate(name, data)
    except ApiError as e:
        e.audit = {"action": "upload", "outcome": "rejected", "detail": {"reason": e.message, "filename": str(filename)[:120]}}
        raise
    key, sha = files.store(data)
    try:
        ts = now()
        cur = g.db.execute(
            "INSERT INTO documents(name,category,owner_id,storage_key,mime,size,sha256,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)", (name, category, g.user["id"], key, mime, len(data), sha, ts, ts))
        row = g.db.execute("SELECT * FROM documents WHERE id=?", (cur.lastrowid,)).fetchone()
        audit.log("upload", doc=row, detail={"size": len(data), "sha256": sha, "category": category})
    except Exception:
        files.remove(key)
        raise
    return reply(doc_json(row, RANK["manage"]), 201)


@bp.get("/documents")
@requires("user")
def search_documents():
    """Search only ever runs over documents the caller can reach (owner or live grant);
    paging and counts are computed after that filter, so nothing leaks through them."""
    u = g.user
    if u["role"] == "admin":
        return reply({"total": 0, "items": []})
    where, args = ["d.deleted_at IS NULL", "(d.owner_id=:uid OR g.id IS NOT NULL)"], {"uid": u["id"]}
    if q := request.args.get("q", "").strip():
        where.append("d.name LIKE :q ESCAPE '\\'")
        args["q"] = like(q[:100])
    if owner := request.args.get("owner", "").strip():
        where.append("(o.name LIKE :o ESCAPE '\\' OR o.email LIKE :o ESCAPE '\\')")
        args["o"] = like(owner[:100])
    if cat := request.args.get("category", "").strip().lower():
        where.append("d.category=:cat")
        args["cat"] = cat[:40]
    if d1 := parse_date("date_from"):
        where.append("d.created_at >= :d1")
        args["d1"] = d1.isoformat()
    if d2 := parse_date("date_to"):
        where.append("d.created_at < :d2")
        args["d2"] = (d2 + timedelta(days=1)).isoformat()
    base = ("FROM documents d JOIN users o ON o.id=d.owner_id "
            "LEFT JOIN grants g ON g.document_id=d.id AND g.user_id=:uid AND g.revoked_at IS NULL "
            "WHERE " + " AND ".join(where))
    total = g.db.execute("SELECT COUNT(*) c " + base, args).fetchone()["c"]
    args.update(lim=int_arg("limit", 50, 1, 100), off=int_arg("offset", 0, 0, 10**9))
    rows = g.db.execute(
        "SELECT d.*, o.name AS owner_name, o.email AS owner_email, g.level AS grant_level " + base +
        " ORDER BY d.created_at DESC, d.id DESC LIMIT :lim OFFSET :off", args).fetchall()
    items = []
    for r in rows:
        level = RANK["manage"] if r["owner_id"] == u["id"] else RANK[r["grant_level"]]
        if u["role"] == "viewer":
            level = min(level, RANK["read"])
        item = doc_json(r, level)
        item.update(owner_name=r["owner_name"], owner_email=r["owner_email"])
        items.append(item)
    return reply({"total": total, "items": items})


# ---------------------------------------------------------------- documents: single document
@bp.get("/documents/<int:doc_id>")
@requires("user")
def get_document(doc_id):
    doc = authorize(g.user, doc_id, "read")
    return reply(doc_json(doc, access_level(g.user, doc)))


@bp.get("/documents/<int:doc_id>/download")
@requires("user")
def download(doc_id):
    doc = authorize(g.user, doc_id, "download")
    try:
        data = files.read(doc["storage_key"])
    except OSError:
        raise ApiError(500, "stored file is unavailable")
    audit.log("download", doc=doc, detail={"size": doc["size"], "sha256": doc["sha256"]})
    resp = current_app.response_class(data, mimetype=doc["mime"])
    resp.headers.set("Content-Disposition", "attachment", filename=doc["name"])  # never rendered inline
    resp.headers["Content-Length"] = str(len(data))
    return resp


@bp.patch("/documents/<int:doc_id>")
@requires("user")
def update_metadata(doc_id):
    doc = authorize(g.user, doc_id, "edit")
    body = json_body({"name", "category"})
    if not body:
        raise ApiError(400, "nothing to change")
    name, category = doc["name"], doc["category"]
    if "name" in body:
        name = files.clean_name(str(body["name"]))
        if files.ext_of(name) != files.ext_of(doc["name"]):
            raise ApiError(400, "the file extension cannot be changed")
    if "category" in body:
        category = files.clean_category(body["category"])
    g.db.execute("UPDATE documents SET name=?, category=?, updated_at=? WHERE id=?", (name, category, now(), doc_id))
    audit.log("metadata_change", doc=doc, detail={"old": {"name": doc["name"], "category": doc["category"]},
                                                  "new": {"name": name, "category": category}})
    return reply({"ok": True})


@bp.put("/documents/<int:doc_id>/content")
@requires("user")
def replace_content(doc_id):
    doc = authorize(g.user, doc_id, "edit")
    filename, data = get_upload()
    try:
        mime = files.validate(doc["name"], data)  # must still be valid for the existing name/type
    except ApiError as e:
        e.audit = {"action": "content_change", "outcome": "rejected", "doc_id": doc_id, "doc_name": doc["name"],
                   "detail": {"reason": e.message}}
        raise
    key, sha = files.store(data)
    g.db.execute("UPDATE documents SET storage_key=?, mime=?, size=?, sha256=?, updated_at=? WHERE id=?",
                 (key, mime, len(data), sha, now(), doc_id))
    audit.log("content_change", doc=doc, detail={"old_sha256": doc["sha256"], "new_sha256": sha, "size": len(data)})
    old = doc["storage_key"]
    g.post_commit.append(lambda: files.remove(old))  # only after the DB commit succeeded
    return reply({"ok": True, "sha256": sha})


@bp.delete("/documents/<int:doc_id>")
@requires("user")
def delete_document(doc_id):
    doc = authorize(g.user, doc_id, "delete")
    g.db.execute("UPDATE documents SET deleted_at=?, deleted_by=? WHERE id=?", (now(), g.user["id"], doc_id))
    audit.log("delete", doc=doc)
    return reply({"ok": True})


@bp.post("/documents/<int:doc_id>/restore")
@requires("user")
def restore_document(doc_id):
    doc = authorize(g.user, doc_id, "restore", include_deleted=True)
    if doc["deleted_at"] is None:
        raise ApiError(409, "document is not deleted")
    g.db.execute("UPDATE documents SET deleted_at=NULL, deleted_by=NULL WHERE id=?", (doc_id,))
    audit.log("restore", doc=doc)
    return reply({"ok": True})


@bp.get("/documents/<int:doc_id>/audit")
@requires("user")
def document_audit(doc_id):
    doc = authorize(g.user, doc_id, "manage")
    rows = g.db.execute("SELECT id,ts,actor_email,action,outcome,detail FROM audit_log WHERE doc_id=? "
                        "ORDER BY id DESC LIMIT 200", (doc["id"],)).fetchall()
    return reply({"items": [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]})


# ---------------------------------------------------------------- grants
@bp.get("/documents/<int:doc_id>/grants")
@requires("user")
def list_grants(doc_id):
    doc = authorize(g.user, doc_id, "manage")
    rows = g.db.execute("SELECT g.user_id, u.email, u.name, g.level, g.granted_at FROM grants g JOIN users u ON u.id=g.user_id "
                        "WHERE g.document_id=? AND g.revoked_at IS NULL ORDER BY u.email", (doc["id"],)).fetchall()
    return reply({"items": [dict(r) for r in rows]})


@bp.post("/documents/<int:doc_id>/grants")
@requires("user")
def add_grant(doc_id):
    doc = authorize(g.user, doc_id, "manage")
    body = json_body({"email", "level", "suggestion_id"}, {"email", "level"})
    level = body["level"]
    if level not in ("read", "edit"):
        raise ApiError(400, "level must be 'read' or 'edit'")
    target = g.db.execute("SELECT * FROM users WHERE email=? AND active=1",
                          (str(body["email"]).strip().lower(),)).fetchone()
    # One generic refusal for every invalid target so this cannot be used to enumerate users.
    cannot = ApiError(422, "that person cannot be granted access to this document")
    if (target is None or target["role"] == "admin" or target["id"] == doc["owner_id"]
            or (level == "edit" and target["role"] != "owner")):
        raise cannot
    sid = body.get("suggestion_id")
    if sid is not None:
        s = g.db.execute("SELECT * FROM suggestions WHERE id=?", (sid if isinstance(sid, int) else -1,)).fetchone()
        if (s is None or s["document_id"] != doc["id"] or s["requested_by"] != g.user["id"]
                or target["id"] not in json.loads(s["candidates"])):
            raise ApiError(422, "suggestion does not apply to this document and person")
    prev = g.db.execute("SELECT id, level FROM grants WHERE document_id=? AND user_id=? AND revoked_at IS NULL",
                        (doc["id"], target["id"])).fetchone()
    if prev:
        g.db.execute("UPDATE grants SET level=? WHERE id=?", (level, prev["id"]))
    else:
        g.db.execute("INSERT INTO grants(document_id,user_id,level,granted_by,granted_at) VALUES(?,?,?,?,?)",
                     (doc["id"], target["id"], level, g.user["id"], now()))
    audit.log("grant_changed" if prev else "grant_added", doc=doc,
              detail={"user_id": target["id"], "email": target["email"], "level": level,
                      "previous": prev["level"] if prev else None, "via_suggestion": sid})
    return reply({"ok": True, "user_id": target["id"], "level": level}, 200 if prev else 201)


@bp.delete("/documents/<int:doc_id>/grants/<int:user_id>")
@requires("user")
def revoke_grant(doc_id, user_id):
    doc = authorize(g.user, doc_id, "manage")
    cur = g.db.execute("UPDATE grants SET revoked_at=?, revoked_by=? WHERE document_id=? AND user_id=? AND revoked_at IS NULL",
                       (now(), g.user["id"], doc["id"], user_id))
    if cur.rowcount == 0:
        raise ApiError(404, "no such grant")
    audit.log("grant_revoked", doc=doc, detail={"user_id": user_id})
    return reply({"ok": True})


# ---------------------------------------------------------------- AI-assisted suggestions (advisory only)
def suggest_recipients(db, doc):
    """Swap point for an LLM. The rule here uses only metadata (who else already holds access to the owner's
    documents in the same category), never document contents. Whatever produces candidates, the result is
    only a list: it cannot create a grant. A person must confirm each one through add_grant()."""
    return db.execute(
        "SELECT u.id, u.email, u.name, COUNT(DISTINCT g.document_id) AS n FROM users u "
        "JOIN grants g ON g.user_id=u.id AND g.revoked_at IS NULL "
        "JOIN documents d2 ON d2.id=g.document_id AND d2.owner_id=:owner AND d2.deleted_at IS NULL "
        "  AND d2.category=:cat AND d2.id<>:doc "
        "WHERE u.active=1 AND u.role<>'admin' AND u.id<>:owner "
        "  AND u.id NOT IN (SELECT user_id FROM grants WHERE document_id=:doc AND revoked_at IS NULL) "
        "GROUP BY u.id ORDER BY n DESC, u.email LIMIT 5",
        {"owner": doc["owner_id"], "cat": doc["category"], "doc": doc["id"]}).fetchall()


@bp.post("/documents/<int:doc_id>/suggestions")
@requires("user")
def suggestions(doc_id):
    doc = authorize(g.user, doc_id, "manage")
    rows = suggest_recipients(g.db, doc)
    cur = g.db.execute("INSERT INTO suggestions(document_id,requested_by,candidates,created_at) VALUES(?,?,?,?)",
                       (doc["id"], g.user["id"], json.dumps([r["id"] for r in rows]), now()))
    audit.log("ai_suggestion", doc=doc, detail={"suggestion_id": cur.lastrowid, "candidate_ids": [r["id"] for r in rows],
                                                "engine": "category-colocation-heuristic"})
    return reply({"suggestion_id": cur.lastrowid, "note": "Suggestions only. Nothing is shared until you confirm each one.",
                  "candidates": [{"email": r["email"], "name": r["name"],
                                  "reason": f"already has access to {r['n']} other '{doc['category']}' document(s) you own"}
                                 for r in rows]})


# ---------------------------------------------------------------- admin: users
@bp.get("/admin/users")
@requires("admin")
def admin_list_users():
    rows = g.db.execute("SELECT id,email,name,role,active,created_at FROM users ORDER BY id").fetchall()
    return reply({"items": [dict(r) for r in rows]})


def _check_password_strength(pw):
    if not isinstance(pw, str) or len(pw) < 12 or len(pw) > 200:
        raise ApiError(400, "password must be 12-200 characters")


@bp.post("/admin/users")
@requires("admin")
def admin_create_user():
    body = json_body({"email", "name", "password", "role"}, {"email", "name", "password", "role"})
    email = str(body["email"]).strip().lower()
    if not EMAIL_RE.match(email):
        raise ApiError(400, "invalid email")
    if body["role"] not in ("admin", "owner", "viewer"):
        raise ApiError(400, "role must be admin, owner or viewer")
    name = str(body["name"]).strip()
    if not 1 <= len(name) <= 100:
        raise ApiError(400, "name must be 1-100 characters")
    _check_password_strength(body["password"])
    if g.db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        raise ApiError(409, "email already in use")
    cur = g.db.execute("INSERT INTO users(email,name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                       (email, name, auth.hash_password(body["password"]), body["role"], now()))
    audit.log("user_created", detail={"user_id": cur.lastrowid, "email": email, "role": body["role"]})
    return reply({"id": cur.lastrowid, "email": email, "role": body["role"]}, 201)


@bp.patch("/admin/users/<int:user_id>")
@requires("admin")
def admin_update_user(user_id):
    body = json_body({"name", "role", "active", "password"})
    target = g.db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        raise ApiError(404, "not found")
    if user_id == g.user["id"] and ("role" in body or "active" in body):
        raise ApiError(409, "admins cannot change their own role or active flag")
    changes = {}
    if "role" in body:
        if body["role"] not in ("admin", "owner", "viewer"):
            raise ApiError(400, "invalid role")
        changes["role"] = body["role"]
    if "active" in body:
        if not isinstance(body["active"], bool):
            raise ApiError(400, "active must be true or false")
        changes["active"] = int(body["active"])
    if "name" in body:
        changes["name"] = str(body["name"]).strip()[:100] or target["name"]
    if "password" in body:
        _check_password_strength(body["password"])
        changes["password_hash"] = auth.hash_password(body["password"])
    if not changes:
        raise ApiError(400, "nothing to change")
    sets = ", ".join(f"{k}=?" for k in changes)  # keys come from the whitelist above, never from the client
    g.db.execute(f"UPDATE users SET {sets} WHERE id=?", (*changes.values(), user_id))
    if {"role", "active", "password_hash"} & set(changes):
        auth.end_all_sessions(g.db, user_id)  # role/credential change takes effect immediately
    shown = {k: v for k, v in changes.items() if k != "password_hash"}
    if "password_hash" in changes:
        shown["password"] = "changed"
    audit.log("user_updated", detail={"user_id": user_id, "email": target["email"], "changes": shown})
    return reply({"ok": True})


# ---------------------------------------------------------------- admin: audit & activity
@bp.get("/admin/audit")
@requires("admin")
def admin_audit():
    where, args = ["1=1"], {}
    for param, col in (("action", "action"), ("outcome", "outcome")):
        if v := request.args.get(param):
            where.append(f"{col}=:{param}")
            args[param] = v
    if v := request.args.get("actor"):
        where.append("actor_email LIKE :actor ESCAPE '\\'")
        args["actor"] = like(v[:100])
    if v := request.args.get("doc_id"):
        where.append("doc_id=:doc_id")
        args["doc_id"] = int_arg("doc_id", 0, 0, 10**12)
    if d := parse_date("since"):
        where.append("ts>=:since")
        args["since"] = d.isoformat()
    if v := request.args.get("before_id"):
        where.append("id<:before")
        args["before"] = int_arg("before_id", 0, 0, 10**12)
    args["lim"] = int_arg("limit", 100, 1, 500)
    rows = g.db.execute("SELECT id,ts,actor_id,actor_email,action,outcome,doc_id,doc_name,detail,ip FROM audit_log WHERE "
                        + " AND ".join(where) + " ORDER BY id DESC LIMIT :lim", args).fetchall()
    return reply({"items": [{**dict(r), "detail": json.loads(r["detail"])} for r in rows]})


@bp.get("/admin/audit/verify")
@requires("admin")
def admin_audit_verify():
    return reply(audit.verify(g.db))


@bp.get("/admin/audit/head")
@requires("admin")
def admin_audit_head():
    """Record this value somewhere the application cannot write (ticket, email, WORM store)."""
    r = g.db.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return reply({"last_id": r["id"], "head": r["hash"]} if r else {"last_id": 0, "head": audit.GENESIS})


ALERT_DENIED = 5
ALERT_DOWNLOADS = 20


@bp.get("/admin/activity")
@requires("admin")
def admin_activity():
    hours = int_arg("hours", 24, 1, 24 * 30)
    from datetime import datetime, timezone
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    counts = g.db.execute("SELECT action, outcome, COUNT(*) n FROM audit_log WHERE ts>=? GROUP BY action, outcome "
                          "ORDER BY n DESC", (since,)).fetchall()
    alerts = []
    for r in g.db.execute("SELECT actor_email, COUNT(*) n FROM audit_log WHERE ts>=? AND outcome='denied' "
                          "AND action LIKE '%\\_refused' ESCAPE '\\' AND actor_email IS NOT NULL "
                          "GROUP BY actor_email HAVING n>=?", (since, ALERT_DENIED)):
        alerts.append({"kind": "repeated_refused_access", "actor": r["actor_email"], "count": r["n"]})
    for r in g.db.execute("SELECT actor_email, COUNT(*) n FROM audit_log WHERE ts>=? AND action='download' "
                          "AND outcome='ok' GROUP BY actor_email HAVING n>=?", (since, ALERT_DOWNLOADS)):
        alerts.append({"kind": "bulk_download", "actor": r["actor_email"], "count": r["n"]})
    for r in g.db.execute("SELECT detail, COUNT(*) n FROM audit_log WHERE ts>=? AND action='login_failed' "
                          "GROUP BY detail HAVING n>=?", (since, ALERT_DENIED)):
        alerts.append({"kind": "repeated_failed_login", "target": json.loads(r["detail"]).get("email"), "count": r["n"]})
    perm = g.db.execute("SELECT id,ts,actor_email,action,doc_id,doc_name,detail FROM audit_log WHERE ts>=? AND action IN "
                        "('grant_added','grant_changed','grant_revoked') ORDER BY id DESC LIMIT 100", (since,)).fetchall()
    return reply({"window_hours": hours, "counts": [dict(r) for r in counts], "alerts": alerts,
                  "permission_changes": [{**dict(r), "detail": json.loads(r["detail"])} for r in perm]})
