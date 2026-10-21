"""THE authorization decision lives here and nowhere else.

 - `authorize(user, doc_id, action)` is called by every document route.
 - `requires(kind)` declares, and enforces, the role gate of every route; the test-suite
   fails if any /api route is missing a declaration.
 - Deny by default. A document is reachable only by its owner or by someone holding an
   un-revoked grant. Admins have NO content access (they manage users and read the audit).
 - Everything is read from the DB on every call: nothing is cached, so revocation is instant.
"""
from functools import wraps

from flask import g, request

from .util import ApiError

RANK = {"none": 0, "read": 1, "edit": 2, "manage": 3}
NEEDS = {"read": "read", "download": "read", "edit": "edit",
         "delete": "manage", "manage": "manage", "restore": "manage"}


def _load(doc_id: int, include_deleted: bool):
    row = g.db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if row is None or (row["deleted_at"] is not None and not include_deleted):
        return None
    return row


def access_level(user: dict, doc) -> int:
    """Effective rank (0..3) of `user` on `doc`."""
    if user["role"] == "admin" or not user["active"]:
        return 0
    if doc["owner_id"] == user["id"]:
        raw = RANK["manage"]
    else:
        grant = g.db.execute(
            "SELECT level FROM grants WHERE document_id=? AND user_id=? AND revoked_at IS NULL",
            (doc["id"], user["id"])).fetchone()
        raw = RANK[grant["level"]] if grant else 0
    # Viewers can never exceed read, whatever is in the grants table (e.g. after a demotion).
    return min(raw, RANK["read"]) if user["role"] == "viewer" else raw


def authorize(user: dict, doc_id: int, action: str, include_deleted: bool = False):
    need = RANK[NEEDS[action]]
    doc = _load(doc_id, include_deleted)
    level = access_level(user, doc) if doc else 0
    if level >= need:
        return doc
    audit = {"action": f"{action}_refused", "doc_id": doc_id, "doc_name": doc["name"] if doc else None,
             "detail": {"reason": "no_access" if level == 0 else "insufficient_level"}}
    # No access at all -> 404 (existence is not revealed). Some access but not enough -> 403.
    if level == 0:
        raise ApiError(404, "not found", audit)
    raise ApiError(403, "insufficient permission", audit)


def fetch_doc_unchecked(doc_id: int, include_deleted: bool = False):
    """No authorization. Only used by the mutation-testing script to simulate a removed check."""
    doc = _load(doc_id, include_deleted)
    if doc is None:
        raise ApiError(404, "not found")
    return doc


def requires(kind: str):
    """kind: 'public' | 'user' (any logged-in user; document routes then call authorize())
    | 'owner' (role owner) | 'admin' (role admin)."""
    assert kind in ("public", "user", "owner", "admin")

    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if kind != "public":
                if g.user is None:
                    raise ApiError(401, "authentication required")
                if kind in ("owner", "admin") and g.user["role"] != kind:
                    raise ApiError(403, "forbidden", {"action": "role_refused",
                                                      "detail": {"endpoint": request.endpoint, "needs": kind}})
            return fn(*a, **kw)
        wrapper._authz = kind
        return wrapper
    return deco
