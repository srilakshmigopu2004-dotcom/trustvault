"""Idempotent demo data. Usage: TV_AUDIT_KEY=... python -m trustvault.seed
Demo password comes from TV_SEED_PASSWORD (default below). Change it on any shared deployment."""
import os
import sys

from . import audit, auth, create_app, db as dbm, files
from .util import now

PASSWORD = os.environ.get("TV_SEED_PASSWORD", "TrustVault-Demo-2026!")
USERS = [
    ("admin@trustvault.test", "Ada Admin", "admin"),
    ("alice@trustvault.test", "Alice Owner", "owner"),
    ("bob@trustvault.test", "Bob Owner", "owner"),
    ("carol@trustvault.test", "Carol Viewer", "viewer"),
    ("dave@trustvault.test", "Dave Viewer", "viewer"),
]
PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
DOCS = [  # owner, name, category, content, [(grantee, level)]
    ("alice@trustvault.test", "salary-letter-carol.pdf", "hr", PDF, [("carol@trustvault.test", "read")]),
    ("alice@trustvault.test", "salary-letter-dave.pdf", "hr", PDF, [("dave@trustvault.test", "read")]),
    ("alice@trustvault.test", "contract-acme.txt", "contracts", b"Acme master services agreement (demo).\n",
     [("bob@trustvault.test", "edit"), ("carol@trustvault.test", "read")]),
    ("bob@trustvault.test", "drawing-rev-b.pdf", "engineering", PDF, []),
]


def main():
    app = create_app()
    with app.app_context(), app.test_request_context():
        conn = dbm.connect(app.config["DB_PATH"])
        try:
            if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                print("already seeded")
                return
            conn.execute("BEGIN IMMEDIATE")
            ids = {}
            for email, name, role in USERS:
                cur = conn.execute("INSERT INTO users(email,name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                                   (email, name, auth.hash_password(PASSWORD), role, now()))
                ids[email] = cur.lastrowid
            for owner, name, cat, content, grants in DOCS:
                mime = files.validate(name, content)
                key, sha = files.store(content)
                ts = now()
                cur = conn.execute("INSERT INTO documents(name,category,owner_id,storage_key,mime,size,sha256,created_at,updated_at)"
                                   " VALUES(?,?,?,?,?,?,?,?,?)", (name, cat, ids[owner], key, mime, len(content), sha, ts, ts))
                actor = {"id": ids[owner], "email": owner}
                audit.append(conn, actor, "upload", doc_id=cur.lastrowid, doc_name=name, detail={"seed": True, "sha256": sha})
                for grantee, level in grants:
                    conn.execute("INSERT INTO grants(document_id,user_id,level,granted_by,granted_at) VALUES(?,?,?,?,?)",
                                 (cur.lastrowid, ids[grantee], level, ids[owner], ts))
                    audit.append(conn, actor, "grant_added", doc_id=cur.lastrowid, doc_name=name,
                                 detail={"seed": True, "user_id": ids[grantee], "email": grantee, "level": level})
            conn.commit()
            print("seeded; demo password:", PASSWORD)
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
