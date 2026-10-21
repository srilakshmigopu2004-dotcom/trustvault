import io
import os
import shutil
import tempfile
import unittest

from werkzeug.security import generate_password_hash

from trustvault import create_app, db as dbm
from trustvault.util import now

PASSWORD = "correct-horse-battery-1"
PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"
HASH = "pbkdf2:sha256:1000"  # fast hashes for tests only


class World:
    """A fresh app + DB with one user per scenario role, and one document owned by alice."""
    ROLES = {  # name -> (role)
        "admin": "admin", "alice": "owner", "bob": "owner", "carol": "viewer", "dave": "viewer",
        "erin": "owner", "frank": "viewer",
    }

    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="tv-test-")
        self.app = create_app({
            "TESTING": True, "DB_PATH": os.path.join(self.tmp, "t.db"), "STORAGE_DIR": os.path.join(self.tmp, "blobs"),
            "AUDIT_KEY": b"test-audit-key-0123456789", "COOKIE_SECURE": False, "HASH_METHOD": HASH,
        })
        self.ids = {}
        conn = dbm.connect(self.app.config["DB_PATH"])
        for name, role in self.ROLES.items():
            cur = conn.execute("INSERT INTO users(email,name,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                               (f"{name}@x.test", name.title(), generate_password_hash(PASSWORD, method=HASH), role, now()))
            self.ids[name] = cur.lastrowid
        conn.close()
        self.clients = {}

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def client(self, name):
        """Logged-in client for `name` (cached). Sends the CSRF header automatically."""
        if name not in self.clients:
            c = Client(self.app)
            c.login(f"{name}@x.test")
            self.clients[name] = c
        return self.clients[name]

    def anon(self):
        return Client(self.app)

    def sql(self, query, args=()):
        conn = dbm.connect(self.app.config["DB_PATH"])
        try:
            cur = conn.execute(query, args)
            return cur.fetchall()
        finally:
            conn.close()

    def upload(self, who, name="secret.txt", content=b"top secret text", category="general"):
        r = self.client(who).post("/api/documents", data={"file": (io.BytesIO(content), name), "category": category},
                                  content_type="multipart/form-data")
        assert r.status_code == 201, r.get_json()
        return r.get_json()["id"]

    def grant(self, owner, doc_id, who, level="read"):
        r = self.client(owner).post(f"/api/documents/{doc_id}/grants", json={"email": f"{who}@x.test", "level": level})
        assert r.status_code in (200, 201), r.get_json()


class Client:
    def __init__(self, app):
        self.c = app.test_client()
        self.csrf = ""

    def login(self, email, password=PASSWORD):
        r = self.c.post("/api/auth/login", json={"email": email, "password": password})
        if r.status_code == 200:
            self.csrf = r.get_json()["csrf"]
        return r

    def _h(self):
        return {"X-CSRF-Token": self.csrf} if self.csrf else {}

    def get(self, url, **kw):
        return self.c.get(url, headers=self._h(), **kw)

    def post(self, url, **kw):
        return self.c.post(url, headers=self._h(), **kw)

    def put(self, url, **kw):
        return self.c.put(url, headers=self._h(), **kw)

    def patch(self, url, **kw):
        return self.c.patch(url, headers=self._h(), **kw)

    def delete(self, url, **kw):
        return self.c.delete(url, headers=self._h(), **kw)


class WorldTest(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.addCleanup(self.w.close)
