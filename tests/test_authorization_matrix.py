"""One user must never reach another user's documents, through ANY document route.

Every route containing <int:doc_id> must appear in MATRIX (test_every_document_route_is_in_matrix
fails otherwise), and is exercised as every kind of actor with the expected status.
"""
import io
import unittest

from .helpers import World, WorldTest

# actors: alice = owner of the doc; bob = edit grant; carol = read grant; dave = viewer without grant;
# erin = another owner without grant; frank = had a grant, now revoked; admin; anonymous.
ACTORS = ["alice", "bob", "carol", "dave", "erin", "frank", "admin", "anon"]

NO_ACCESS = dict(dave=404, erin=404, frank=404, admin=404, anon=401)


def exp(alice, bob, carol):
    return dict(alice=alice, bob=bob, carol=carol, **NO_ACCESS)


def txt():
    return {"file": (io.BytesIO(b"replacement"), "secret.txt")}


# (method, rule, builder(world, doc_id) -> kwargs, prep, expected)
MATRIX = [
    ("GET", "/api/documents/<int:doc_id>", lambda w, d: {}, None, exp(200, 200, 200)),
    ("GET", "/api/documents/<int:doc_id>/download", lambda w, d: {}, None, exp(200, 200, 200)),
    ("PATCH", "/api/documents/<int:doc_id>", lambda w, d: {"json": {"category": "hr"}}, None, exp(200, 200, 403)),
    ("PUT", "/api/documents/<int:doc_id>/content",
     lambda w, d: {"data": txt(), "content_type": "multipart/form-data"}, None, exp(200, 200, 403)),
    ("DELETE", "/api/documents/<int:doc_id>", lambda w, d: {}, None, exp(200, 403, 403)),
    ("POST", "/api/documents/<int:doc_id>/restore", lambda w, d: {}, "delete", exp(200, 403, 403)),
    ("GET", "/api/documents/<int:doc_id>/grants", lambda w, d: {}, None, exp(200, 403, 403)),
    ("POST", "/api/documents/<int:doc_id>/grants",
     lambda w, d: {"json": {"email": "erin@x.test", "level": "read"}}, None, exp(201, 403, 403)),
    ("DELETE", "/api/documents/<int:doc_id>/grants/<int:user_id>", lambda w, d: {}, None, exp(200, 403, 403)),
    ("POST", "/api/documents/<int:doc_id>/suggestions", lambda w, d: {}, None, exp(200, 403, 403)),
    ("GET", "/api/documents/<int:doc_id>/audit", lambda w, d: {}, None, exp(200, 403, 403)),
]


def build_url(rule, doc_id, w):
    return rule.replace("<int:doc_id>", str(doc_id)).replace("<int:user_id>", str(w.ids["carol"]))


class MatrixTest(unittest.TestCase):
    def fresh(self):
        w = World()
        self.addCleanup(w.close)
        doc = w.upload("alice")
        w.grant("alice", doc, "bob", "edit")
        w.grant("alice", doc, "carol", "read")
        w.grant("alice", doc, "frank", "read")
        r = w.client("alice").delete(f"/api/documents/{doc}/grants/{w.ids['frank']}")
        self.assertEqual(r.status_code, 200)
        return w, doc

    def test_matrix(self):
        for method, rule, build, prep, expected in MATRIX:
            for actor in ACTORS:
                with self.subTest(route=f"{method} {rule}", actor=actor):
                    w, doc = self.fresh()
                    if prep == "delete":
                        self.assertEqual(w.client("alice").delete(f"/api/documents/{doc}").status_code, 200)
                    client = w.anon() if actor == "anon" else w.client(actor)
                    r = client.c.open(build_url(rule, doc, w), method=method,
                                      headers=client._h(), **build(w, doc))
                    self.assertEqual(r.status_code, expected[actor], r.get_json())

    def test_every_document_route_is_in_matrix(self):
        from trustvault import create_app
        import tempfile, os
        app = create_app({"DB_PATH": os.path.join(tempfile.mkdtemp(), "x.db"), "AUDIT_KEY": b"k" * 20,
                          "STORAGE_DIR": tempfile.mkdtemp(), "COOKIE_SECURE": False})
        in_matrix = {(m, r) for m, r, *_ in MATRIX}
        for rule in app.url_map.iter_rules():
            if "<int:doc_id>" in rule.rule:
                for m in rule.methods - {"HEAD", "OPTIONS"}:
                    self.assertIn((m, rule.rule), in_matrix, f"{m} {rule.rule} has no authorization-matrix test")

    def test_every_api_route_declares_its_role_gate(self):
        from trustvault import create_app
        import tempfile, os
        app = create_app({"DB_PATH": os.path.join(tempfile.mkdtemp(), "x.db"), "AUDIT_KEY": b"k" * 20,
                          "STORAGE_DIR": tempfile.mkdtemp(), "COOKIE_SECURE": False})
        for rule in app.url_map.iter_rules():
            if rule.rule.startswith("/api/"):
                fn = app.view_functions[rule.endpoint]
                self.assertIn(getattr(fn, "_authz", None), ("public", "user", "owner", "admin"),
                              f"{rule.rule} does not declare @requires(...)")


class RoleGateTest(WorldTest):
    def test_upload_roles(self):
        for who, status in (("alice", 201), ("dave", 403), ("admin", 403)):
            r = self.w.client(who).post("/api/documents", data={"file": (io.BytesIO(b"x"), "a.txt")},
                                        content_type="multipart/form-data")
            self.assertEqual(r.status_code, status, who)
        self.assertEqual(self.w.anon().post("/api/documents").status_code, 401)

    def test_admin_endpoints_are_admin_only(self):
        for url in ("/api/admin/users", "/api/admin/audit", "/api/admin/audit/verify",
                    "/api/admin/audit/head", "/api/admin/activity"):
            self.assertEqual(self.w.client("admin").get(url).status_code, 200, url)
            for who in ("alice", "carol"):
                self.assertEqual(self.w.client(who).get(url).status_code, 403, (who, url))
            self.assertEqual(self.w.anon().get(url).status_code, 401, url)

    def test_ids_are_not_guessable_by_enumeration(self):
        doc = self.w.upload("alice")
        missing = self.w.client("dave").get("/api/documents/99999")
        hidden = self.w.client("dave").get(f"/api/documents/{doc}")
        self.assertEqual((missing.status_code, missing.get_json()), (hidden.status_code, hidden.get_json()))


if __name__ == "__main__":
    unittest.main()
