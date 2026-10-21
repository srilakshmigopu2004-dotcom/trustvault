import json
import sqlite3

from .helpers import WorldTest


class AuditTest(WorldTest):
    def actions(self, **where):
        q = "SELECT action, outcome, actor_email, doc_id, detail FROM audit_log ORDER BY id"
        return [dict(zip(("action", "outcome", "actor", "doc_id", "detail"), r)) for r in self.w.sql(q)]

    def test_events_are_recorded(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "carol")
        self.w.client("carol").get(f"/api/documents/{doc}/download")
        self.w.client("alice").patch(f"/api/documents/{doc}", json={"category": "hr"})
        self.w.client("alice").delete(f"/api/documents/{doc}/grants/{self.w.ids['carol']}")
        self.w.client("alice").delete(f"/api/documents/{doc}")
        seen = {(a["action"], a["outcome"]) for a in self.actions()}
        for want in [("login", "ok"), ("upload", "ok"), ("grant_added", "ok"), ("download", "ok"),
                     ("metadata_change", "ok"), ("grant_revoked", "ok"), ("delete", "ok")]:
            self.assertIn(want, seen)

    def test_refused_attempts_are_recorded_and_leave_no_side_effects(self):
        doc = self.w.upload("alice")
        before = self.w.sql("SELECT updated_at, deleted_at FROM documents WHERE id=?", (doc,))[0]
        for r in (self.w.client("dave").get(f"/api/documents/{doc}/download"),
                  self.w.client("dave").delete(f"/api/documents/{doc}"),
                  self.w.client("dave").post(f"/api/documents/{doc}/grants", json={"email": "dave@x.test", "level": "read"})):
            self.assertEqual(r.status_code, 404)
        self.assertEqual(self.w.sql("SELECT updated_at, deleted_at FROM documents WHERE id=?", (doc,))[0][:], before[:])
        refused = [a for a in self.actions() if a["outcome"] == "denied" and a["actor"] == "dave@x.test"]
        self.assertEqual(sorted(a["action"] for a in refused), ["delete_refused", "download_refused", "manage_refused"])
        self.assertTrue(all(a["doc_id"] == doc for a in refused))

    def test_failed_logins_and_role_refusals_are_recorded(self):
        self.w.anon().login("alice@x.test", "wrong-password-123")
        self.w.client("carol").get("/api/admin/audit")
        seen = {(a["action"], a["outcome"]) for a in self.actions()}
        self.assertIn(("login_failed", "denied"), seen)
        self.assertIn(("role_refused", "denied"), seen)

    def test_rejected_upload_is_recorded(self):
        import io
        r = self.w.client("alice").post("/api/documents", data={"file": (io.BytesIO(b"MZ\x90"), "evil.pdf")},
                                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 415)
        self.assertIn(("upload", "rejected"), {(a["action"], a["outcome"]) for a in self.actions()})

    def test_database_rejects_update_and_delete(self):
        self.w.upload("alice")
        conn = sqlite3.connect(self.w.app.config["DB_PATH"])
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit_log SET action='nothing' WHERE id=1")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM audit_log")
        conn.close()

    def test_chain_verifies_then_detects_tampering_even_if_triggers_are_dropped(self):
        doc = self.w.upload("alice")
        self.w.client("alice").delete(f"/api/documents/{doc}")
        admin = self.w.client("admin")
        self.assertTrue(admin.get("/api/admin/audit/verify").get_json()["ok"])
        conn = sqlite3.connect(self.w.app.config["DB_PATH"])  # attacker with raw DB write access
        conn.execute("DROP TRIGGER audit_no_update")
        conn.execute("UPDATE audit_log SET action='download', actor_email='someone.else@x.test' WHERE action='delete'")
        conn.commit(); conn.close()
        res = admin.get("/api/admin/audit/verify").get_json()
        self.assertFalse(res["ok"])
        self.assertIsNotNone(res["first_bad_id"])

    def test_attacker_cannot_forge_rows_without_the_server_key(self):
        self.w.upload("alice")
        conn = sqlite3.connect(self.w.app.config["DB_PATH"])
        conn.execute("DROP TRIGGER audit_no_update")
        last = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()[0]
        import hashlib
        fake = hashlib.sha256(last.encode()).hexdigest()  # plain SHA-256: an attacker cannot know the HMAC key
        conn.execute("INSERT INTO audit_log(ts,action,outcome,detail,prev_hash,hash) VALUES('t','forged','ok','{}',?,?)", (last, fake))
        conn.commit(); conn.close()
        self.assertFalse(self.w.client("admin").get("/api/admin/audit/verify").get_json()["ok"])

    def test_admin_activity_flags_repeated_refusals(self):
        doc = self.w.upload("alice")
        for _ in range(5):
            self.w.client("dave").get(f"/api/documents/{doc}")
        data = self.w.client("admin").get("/api/admin/activity").get_json()
        self.assertTrue(any(a["kind"] == "repeated_refused_access" and a["actor"] == "dave@x.test" for a in data["alerts"]))

    def test_user_supplied_text_cannot_forge_log_lines(self):
        import io
        self.w.client("alice").post("/api/documents", data={"file": (io.BytesIO(b"x"), "a\nfake_action.txt")},
                                    content_type="multipart/form-data")
        for a in self.w.client("admin").get("/api/admin/audit").get_json()["items"]:
            self.assertNotIn("\n", json.dumps(a["doc_name"] or ""))
