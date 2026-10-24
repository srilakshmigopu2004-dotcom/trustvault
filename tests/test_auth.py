import os
import sqlite3

from trustvault import db as dbm

from .helpers import PASSWORD, WorldTest


class AuthTest(WorldTest):
    def test_demo_passwords_are_distinct_for_each_login_role(self):
        from trustvault.seed import ROLE_PASSWORDS

        self.assertEqual(set(ROLE_PASSWORDS), {"admin", "owner", "viewer"})
        self.assertEqual(len(set(ROLE_PASSWORDS.values())), 3)

    def test_profile_updates_name_phone_and_login_email(self):
        alice = self.w.client("alice")
        result = alice.patch("/api/auth/profile", json={
            "name": "Alice Ledger", "email": "ALICE.NEW@x.test", "phone": "+1 (555) 123-4567",
            "current_password": PASSWORD,
        })
        self.assertEqual(result.status_code, 200, result.get_json())
        self.assertEqual(result.get_json(), {
            "id": self.w.ids["alice"], "email": "alice.new@x.test", "name": "Alice Ledger",
            "phone": "+1 (555) 123-4567", "role": "owner",
        })
        self.assertEqual(alice.get("/api/auth/me").get_json()["phone"], "+1 (555) 123-4567")
        self.assertEqual(self.w.anon().login("alice@x.test", PASSWORD).status_code, 401)
        self.assertEqual(self.w.anon().login("alice.new@x.test", PASSWORD).status_code, 200)
        self.assertEqual(self.w.sql("SELECT action FROM audit_log WHERE action='profile_updated'")[0][0], "profile_updated")

    def test_profile_validates_phone_email_and_email_change_password(self):
        alice = self.w.client("alice")
        wrong_password = alice.patch("/api/auth/profile", json={
            "email": "alice.new@x.test", "current_password": "incorrect-password",
        })
        self.assertEqual(wrong_password.status_code, 403)
        duplicate = alice.patch("/api/auth/profile", json={
            "email": "bob@x.test", "current_password": PASSWORD,
        })
        self.assertEqual(duplicate.status_code, 409)
        invalid_phone = alice.patch("/api/auth/profile", json={"phone": "call me"})
        self.assertEqual(invalid_phone.status_code, 400)
        self.assertEqual(alice.get("/api/auth/me").status_code, 200)

    def test_self_service_password_change_revokes_sessions_and_allows_new_login(self):
        alice = self.w.client("alice")
        new_password = "brand-new-secure-password-9"
        result = alice.post("/api/auth/password", json={
            "current_password": PASSWORD, "new_password": new_password,
        })
        self.assertEqual(result.status_code, 200, result.get_json())
        self.assertEqual(alice.get("/api/auth/me").status_code, 401)
        self.assertEqual(self.w.anon().login("alice@x.test", PASSWORD).status_code, 401)
        self.assertEqual(self.w.anon().login("alice@x.test", new_password).status_code, 200)
        self.assertEqual(self.w.sql("SELECT COUNT(*) FROM audit_log WHERE action='password_changed'")[0][0], 1)

    def test_phone_column_is_added_to_existing_database(self):
        path = os.path.join(self.w.tmp, "legacy.db")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, name TEXT, password_hash TEXT, role TEXT, active INTEGER, created_at TEXT)")
        conn.close()
        dbm.init_db(path)
        conn = sqlite3.connect(path)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        conn.close()
        self.assertIn("phone", columns)

    def test_login_does_not_reveal_which_part_was_wrong(self):
        a = self.w.anon().login("alice@x.test", "wrong-password-xx")
        b = self.w.anon().login("nobody@x.test", "wrong-password-xx")
        self.assertEqual((a.status_code, a.get_json()), (b.status_code, b.get_json()))

    def test_lockout_after_repeated_failures_even_with_right_password(self):
        c = self.w.anon()
        for _ in range(5):
            self.assertEqual(c.login("alice@x.test", "nope-nope-nope").status_code, 401)
        self.assertEqual(c.login("alice@x.test", PASSWORD).status_code, 429)

    def test_cookie_flags(self):
        r = self.w.anon().login("alice@x.test")
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_state_changing_requests_need_csrf_token(self):
        c = self.w.client("alice")
        doc = self.w.upload("alice")
        no_token = c.c.delete(f"/api/documents/{doc}")  # cookie present, header missing
        self.assertEqual(no_token.status_code, 403)
        wrong = c.c.delete(f"/api/documents/{doc}", headers={"X-CSRF-Token": "x" * 32})
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(c.get(f"/api/documents/{doc}").status_code, 200)  # untouched

    def test_new_session_on_every_login_and_client_cannot_choose_it(self):
        c = self.w.anon()
        c.c.set_cookie("tv_session", "attacker-chosen-value")
        c.login("alice@x.test")
        self.assertNotEqual(c.c.get_cookie("tv_session").value, "attacker-chosen-value")

    def test_session_tokens_are_not_stored_in_plaintext(self):
        c = self.w.client("alice")
        token = c.c.get_cookie("tv_session").value
        self.assertEqual(self.w.sql("SELECT COUNT(*) FROM sessions WHERE token_hash=?", (token,))[0][0], 0)

    def test_passwords_are_hashed_and_never_returned(self):
        users = self.w.client("admin").get("/api/admin/users").get_json()["items"]
        self.assertTrue(all("password" not in k for u in users for k in u))
        self.assertNotIn(PASSWORD, str(self.w.sql("SELECT password_hash FROM users")))

    def test_admin_user_management_rules(self):
        admin = self.w.client("admin")
        self.assertEqual(admin.post("/api/admin/users", json={"email": "n@x.test", "name": "N", "password": "short", "role": "viewer"}).status_code, 400)
        self.assertEqual(admin.post("/api/admin/users", json={"email": "n@x.test", "name": "N", "password": PASSWORD, "role": "superuser"}).status_code, 400)
        self.assertEqual(admin.post("/api/admin/users", json={"email": "n@x.test", "name": "N", "password": PASSWORD, "role": "viewer"}).status_code, 201)
        self.assertEqual(admin.post("/api/admin/users", json={"email": "N@x.test", "name": "N", "password": PASSWORD, "role": "viewer"}).status_code, 409)
        self.assertEqual(admin.patch(f"/api/admin/users/{self.w.ids['admin']}", json={"active": False}).status_code, 409)
        self.assertEqual(self.w.anon().login("n@x.test").status_code, 200)
        audit = self.w.sql("SELECT detail FROM audit_log WHERE action='user_created'")
        self.assertNotIn(PASSWORD, str(audit))

    def test_non_admins_cannot_create_users_or_edit_users(self):
        body = {"email": "intruder@x.test", "name": "I", "password": PASSWORD, "role": "admin"}
        for who in ("alice", "carol", "bob"):
            self.assertEqual(self.w.client(who).post("/api/admin/users", json=body).status_code, 403, who)
        self.assertEqual(self.w.anon().post("/api/admin/users", json=body).status_code, 401)
        self.assertEqual(self.w.sql("SELECT COUNT(*) FROM users WHERE email='intruder@x.test'")[0][0], 0)

    def test_password_change_and_role_change_end_existing_sessions(self):
        carol = self.w.client("carol")
        self.assertEqual(carol.get("/api/auth/me").status_code, 200)
        r = self.w.client("admin").patch(f"/api/admin/users/{self.w.ids['carol']}", json={"password": "a-brand-new-password-9"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(carol.get("/api/auth/me").status_code, 401)  # old session is dead
        self.assertEqual(self.w.anon().login("carol@x.test", PASSWORD).status_code, 401)
        self.assertEqual(self.w.anon().login("carol@x.test", "a-brand-new-password-9").status_code, 200)
        dave = self.w.client("dave")
        self.w.client("admin").patch(f"/api/admin/users/{self.w.ids['dave']}", json={"role": "owner"})
        self.assertEqual(dave.get("/api/auth/me").status_code, 401)
