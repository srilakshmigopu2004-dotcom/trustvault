from .helpers import PASSWORD, WorldTest


class AuthTest(WorldTest):
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
