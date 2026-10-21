import io

from .helpers import WorldTest


class RevocationTest(WorldTest):
    def test_revoke_takes_effect_immediately_for_existing_session(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "carol")
        carol = self.w.client("carol")  # session issued BEFORE the revoke
        self.assertEqual(carol.get(f"/api/documents/{doc}/download").status_code, 200)
        self.assertEqual(self.w.client("alice").delete(f"/api/documents/{doc}/grants/{self.w.ids['carol']}").status_code, 200)
        self.assertEqual(carol.get(f"/api/documents/{doc}/download").status_code, 404)
        self.assertEqual(carol.get(f"/api/documents/{doc}").status_code, 404)
        self.assertEqual(carol.get("/api/documents").get_json()["total"], 0)

    def test_regrant_after_revoke_works(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "carol")
        self.w.client("alice").delete(f"/api/documents/{doc}/grants/{self.w.ids['carol']}")
        self.w.grant("alice", doc, "carol")
        self.assertEqual(self.w.client("carol").get(f"/api/documents/{doc}").status_code, 200)

    def test_deactivating_a_user_kills_sessions(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "carol")
        carol = self.w.client("carol")
        r = self.w.client("admin").patch(f"/api/admin/users/{self.w.ids['carol']}", json={"active": False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(carol.get(f"/api/documents/{doc}/download").status_code, 401)
        self.assertEqual(self.w.anon().login("carol@x.test").status_code, 401)  # cannot log back in either

    def test_logout_invalidates_session_server_side(self):
        c = self.w.client("alice")
        stolen_cookie = c.c.get_cookie("tv_session").value
        self.assertEqual(c.post("/api/auth/logout").status_code, 200)
        other = self.w.anon()
        other.c.set_cookie("tv_session", stolen_cookie)
        self.assertEqual(other.get("/api/auth/me").status_code, 401)

    def test_deleted_document_is_unreachable_even_for_owner_and_grantees(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "carol")
        self.w.client("alice").delete(f"/api/documents/{doc}")
        for who in ("alice", "carol"):
            self.assertEqual(self.w.client(who).get(f"/api/documents/{doc}/download").status_code, 404)
            self.assertEqual(self.w.client(who).get("/api/documents").get_json()["total"], 0)
        self.assertEqual(self.w.client("alice").post(f"/api/documents/{doc}/restore").status_code, 200)
        self.assertEqual(self.w.client("carol").get(f"/api/documents/{doc}/download").status_code, 200)

    def test_demotion_to_viewer_caps_edit_grant_and_promotion_to_admin_removes_access(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "bob", "edit")
        bob = self.w.client("bob")
        self.assertEqual(bob.patch(f"/api/documents/{doc}", json={"category": "x"}).status_code, 200)
        self.w.client("admin").patch(f"/api/admin/users/{self.w.ids['bob']}", json={"role": "viewer"})
        bob = self.w.client("bob") if False else bob
        bob = self.w.anon(); bob.login("bob@x.test")
        self.assertEqual(bob.patch(f"/api/documents/{doc}", json={"category": "y"}).status_code, 403)
        self.assertEqual(bob.get(f"/api/documents/{doc}").status_code, 200)
        self.w.client("admin").patch(f"/api/admin/users/{self.w.ids['bob']}", json={"role": "admin"})
        bob = self.w.anon(); bob.login("bob@x.test")
        self.assertEqual(bob.get(f"/api/documents/{doc}").status_code, 404)
        self.assertEqual(bob.get("/api/documents").get_json()["total"], 0)


class SearchTest(WorldTest):
    def test_search_never_returns_or_counts_inaccessible_documents(self):
        mine = self.w.upload("alice", "alpha-plan.txt", category="hr")
        shared = self.w.upload("alice", "alpha-shared.txt", category="hr")
        self.w.upload("bob", "alpha-bob-secret.txt", category="hr")
        self.w.grant("alice", shared, "carol")
        names = lambda who, qs="": sorted(i["name"] for i in self.w.client(who).get("/api/documents" + qs).get_json()["items"])
        self.assertEqual(names("alice", "?q=alpha"), ["alpha-plan.txt", "alpha-shared.txt"])
        self.assertEqual(names("carol", "?q=alpha"), ["alpha-shared.txt"])
        self.assertEqual(names("dave", "?q=alpha"), [])
        self.assertEqual(names("dave", "?owner=bob"), [])
        self.assertEqual(self.w.client("carol").get("/api/documents?q=bob-secret").get_json()["total"], 0)
        self.assertEqual(self.w.client("admin").get("/api/documents").get_json()["total"], 0)
        # paging happens after the access filter, so totals never include hidden rows
        r = self.w.client("carol").get("/api/documents?limit=1").get_json()
        self.assertEqual((r["total"], len(r["items"])), (1, 1))

    def test_filters_and_wildcards(self):
        self.w.upload("alice", "a_b.txt", category="hr")
        self.w.upload("alice", "axb.txt", category="legal")
        c = self.w.client("alice")
        self.assertEqual([i["name"] for i in c.get("/api/documents?q=a_b").get_json()["items"]], ["a_b.txt"])  # '_' is literal
        self.assertEqual(c.get("/api/documents?q=%25").get_json()["total"], 0)  # '%' is literal
        self.assertEqual(c.get("/api/documents?category=legal").get_json()["total"], 1)
        self.assertEqual(c.get("/api/documents?owner=alice").get_json()["total"], 2)
        self.assertEqual(c.get("/api/documents?date_from=2000-01-01&date_to=2100-01-01").get_json()["total"], 2)
        self.assertEqual(c.get("/api/documents?date_to=2000-01-01").get_json()["total"], 0)
        self.assertEqual(c.get("/api/documents?date_from=garbage").status_code, 400)
        self.assertEqual(c.get("/api/documents?q=' OR 1=1 --").get_json()["total"], 0)  # injection is just a string
