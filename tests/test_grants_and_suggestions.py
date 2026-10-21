from .helpers import WorldTest


class GrantRulesTest(WorldTest):
    def grant(self, who, doc, email, level="read", **extra):
        return self.w.client(who).post(f"/api/documents/{doc}/grants", json={"email": email, "level": level, **extra})

    def test_invalid_targets_all_get_the_same_generic_refusal(self):
        doc = self.w.upload("alice")
        results = {
            "unknown": self.grant("alice", doc, "nobody@x.test"),
            "admin": self.grant("alice", doc, "admin@x.test"),
            "self": self.grant("alice", doc, "alice@x.test"),
            "viewer_edit": self.grant("alice", doc, "carol@x.test", "edit"),
        }
        for k, r in results.items():
            self.assertEqual((r.status_code, r.get_json()), (422, results["unknown"].get_json()), k)

    def test_cannot_grant_to_deactivated_user(self):
        doc = self.w.upload("alice")
        self.w.client("admin").patch(f"/api/admin/users/{self.w.ids['carol']}", json={"active": False})
        self.assertEqual(self.grant("alice", doc, "carol@x.test").status_code, 422)

    def test_grantee_cannot_widen_own_or_anyone_elses_access(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "bob", "edit")
        self.assertEqual(self.grant("bob", doc, "bob@x.test", "edit").status_code, 403)
        self.assertEqual(self.grant("bob", doc, "erin@x.test").status_code, 403)
        self.assertEqual(self.w.client("bob").delete(f"/api/documents/{doc}/grants/{self.w.ids['bob']}").status_code, 403)

    def test_changing_level_updates_single_active_grant(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "bob", "read")
        self.assertEqual(self.w.client("bob").patch(f"/api/documents/{doc}", json={"category": "x"}).status_code, 403)
        self.w.grant("alice", doc, "bob", "edit")
        self.assertEqual(self.w.client("bob").patch(f"/api/documents/{doc}", json={"category": "x"}).status_code, 200)
        self.assertEqual(len(self.w.client("alice").get(f"/api/documents/{doc}/grants").get_json()["items"]), 1)

    def test_grants_on_one_document_do_not_leak_to_another(self):
        d1, d2 = self.w.upload("alice", "one.txt"), self.w.upload("alice", "two.txt")
        self.w.grant("alice", d1, "carol")
        self.assertEqual(self.w.client("carol").get(f"/api/documents/{d1}").status_code, 200)
        self.assertEqual(self.w.client("carol").get(f"/api/documents/{d2}").status_code, 404)


class SuggestionTest(WorldTest):
    def setUp(self):
        super().setUp()
        self.a1 = self.w.upload("alice", "a1.txt", category="hr")
        self.a2 = self.w.upload("alice", "a2.txt", category="hr")
        self.w.grant("alice", self.a1, "carol")

    def suggest(self, who="alice", doc=None):
        return self.w.client(who).post(f"/api/documents/{doc or self.a2}/suggestions")

    def test_suggestion_changes_no_access(self):
        r = self.suggest()
        self.assertEqual(r.status_code, 200)
        self.assertEqual([c["email"] for c in r.get_json()["candidates"]], ["carol@x.test"])
        self.assertEqual(self.w.client("carol").get(f"/api/documents/{self.a2}").status_code, 404)  # still no access

    def test_human_confirmation_required_and_both_steps_audited(self):
        sid = self.suggest().get_json()["suggestion_id"]
        r = self.w.client("alice").post(f"/api/documents/{self.a2}/grants",
                                        json={"email": "carol@x.test", "level": "read", "suggestion_id": sid})
        self.assertEqual(r.status_code, 201)
        rows = self.w.sql("SELECT action, detail FROM audit_log WHERE doc_id=? ORDER BY id", (self.a2,))
        actions = [r[0] for r in rows]
        self.assertIn("ai_suggestion", actions)
        self.assertLess(actions.index("ai_suggestion"), actions.index("grant_added"))
        self.assertIn(f'"via_suggestion": {sid}', [r[1] for r in rows if r[0] == "grant_added"][0])

    def test_suggestion_is_bound_to_document_requester_and_candidate(self):
        sid = self.suggest().get_json()["suggestion_id"]
        bad = lambda who, doc, email: self.w.client(who).post(
            f"/api/documents/{doc}/grants", json={"email": email, "level": "read", "suggestion_id": sid}).status_code
        self.assertEqual(bad("alice", self.a1, "carol@x.test"), 422)   # other document
        self.assertEqual(bad("alice", self.a2, "dave@x.test"), 422)    # not a suggested candidate
        self.assertEqual(self.w.client("alice").post(f"/api/documents/{self.a2}/grants",
                         json={"email": "carol@x.test", "level": "read", "suggestion_id": "1 OR 1=1"}).status_code, 422)

    def test_only_manager_can_request_suggestions(self):
        self.w.grant("alice", self.a2, "bob", "edit")
        self.assertEqual(self.suggest("bob").status_code, 403)
        self.assertEqual(self.suggest("dave").status_code, 404)
