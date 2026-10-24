import io
import zipfile

from .helpers import PDF, WorldTest


def zip_bytes(entries):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in entries.items():
            z.writestr(n, d)
    return b.getvalue()


class UploadTest(WorldTest):
    def up(self, name, content, who="alice", **extra):
        return self.w.client(who).post("/api/documents", data={"file": (io.BytesIO(content), name), **extra},
                                       content_type="multipart/form-data")

    def test_rejects_wrong_content_for_extension(self):
        for name, content in [("a.pdf", b"MZ\x90\x00 not a pdf"), ("a.png", PDF), ("a.jpg", b"GIF89a"),
                              ("a.txt", b"hello\x00world"), ("a.txt", b"\xff\xfe\xfa"), ("a.docx", b"PK not really"),
                              ("a.docx", zip_bytes({"hello.txt": "x"}))]:
            self.assertEqual(self.up(name, content).status_code, 415, name)

    def test_rejects_active_content_types_and_unknown_extensions(self):
        for name in ("page.html", "image.svg", "run.exe", "script.js", "noextension", "a.pdf.exe", "a.PHP"):
            self.assertEqual(self.up(name, b"<script>alert(1)</script>").status_code, 415, name)

    def test_accepts_valid_files(self):
        self.assertEqual(self.up("ok.pdf", PDF).status_code, 201)
        self.assertEqual(self.up("ok.txt", "héllo".encode()).status_code, 201)
        docx = zip_bytes({"[Content_Types].xml": "<x/>", "word/document.xml": "<d/>"})
        self.assertEqual(self.up("ok.docx", docx).status_code, 201)

    def test_zip_bomb_and_zip_slip_rejected(self):
        bomb = zip_bytes({"[Content_Types].xml": "<x/>", "word/document.xml": "A" * (60 * 1024 * 1024)})
        self.assertLess(len(bomb), 1024 * 1024)
        self.assertEqual(self.up("bomb.docx", bomb).status_code, 415)
        slip = zip_bytes({"[Content_Types].xml": "<x/>", "word/document.xml": "<d/>", "../../evil": "x"})
        self.assertEqual(self.up("slip.docx", slip).status_code, 415)

    def test_total_uncompressed_size_cap(self):
        import os
        from trustvault import files
        files.ZIP_MAX_UNCOMPRESSED, old = 1024, files.ZIP_MAX_UNCOMPRESSED
        self.addCleanup(setattr, files, "ZIP_MAX_UNCOMPRESSED", old)
        big = zip_bytes({"[Content_Types].xml": "<x/>", "word/document.xml": os.urandom(4096)})  # incompressible: ratio ~1
        self.assertEqual(self.up("big.docx", big).status_code, 415)

    def test_size_limit(self):
        self.w.app.config["MAX_UPLOAD_BYTES"] = 1024
        self.assertEqual(self.up("big.txt", b"a" * 2048).status_code, 413)
        self.assertEqual(self.up("small.txt", b"a" * 100).status_code, 201)

    def test_path_traversal_in_filename_is_neutralised(self):
        r = self.up("../../../etc/passwd.txt", b"x")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["name"], "passwd.txt")
        r = self.up("..\\..\\windows\\evil.txt", b"x")
        self.assertEqual(r.status_code, 201)
        name = r.get_json()["name"]
        # Exact result depends on the Werkzeug version; what matters is that no path survives.
        self.assertNotIn("/", name)
        self.assertNotIn("\\", name)
        self.assertFalse(name.startswith("."))
        self.assertTrue(name.endswith("evil.txt"))
        import os
        for f in os.listdir(self.w.app.config["STORAGE_DIR"]):
            self.assertRegex(f, r"^[0-9a-f]{32}$")  # blob names are random keys, never user input

    def test_download_headers_prevent_inline_rendering_and_caching(self):
        doc = self.w.upload("alice", "notes.txt", b"<script>alert(1)</script>")
        r = self.w.client("alice").get(f"/api/documents/{doc}/download")
        self.assertIn("attachment", r.headers["Content-Disposition"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("no-store", r.headers["Cache-Control"])
        self.assertIn("private", r.headers["Cache-Control"])
        self.assertEqual(r.data, b"<script>alert(1)</script>")

    def test_client_supplied_content_type_is_ignored(self):
        r = self.w.client("alice").post("/api/documents", content_type="multipart/form-data",
                                        data={"file": (io.BytesIO(b"x"), "a.txt", "text/html")})
        doc = r.get_json()["id"]
        self.assertEqual(self.w.client("alice").get(f"/api/documents/{doc}/download").mimetype, "text/plain")

    def test_replacing_content_is_validated_and_old_blob_removed(self):
        import os
        doc = self.w.upload("alice", "a.pdf", PDF)
        bad = self.w.client("alice").put(f"/api/documents/{doc}/content", content_type="multipart/form-data",
                                         data={"file": (io.BytesIO(b"MZ"), "a.pdf")})
        self.assertEqual(bad.status_code, 415)
        good = self.w.client("alice").put(f"/api/documents/{doc}/content", content_type="multipart/form-data",
                                          data={"file": (io.BytesIO(PDF + b"v2"), "a.pdf")})
        self.assertEqual(good.status_code, 200)
        self.assertEqual(len(os.listdir(self.w.app.config["STORAGE_DIR"])), 1)
        self.assertEqual(self.w.client("alice").get(f"/api/documents/{doc}/download").data, PDF + b"v2")


class MassAssignmentAndInputTest(WorldTest):
    def test_unknown_fields_rejected_not_applied(self):
        doc = self.w.upload("alice")
        self.w.grant("alice", doc, "bob", "edit")
        bob = self.w.client("bob")
        for body in ({"owner_id": self.w.ids["bob"]}, {"category": "x", "deleted_at": None}, {"storage_key": "../x"}):
            self.assertEqual(bob.patch(f"/api/documents/{doc}", json=body).status_code, 400)
        self.assertEqual(self.w.sql("SELECT owner_id FROM documents WHERE id=?", (doc,))[0][0], self.w.ids["alice"])
        self.assertEqual(self.w.client("alice").post(f"/api/documents/{doc}/grants",
                         json={"email": "carol@x.test", "level": "read", "granted_by": 1}).status_code, 400)

    def test_upload_form_cannot_set_owner(self):
        r = self.w.client("alice").post("/api/documents", content_type="multipart/form-data",
                                        data={"file": (io.BytesIO(b"x"), "a.txt"), "owner_id": str(self.w.ids["bob"])})
        self.assertEqual(r.get_json()["owner_id"], self.w.ids["alice"])

    def test_users_cannot_change_their_own_role(self):
        c = self.w.client("carol")
        self.assertEqual(c.patch(f"/api/admin/users/{self.w.ids['carol']}", json={"role": "admin"}).status_code, 403)

    def test_bad_json_and_bad_types(self):
        c = self.w.client("alice")
        doc = self.w.upload("alice")
        self.assertEqual(c.post(f"/api/documents/{doc}/grants", data="not json", content_type="application/json").status_code, 400)
        self.assertEqual(c.post(f"/api/documents/{doc}/grants", json={"email": ["a"], "level": {"x": 1}}).status_code, 400)
        self.assertEqual(c.get("/api/documents?limit=abc").status_code, 400)
        self.assertEqual(c.get("/api/nope").status_code, 404)
