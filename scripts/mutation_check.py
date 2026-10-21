"""Mutation check: remove one security control at a time and confirm the test-suite FAILS.
A mutant that survives means a control exists that no test would miss.

    python scripts/mutation_check.py
Exit code 1 if any mutant survives.
"""
import concurrent.futures as cf
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUTHZ_CALL = re.compile(r'authorize\(g\.user, doc_id, "[a-z]+"(?:, include_deleted=True)?\)')

# (label, file, old, new)  -- literal text replacements
STATIC = [
    ("grant lookup ignores revocation", "authz.py", "AND revoked_at IS NULL\"", "\""),
    ("admins get content access", "authz.py", 'user["role"] == "admin" or not user["active"]', "False"),
    ("viewer cap on edit removed", "authz.py", 'return min(raw, RANK["read"]) if user["role"] == "viewer" else raw', "return raw"),
    ("deleted documents reachable", "authz.py", 'row["deleted_at"] is not None and not include_deleted', "False"),
    ("insufficient level allowed", "authz.py", "if level >= need:", "if level >= 0:"),
    ("search ignores grants", "routes.py", "(d.owner_id=:uid OR g.id IS NOT NULL)", "1=1"),
    ("search ignores revocation", "routes.py", "g.user_id=:uid AND g.revoked_at IS NULL", "g.user_id=:uid"),
    ("search ignores soft delete", "routes.py", '"d.deleted_at IS NULL", ', ""),
    ("admin can search content", "routes.py", 'if u["role"] == "admin":\n        return reply({"total": 0, "items": []})', "pass"),
    ("CSRF check removed", "routes.py", 'if g.user and request.endpoint != "api.login" and', "if False and"),
    ("refused attempts not audited", "__init__.py", "if e.audit:", "if False:"),
    ("download not audited", "routes.py", 'audit.log("download",', 'print('),
    ("download served inline", "routes.py", 'resp.headers.set("Content-Disposition", "attachment", filename=doc["name"])', "pass"),
    ("no-store removed", "__init__.py", 'resp.headers["Cache-Control"] = "private, no-store"', "pass"),
    ("nosniff removed", "__init__.py", 'resp.headers["X-Content-Type-Options"] = "nosniff"', "pass"),
    ("audit triggers removed", "schema.sql", "CREATE TRIGGER audit_no_update", "CREATE TABLE _unused1(x); --"),
    ("audit hash not chained", "audit.py", "prev = last[\"hash\"] if last else GENESIS", "prev = GENESIS"),
    ("sessions survive deactivation", "auth.py", "DELETE FROM sessions WHERE user_id=?", "SELECT ?"),
    ("session survives logout", "auth.py", "DELETE FROM sessions WHERE token_hash=?", "SELECT ?"),
    ("grantee may be admin", "routes.py", 'target["role"] == "admin" or ', ""),
    ("viewer may receive edit", "routes.py", 'or (level == "edit" and target["role"] != "owner")', ""),
    ("suggestion binding removed", "routes.py", "s is None or s[\"document_id\"] != doc[\"id\"] or s[\"requested_by\"] != g.user[\"id\"]", "s is None"),
    ("unknown fields accepted", "routes.py", "if extra:\n        raise", "if False:\n        raise"),
    ("magic-byte check removed", "files.py", 'ok = data.startswith(b"%PDF-")', "ok = True"),
    ("zip bomb check removed", "files.py", "if total > ZIP_MAX_UNCOMPRESSED:\n        return False", "pass"),
    ("login lockout removed", "auth.py", "return e >= MAX_FAILS_PER_EMAIL or i >= MAX_FAILS_PER_IP", "return False"),
]


def dynamic():
    src = open(os.path.join(ROOT, "trustvault", "routes.py"), encoding="utf-8").read()
    for i, m in enumerate(AUTHZ_CALL.finditer(src)):
        line = src.count("\n", 0, m.start()) + 1
        yield (f"authorize() removed at routes.py:{line} -> {m.group(0)}", "routes.py", m.group(0), "fetch_doc_unchecked(doc_id, True)")
    for m in re.finditer(r'@requires\("admin"\)', src):
        line = src.count("\n", 0, m.start()) + 1
        yield (f"admin gate removed at routes.py:{line}", "routes.py", "@@ADMIN@@", str(m.start()))
    for m in re.finditer(r'@requires\("owner"\)', src):
        line = src.count("\n", 0, m.start()) + 1
        yield (f"owner-role gate removed at routes.py:{line}", "routes.py", "@@OWNER@@", str(m.start()))


def run(mutant):
    label, fname, old, new = mutant
    tmp = tempfile.mkdtemp(prefix="tv-mut-")
    try:
        dst = os.path.join(tmp, "p")
        shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns("__pycache__", "data", ".git", "*.pyc"))
        path = os.path.join(dst, "trustvault", fname) if fname != "schema.sql" else os.path.join(dst, "trustvault", "schema.sql")
        text = open(path, encoding="utf-8").read()
        if old in ("@@ADMIN@@", "@@OWNER@@"):
            pos = int(new)
            kind = "admin" if old == "@@ADMIN@@" else "owner"
            target = f'@requires("{kind}")'
            assert text[pos:pos + len(target)] == target
            text = text[:pos] + '@requires("user")' + text[pos + len(target):]
        else:
            if old not in text:
                return label, "BROKEN-MUTANT (pattern not found)"
            text = text.replace(old, new, 1)
        open(path, "w", encoding="utf-8").write(text)
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-f"],
                           cwd=dst, capture_output=True, text=True, timeout=600)
        return label, ("killed" if r.returncode != 0 else "SURVIVED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    mutants = [(l, f, o, n) for l, f, o, n in STATIC] + list(dynamic())
    results = []
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        for label, status in pool.map(run, mutants):
            print(f"{status:9s} {label}", flush=True)
            results.append(status)
    bad = [s for s in results if s != "killed"]
    print(f"\n{len(results) - len(bad)}/{len(results)} mutants killed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
