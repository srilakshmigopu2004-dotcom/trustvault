# TrustVault

Secure document sharing where the wrong person cannot read a file, and the record shows who did.
Flask + SQLite, no external services. Server-side authorization on every request.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
export TV_AUDIT_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export TV_INSECURE_COOKIES=1            # local http only; cookies are Secure by default
python -m trustvault.seed               # creates data/ and demo users + documents (idempotent)
flask --app run run                     # http://127.0.0.1:5000
python -m unittest discover -s tests -t .   # 56 tests (plain unittest; pytest should also work)
python scripts/mutation_check.py            # removes each security control in turn; every mutant must be killed
```

Production / clean-clone deploy (any host that runs Docker, with a persistent volume at `/data`):

```bash
docker build -t trustvault .
docker run -p 8000:8000 -v tvdata:/data \
  -e TV_AUDIT_KEY=<32+ random chars> -e TV_SEED_PASSWORD=<demo password> trustvault
```
Put it behind HTTPS (cookies are `Secure`). Set `TV_TRUST_PROXY=1` behind a reverse proxy. Keep `TV_AUDIT_KEY` out of the repo
and out of the database volume. Schema: `trustvault/schema.sql` (applied automatically on first start).

### Demo accounts (password = `TV_SEED_PASSWORD`, default `TrustVault-Demo-2026!`)
| Role | Email |
|---|---|
| admin | admin@trustvault.test |
| owner | alice@trustvault.test, bob@trustvault.test |
| viewer | carol@trustvault.test, dave@trustvault.test |

Seed data: Alice owns two HR letters (one each shared with Carol and Dave) and a contract (Bob: edit, Carol: read). Bob owns a drawing nobody else can see.
Log in as Carol and try `/api/documents/2/download` (Dave's letter): 404.

## Roles and permission model

| Role | Can do |
|---|---|
| **admin** | Manage users (create, change role, deactivate, reset password), read the audit trail and activity view. **Cannot read, list or download any document's content**: admin is excluded in `authz.access_level`, and grants to admins are refused. The audit view shows document names and ids, never contents. |
| **owner** | Upload documents; owns what they upload; grants/revokes `read` or `edit` to named people; deletes/restores own documents; sees the activity on own documents. Can also be granted access to other people's documents. |
| **viewer** | Reads documents they were granted. Never above `read`, even if the grants table says `edit` (capped in code). Cannot upload. |

**Model in my own words.** Access is deny-by-default and per document. A person can reach a document only if (a) they own it, or (b) there is an
un-revoked row in `grants` for (document, person). Grant levels: `read` (view metadata, download) and `edit` (also rename, recategorise, replace content).
Only the owner can delete, restore, grant, revoke, see the document's audit and ask for suggestions. There are no groups and no folder
inheritance: they are the usual source of "access to a folder shows forty files", so I left them out. One function, `authz.authorize(user, doc_id, action)`,
makes the decision and every document route calls it first. Nothing is cached: role, active flag, session and grants are read from the database on every request.
No access at all returns **404** (existence is not revealed); some access but not enough returns **403**.

**Revocation** (`DELETE .../grants/<user>`) sets `revoked_at` in the same transaction that writes the audit row; the next request by that person fails.
There are no download URLs or tokens to expire: every download is an authenticated request authorised at that moment. Cost: one or two small DB queries per request.
Deactivating a user, or changing their role or password, deletes their sessions.

**Storage.** Blobs are written to `TV_STORAGE_DIR` under random 128-bit hex keys, outside any served directory. The only way to read one is
`GET /api/documents/<id>/download`. Files are served as `attachment` with `nosniff` and `Cache-Control: private, no-store`.

**Audit trail.** Written in the same transaction as the action. Refused attempts (including role refusals and failed logins) are written after the
request's side-effects are rolled back. Table is append-only (triggers reject UPDATE/DELETE) and HMAC-chained with a key held outside the DB;
`GET /api/admin/audit/verify` recomputes the chain. Record `GET /api/admin/audit/head` somewhere the app cannot write to, to detect tail truncation. See THREATS.md.

**AI-assisted sharing.** `POST /documents/<id>/suggestions` returns candidate people with reasons (currently a metadata heuristic; `suggest_recipients` is the
swap point for an LLM, which should receive metadata only, never file contents). A suggestion creates no access. The owner must confirm each person
through the normal grant call (optionally passing `suggestion_id`). Suggestion and decision are both audited and linked.

## API: who may call what
`anon` = no session. All state-changing calls need the `X-CSRF-Token` header (returned by login / `GET /api/auth/me`). Every route also declares its gate with `@requires(...)`, enforced by a test.
"Doc-level" means `authz.authorize` is called; users without the required level get 404 (no access) or 403 (not enough).

| Endpoint | Allowed |
|---|---|
| `POST /api/auth/login` | anon (throttled: 5 failures/email, 30/IP per 15 min) |
| `POST /api/auth/logout`, `GET /api/auth/me` | any logged-in user |
| `POST /api/documents` (multipart `file`, `category`) | role **owner** |
| `GET /api/documents?q&owner&category&date_from&date_to&limit&offset` | any logged-in user; returns only documents they can reach (admin: none) |
| `GET /api/documents/<id>` | doc-level **read** |
| `GET /api/documents/<id>/download` | doc-level **read** |
| `PATCH /api/documents/<id>` (`name`, `category`) | doc-level **edit** |
| `PUT /api/documents/<id>/content` | doc-level **edit** |
| `DELETE /api/documents/<id>` (soft delete) | doc-level **manage** (owner) |
| `POST /api/documents/<id>/restore` | doc-level **manage** |
| `GET /api/documents/<id>/grants` | doc-level **manage** |
| `POST /api/documents/<id>/grants` (`email`, `level`, optional `suggestion_id`) | doc-level **manage** |
| `DELETE /api/documents/<id>/grants/<user_id>` | doc-level **manage** |
| `POST /api/documents/<id>/suggestions` | doc-level **manage** |
| `GET /api/documents/<id>/audit` | doc-level **manage** |
| `GET/POST /api/admin/users`, `PATCH /api/admin/users/<id>` | role **admin** |
| `GET /api/admin/audit`, `/audit/verify`, `/audit/head`, `/activity` | role **admin** |

Errors are JSON `{"error": "..."}`. Unknown JSON fields are rejected with 400 (no mass assignment).
Upload rules: extension allow-list (pdf, png, jpg/jpeg, txt, csv, docx, xlsx, pptx), content must match extension (magic bytes / OOXML structure), 10 MB cap, zip-bomb and zip-slip checks, client MIME ignored.

## Tests
`tests/` proves isolation rather than assuming it: an actor × endpoint matrix (owner, edit-grantee, read-grantee, ungranted viewer, other owner, revoked grantee, admin, anonymous);
a test that fails if any document route is missing from the matrix or any `/api` route lacks a role declaration; revocation with a pre-existing session;
search/count leakage; audit tamper detection; upload attacks; CSRF; mass assignment. `scripts/mutation_check.py` deletes every `authorize()` call
and 40+ other controls one at a time and fails if any mutant survives (currently 45/45 killed).

## Deliberately not built
Groups, folder inheritance, external share links, version history, retention/purge, encryption at rest, malware scanning, MFA/password reset by email, per-user rate limits beyond login.
Reasons and consequences are in THREATS.md.

## Unfinished / honest gaps
- Not yet deployed by me: you must deploy and put the live URL here. Deploy early.
- UI is minimal and was only syntax-checked, not browser-tested; API is the tested surface.
- `PROMPTS.md`, the demo video and the write-up are yours to produce from your real build history; they are not generated here.
