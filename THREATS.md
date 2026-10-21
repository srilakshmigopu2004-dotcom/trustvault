# THREATS.md

Format: **threat**, what I did, the test that proves it (`tests/…`), and status (closed / reduced / accepted). Accepted items are things I know are weak.

## Access to documents
| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 1 | IDOR: guess another document ID on any route (metadata, download, edit, delete, grants, audit, suggestions, restore) | Every document route calls `authz.authorize()` first; deny by default | `test_authorization_matrix` (8 actors × 11 routes); `test_every_document_route_is_in_matrix` fails if a new route is added without a matrix row | closed |
| 2 | Existence leak: 403 vs 404, or error text, tells you a document exists | No access → 404 with the same body as a missing ID. 403 only when you already have some access | `test_ids_are_not_guessable_by_enumeration` | closed |
| 3 | Revoked user keeps access via old session/token/link | No tokens or links exist. Sessions are server-side; grants are read from the DB per request. Revoke = `revoked_at` set in the same transaction as the audit row | `test_revoke_takes_effect_immediately_for_existing_session` | closed |
| 4 | Deactivated / demoted / password-changed user keeps a live session | Those admin actions delete all their sessions; role and `active` are re-read per request | `test_deactivating_a_user…`, `test_password_change_and_role_change…` | closed |
| 5 | Stale edit rights after demotion (owner → viewer) or access after promotion to admin | `access_level` caps viewers at read and gives admins zero content access, regardless of grant rows | `test_demotion_to_viewer_caps…` | closed |
| 6 | Search leaks titles, owners, counts, paging totals | One SQL query joins grants first; `COUNT` and `LIMIT` run after the access filter; `%`/`_` escaped; all parameterised | `test_search_never_returns_or_counts…`, `test_filters_and_wildcards` | closed |
| 7 | Soft-deleted documents still readable | `_load()` hides deleted rows for every action except `restore` (owner only) | `test_deleted_document_is_unreachable…` | closed |
| 8 | Grantee escalates: edits own grant, grants others, revokes owner's other grants | Only `manage` (owner) can touch grants; edit-grantees get 403 | `test_grantee_cannot_widen…` | closed |
| 9 | Grant to admin, to self/owner, to a viewer at `edit`, or to a deactivated user | All rejected with one identical generic 422 | `test_invalid_targets_all_get_the_same_generic_refusal` | closed |
| 10 | Mass assignment (`owner_id`, `storage_key`, `deleted_at`, `role`) | Strict whitelist per endpoint; unknown fields → 400; upload form cannot set owner | `MassAssignmentAndInputTest` | closed |
| 11 | A newly added route forgets its auth | `@requires(kind)` on every route; test enumerates `url_map` | `test_every_api_route_declares_its_role_gate` | closed |
| 12 | Concurrent grant/revoke/download races | `BEGIN IMMEDIATE` per request serialises writers; unique partial index allows one live grant per (doc, user) | by construction; no concurrency test (gap) | reduced |
| 13 | Bytes already delivered cannot be recalled when access is revoked a millisecond later | The file is read after the check and sent whole; the window is one request. A recipient who already downloaded keeps their copy | – | **accepted** (inherent) |

## Authentication and sessions
| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 14 | Session fixation | New random token at every login; client-supplied cookie value never accepted | `test_new_session_on_every_login…` | closed |
| 15 | Stolen DB yields live sessions | Only SHA-256 of the token is stored | `test_session_tokens_are_not_stored_in_plaintext` | closed |
| 16 | CSRF | `SameSite=Strict`, `HttpOnly`, `Secure` cookie + per-session CSRF header on every state-changing call | `test_state_changing_requests_need_csrf_token` | closed |
| 17 | Brute force / user enumeration at login | Per-email and per-IP lockout; identical response and one dummy hash verification for unknown/inactive users | `test_lockout…`, `test_login_does_not_reveal…` | reduced |
| 18 | Lockout used to deny a victim their login | 5 failures lock that email for 15 minutes, even for the real owner | – | **accepted** (alternative: per-IP only, weaker) |
| 19 | Cookie theft from the browser or network | HttpOnly, Secure, 8h absolute expiry; logout kills server-side. No IP/UA binding, no MFA | `test_logout_invalidates_session_server_side` | **accepted** (no MFA) |
| 20 | Owners can learn which emails have accounts (a grant to a real email succeeds, to a fake one gets 422) | Generic errors for all invalid targets, but success itself is an oracle | – | **accepted** (owners must be able to share by email; no per-user rate limit) |

## Audit trail
| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 21 | Audit row lost if the action succeeds but logging fails (or the reverse) | Same transaction as the action; commit or roll back together | `test_events_are_recorded` | closed |
| 22 | Refused attempts invisible | Error handler rolls back the request, then writes `*_refused` rows in a new transaction | `test_refused_attempts_are_recorded_and_leave_no_side_effects` | closed |
| 23 | App bug or compromised app code edits/deletes history | SQL triggers reject UPDATE/DELETE | `test_database_rejects_update_and_delete` | reduced: the app's DB user can still `DROP TRIGGER` |
| 24 | Someone with DB write access rewrites history | HMAC chain keyed by `TV_AUDIT_KEY`, which is not in the DB; verify endpoint recomputes | `test_chain_verifies_then_detects_tampering…`, `test_attacker_cannot_forge_rows…` | reduced |
| 25 | Truncating the newest rows leaves a valid chain | Needs an external copy of the head hash (`/audit/head`). I do not automate the off-box copy | – | **accepted** (operators must record the head) |
| 26 | Attacker with full server access gets DB **and** key | Both live on the same host in this design | – | **accepted** (fix: sign into an external log / KMS) |
| 27 | Log injection / log flooding | Structured JSON, so newlines are escaped. Flooding: each refused call writes a row and only login is throttled | `test_user_supplied_text_cannot_forge_log_lines` | injection closed; flooding **accepted** |
| 28 | Admin sees document names in audit/activity | Deliberate: names are in audit rows, contents never | – | **accepted** (policy, documented) |
| 29 | Owners see emails of people who were refused on their documents | Useful for owners, mildly privacy-relevant | – | **accepted** |

## Uploads and files
| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 30 | Path traversal via filename | Names are display-only (basename, control chars stripped). Blobs use random hex keys validated by regex | `test_path_traversal_in_filename_is_neutralised` | closed |
| 31 | Executable/HTML/SVG upload → stored XSS | Extension allow-list (no html/svg/js), content must match type, always `attachment` + `nosniff` + CSP | `test_rejects_active_content…`, `test_download_headers…` | closed |
| 32 | Content-type spoofing | Magic bytes / OOXML structure checked; client MIME ignored | `test_rejects_wrong_content_for_extension`, `test_client_supplied_content_type_is_ignored` | closed |
| 33 | Zip bomb / zip slip in OOXML | Archive inspected, never extracted: entry count, total size, ratio, `..` paths | `test_zip_bomb_and_zip_slip_rejected`, `test_total_uncompressed_size_cap` | closed |
| 34 | Oversized uploads / memory use | 10 MB cap enforced twice; whole file still read into memory (10 MB × concurrency) | `test_size_limit` | reduced |
| 35 | Malware inside an allowed type (macro docx, PDF with JS) | Not scanned. Mitigated only by download-as-attachment. Recipients open it themselves | – | **accepted** |
| 36 | Browser/proxy cache serves a revoked file | `Cache-Control: private, no-store` on downloads and JSON | `test_download_headers…` | closed |
| 37 | Orphan or leftover blobs | Failed insert removes the blob; replaced blobs are deleted after commit. Soft-deleted blobs stay forever (no purge/retention) | `test_replacing_content…` | **accepted** |
| 38 | Files unencrypted at rest | Not implemented; disk access = file access | – | **accepted** |

## Other
| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 39 | SQL injection | Parameterised everywhere. One f-string builds `SET` from a code-side column whitelist | injection strings in search/suggestion tests | closed |
| 40 | XSS in the UI | UI only uses `textContent`; CSP `default-src 'self'`; no inline script | manual only (gap) | reduced |
| 41 | Prompt injection / AI widening access | Heuristic uses metadata only, never file contents. Output is a list; granting needs a separate human-confirmed call; suggestion must match document, requester and candidate; both steps audited | `SuggestionTest` | closed (re-check if an LLM is added) |
| 42 | Admin tries to read files | Admin has zero content access; cannot be granted; search returns nothing | matrix + `test_search_never_returns…` | closed |
| 43 | Single point: SQLite write lock | `BEGIN IMMEDIATE` per request serialises everything; low throughput, one node | – | **accepted** (demo scale) |
| 44 | Shared demo password for seeded accounts | Documented; set `TV_SEED_PASSWORD`; change or delete on real use | – | **accepted** |
| 45 | No password reset, no MFA, no per-user API rate limit | Not built | – | **accepted** |
