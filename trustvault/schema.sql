CREATE TABLE users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name          TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL
);

-- Only a SHA-256 of the session token is stored, so a DB leak does not yield live sessions.
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  csrf       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE login_attempts (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  ip    TEXT,
  ts    TEXT NOT NULL,
  ok    INTEGER NOT NULL
);
CREATE INDEX idx_login_email_ts ON login_attempts(email, ts);
CREATE INDEX idx_login_ip_ts ON login_attempts(ip, ts);

CREATE TABLE documents (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  category    TEXT NOT NULL DEFAULT 'general',
  owner_id    INTEGER NOT NULL REFERENCES users(id),
  storage_key TEXT NOT NULL UNIQUE,          -- random hex; never derived from the name
  mime        TEXT NOT NULL,
  size        INTEGER NOT NULL,
  sha256      TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  deleted_at  TEXT,
  deleted_by  INTEGER REFERENCES users(id)
);
CREATE INDEX idx_documents_owner ON documents(owner_id);
CREATE INDEX idx_documents_created ON documents(created_at);

-- Per-document grants. The owner needs no row: ownership is documents.owner_id.
CREATE TABLE grants (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id INTEGER NOT NULL REFERENCES documents(id),
  user_id     INTEGER NOT NULL REFERENCES users(id),
  level       TEXT NOT NULL CHECK (level IN ('read','edit')),
  granted_by  INTEGER NOT NULL REFERENCES users(id),
  granted_at  TEXT NOT NULL,
  revoked_at  TEXT,
  revoked_by  INTEGER REFERENCES users(id)
);
CREATE UNIQUE INDEX one_active_grant ON grants(document_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_grants_user ON grants(user_id) WHERE revoked_at IS NULL;

-- Suggestions are advisory records only. They never create access.
CREATE TABLE suggestions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id  INTEGER NOT NULL REFERENCES documents(id),
  requested_by INTEGER NOT NULL REFERENCES users(id),
  candidates   TEXT NOT NULL,   -- JSON list of user ids
  created_at   TEXT NOT NULL
);

-- Append-only, HMAC hash-chained audit log.
CREATE TABLE audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  actor_id    INTEGER,
  actor_email TEXT,
  action      TEXT NOT NULL,
  outcome     TEXT NOT NULL CHECK (outcome IN ('ok','denied','rejected')),
  doc_id      INTEGER,
  doc_name    TEXT,
  detail      TEXT NOT NULL DEFAULT '{}',
  ip          TEXT,
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE INDEX idx_audit_doc ON audit_log(doc_id);
CREATE INDEX idx_audit_actor ON audit_log(actor_email);
CREATE INDEX idx_audit_ts ON audit_log(ts);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
