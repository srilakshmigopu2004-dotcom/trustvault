import os
import sqlite3

SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")


def connect(path: str) -> sqlite3.Connection:
    # isolation_level=None: we manage transactions explicitly (BEGIN IMMEDIATE per request).
    conn = sqlite3.connect(path, isolation_level=None, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = connect(path)
    try:
        has = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()
        if not has:
            with open(SCHEMA, encoding="utf-8") as f:
                conn.executescript(f.read())
    finally:
        conn.close()
