import logging
import os

from flask import Flask, g, jsonify, send_from_directory
from werkzeug.exceptions import HTTPException

from . import audit, db as dbm

log = logging.getLogger("trustvault")


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    max_mb = int(os.environ.get("TV_MAX_UPLOAD_MB", "10"))
    app.config.update(
        DB_PATH=os.environ.get("TV_DB_PATH", "data/trustvault.db"),
        STORAGE_DIR=os.environ.get("TV_STORAGE_DIR", "data/blobs"),
        AUDIT_KEY=os.environ.get("TV_AUDIT_KEY", "").encode(),
        MAX_UPLOAD_BYTES=max_mb * 1024 * 1024,
        COOKIE_SECURE=os.environ.get("TV_INSECURE_COOKIES") != "1",
        HASH_METHOD="scrypt",
        SESSION_HOURS=8,
    )
    app.config.update(config or {})
    app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_UPLOAD_BYTES"] + 256 * 1024  # multipart overhead
    if len(app.config["AUDIT_KEY"]) < 16:
        raise RuntimeError(
            "TV_AUDIT_KEY is missing or shorter than 16 characters. Set a stable secret in the "
            "Render service environment, or deploy this repository as a Blueprint so render.yaml "
            "generates it. Do not rotate this key after audit records have been created."
        )
    if os.environ.get("TV_TRUST_PROXY") == "1":
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    dbm.init_db(app.config["DB_PATH"])

    from .routes import bp
    from .util import ApiError
    app.register_blueprint(bp)

    @app.errorhandler(ApiError)
    def handle_api_error(e: ApiError):
        conn = g.get("db")
        if conn is not None:
            conn.rollback()  # the refused request leaves no side effects...
            if e.audit:  # ...except its own record
                conn.execute("BEGIN IMMEDIATE")
                a = dict(e.audit)
                audit.append(conn, g.get("user"), a["action"], a.get("outcome", "denied"),
                             a.get("doc_id"), a.get("doc_name"), a.get("detail"))
        return jsonify({"error": e.message}), e.status

    @app.errorhandler(HTTPException)
    def handle_http(e: HTTPException):
        return jsonify({"error": e.description if e.code != 500 else "internal error"}), e.code

    @app.errorhandler(Exception)
    def handle_unexpected(e):
        log.exception("unhandled error")
        return jsonify({"error": "internal error"}), 500

    @app.after_request
    def finish(resp):
        conn = g.get("db")
        if conn is not None and conn.in_transaction:
            try:
                if resp.status_code < 500:
                    conn.commit()
                    for fn in g.get("post_commit", []):
                        fn()
                else:
                    conn.rollback()
            except Exception:
                log.exception("commit failed")
                conn.rollback()
                resp = jsonify({"error": "internal error"})
                resp.status_code = 500
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        if resp.mimetype == "application/json" or "attachment" in resp.headers.get("Content-Disposition", ""):
            resp.headers["Cache-Control"] = "private, no-store"
        return resp

    @app.teardown_request
    def close_db(exc):
        conn = g.pop("db", None)
        if conn is not None:
            if conn.in_transaction:
                conn.rollback()
            conn.close()

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    return app
