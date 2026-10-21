"""Upload validation and blob storage.

Blobs live outside the web root under random hex keys. There is no URL that maps to a
blob: the only way to read one is GET /api/documents/<id>/download, which calls authorize().
"""
import hashlib
import io
import os
import re
import secrets
import zipfile

from flask import current_app

from .util import ApiError

ALLOWED = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
OOXML_DIR = {".docx": "word/", ".xlsx": "xl/", ".pptx": "ppt/"}
ZIP_MAX_UNCOMPRESSED = 100 * 1024 * 1024
ZIP_MAX_ENTRIES = 2000
ZIP_MAX_RATIO = 200
CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9 _-]{0,39}$")
_KEY_RE = re.compile(r"^[0-9a-f]{32}$")


def clean_name(raw: str) -> str:
    """Display name only. It is never used to build a filesystem path."""
    name = (raw or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip().strip(".")
    if not name or len(name) > 120:
        raise ApiError(400, "invalid file name")
    if ext_of(name) not in ALLOWED:
        raise ApiError(415, "file type not allowed; allowed: " + ", ".join(sorted(ALLOWED)))
    return name


def ext_of(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def clean_category(raw) -> str:
    c = str(raw if raw is not None else "general").strip().lower()
    if not CATEGORY_RE.match(c):
        raise ApiError(400, "invalid category (letters, digits, space, _ and -; max 40)")
    return c


def validate(name: str, data: bytes) -> str:
    """Checks the content matches the extension (magic bytes / structure). Returns the MIME
    type that WE decide on; the client-supplied Content-Type is ignored."""
    ext = ext_of(name)
    if not data:
        raise ApiError(400, "empty file")
    ok = False
    if ext == ".pdf":
        ok = data.startswith(b"%PDF-")
    elif ext == ".png":
        ok = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif ext in (".jpg", ".jpeg"):
        ok = data.startswith(b"\xff\xd8\xff")
    elif ext in (".txt", ".csv"):
        try:
            data.decode("utf-8")
            ok = b"\x00" not in data
        except UnicodeDecodeError:
            ok = False
    elif ext in OOXML_DIR:
        ok = _valid_ooxml(data, OOXML_DIR[ext])
    if not ok:
        raise ApiError(415, "file content does not match its extension, or is unsafe")
    return ALLOWED[ext]


def _valid_ooxml(data: bytes, required_dir: str) -> bool:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except zipfile.BadZipFile:
        return False
    if len(infos) > ZIP_MAX_ENTRIES:
        return False
    total = 0
    for i in infos:
        total += i.file_size
        if i.filename.startswith("/") or ".." in i.filename.split("/"):
            return False
        if i.compress_size and i.file_size / i.compress_size > ZIP_MAX_RATIO:
            return False  # decompression-bomb heuristic
    if total > ZIP_MAX_UNCOMPRESSED:
        return False
    names = {i.filename for i in infos}
    return "[Content_Types].xml" in names and any(n.startswith(required_dir) for n in names)


def _path(key: str) -> str:
    if not _KEY_RE.match(key):
        raise ValueError("bad storage key")
    return os.path.join(current_app.config["STORAGE_DIR"], key)


def store(data: bytes):
    os.makedirs(current_app.config["STORAGE_DIR"], exist_ok=True)
    key = secrets.token_hex(16)
    with open(_path(key), "xb") as f:
        f.write(data)
    return key, hashlib.sha256(data).hexdigest()


def read(key: str) -> bytes:
    with open(_path(key), "rb") as f:
        return f.read()


def remove(key: str) -> None:
    try:
        os.remove(_path(key))
    except FileNotFoundError:
        pass
