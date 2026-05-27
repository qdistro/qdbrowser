"""Download quarantine: store, scan, surface.

Every QtWebEngine download is redirected from the user-facing
``~/Downloads`` to ``~/.local/share/qdbrowser/quarantine/`` (configurable
via ``[downloads] quarantine_dir``). The on-disk layout is:

    quarantine/
      metadata.db                 SQLite index
      <sha256-prefix>-<name>      the file itself
      <sha256-prefix>-<name>.qdistro-meta.json
                                  human-readable origin + scan result

The SQLite schema:

    CREATE TABLE downloads (
      id           INTEGER PRIMARY KEY,
      quarantine_path TEXT NOT NULL,
      filename     TEXT NOT NULL,
      source_url   TEXT NOT NULL,
      content_type TEXT,
      profile_name TEXT,
      tab_id       INTEGER,
      sha256       TEXT,
      size_bytes   INTEGER,
      fetched_at   INTEGER NOT NULL,
      scan_result  TEXT,    -- 'pending' | 'clean' | 'bad' | 'skipped'
      released     INTEGER NOT NULL DEFAULT 0,
      release_path TEXT
    );

The scan step is configurable: ``[downloads] scan_command``. Empty
string means "do not scan; mark as ``skipped``". A non-empty command
runs as ``<cmd> <quarantine_path>`` and is judged by exit code: 0 →
``clean``, anything else → ``bad``.

The release step is gated by polkit
(``org.qdistro.qdbrowser.downloads.release``). On approval the file
moves to ``[downloads] release_dir`` (default ``~/Downloads``) and the
DB row is updated.

The module is import-clean: it doesn't import PyQt6 directly so unit
tests can drive it without spinning up a QApplication. The download
intake helper that *does* touch Qt lives in ``plugins/downloads.py``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import time
from typing import Optional


log = logging.getLogger("qdbrowser.quarantine")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS downloads (
    id INTEGER PRIMARY KEY,
    quarantine_path TEXT NOT NULL,
    filename TEXT NOT NULL,
    source_url TEXT NOT NULL,
    content_type TEXT,
    profile_name TEXT,
    tab_id INTEGER,
    sha256 TEXT,
    size_bytes INTEGER,
    fetched_at INTEGER NOT NULL,
    scan_result TEXT,
    released INTEGER NOT NULL DEFAULT 0,
    release_path TEXT
);
CREATE INDEX IF NOT EXISTS downloads_by_fetched_at
    ON downloads(fetched_at DESC);
"""


# Polkit action id for release-from-quarantine. The action is declared
# in ``polkit/org.qdistro.qdbrowser.policy``.
POLKIT_RELEASE_ACTION = "org.qdistro.qdbrowser.downloads.release"


class QuarantineStore:
    """SQLite-backed metadata store + filesystem layout helper.

    Constructors:
        QuarantineStore(quarantine_dir)
            Open or create the directory + DB.

    The class is independent of Qt; downloads.py wires it into
    ``QWebEngineDownloadRequest`` via the helper methods at the bottom.
    """

    def __init__(self, quarantine_dir: str):
        self._dir = os.path.expanduser(quarantine_dir)
        os.makedirs(self._dir, mode=0o700, exist_ok=True)
        # Tighten permissions on pre-existing directories created by
        # earlier versions that used the default umask.
        try:
            os.chmod(self._dir, 0o700)
        except OSError as exc:
            log.warning("cannot tighten quarantine dir permissions %s: %s",
                        self._dir, exc)
        self._db_path = os.path.join(self._dir, "metadata.db")
        self._db = sqlite3.connect(self._db_path)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        self._db.commit()
        # Restrict DB file permissions — quarantine metadata includes
        # source URLs and file hashes, treat as private.
        try:
            os.chmod(self._db_path, 0o600)
        except OSError:
            pass

    @property
    def directory(self) -> str:
        return self._dir

    @property
    def db_path(self) -> str:
        return self._db_path

    # -- path planning -------------------------------------------------

    def plan_path(self, suggested_name: str) -> str:
        """Pick a path inside the quarantine for ``suggested_name``.

        Collisions get a numeric suffix so two downloads of the same
        URL don't clobber each other before the SHA256 is known.
        """
        clean = _sanitize_name(suggested_name)
        path = os.path.join(self._dir, clean)
        if not os.path.exists(path):
            return path
        # Numeric suffix: name.1.ext, name.2.ext, ...
        base, ext = os.path.splitext(clean)
        for n in range(1, 1000):
            candidate = os.path.join(self._dir, f"{base}.{n}{ext}")
            if not os.path.exists(candidate):
                return candidate
        # Fall back to timestamp
        return os.path.join(self._dir, f"{base}.{int(time.time())}{ext}")

    # -- record creation ----------------------------------------------

    def record(self,
               quarantine_path: str,
               filename: str,
               source_url: str,
               content_type: Optional[str] = None,
               profile_name: Optional[str] = None,
               tab_id: Optional[int] = None,
               size_bytes: Optional[int] = None,
               sha256: Optional[str] = None,
               fetched_at: Optional[int] = None,
               scan_result: str = "pending") -> int:
        ts = int(fetched_at if fetched_at is not None else time.time())
        cur = self._db.execute(
            "INSERT INTO downloads "
            "(quarantine_path, filename, source_url, content_type, "
            " profile_name, tab_id, sha256, size_bytes, fetched_at, "
            " scan_result) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (quarantine_path, filename, source_url, content_type,
             profile_name, tab_id, sha256, size_bytes, ts, scan_result))
        self._db.commit()
        log.info(
            "qdbrowser.quarantine record id=%s url=%s path=%s scan=%s",
            cur.lastrowid, source_url, quarantine_path, scan_result)
        return cur.lastrowid

    def write_sidecar(self, row_id: int, quarantine_path: str,
                      payload: dict) -> str:
        sidecar = quarantine_path + ".qdistro-meta.json"
        fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        return sidecar

    def update_after_finish(self, row_id: int, sha256: str,
                            size_bytes: int) -> None:
        self._db.execute(
            "UPDATE downloads SET sha256=?, size_bytes=? WHERE id=?",
            (sha256, size_bytes, row_id))
        self._db.commit()

    def update_scan_result(self, row_id: int, scan_result: str) -> None:
        self._db.execute(
            "UPDATE downloads SET scan_result=? WHERE id=?",
            (scan_result, row_id))
        self._db.commit()
        log.info("qdbrowser.quarantine scan id=%s result=%s",
                 row_id, scan_result)

    def mark_released(self, row_id: int, release_path: str) -> None:
        self._db.execute(
            "UPDATE downloads SET released=1, release_path=? WHERE id=?",
            (release_path, row_id))
        self._db.commit()
        log.info("qdbrowser.quarantine release id=%s path=%s",
                 row_id, release_path)

    # -- queries ------------------------------------------------------

    def list_pending(self) -> list:
        """Return unreleased downloads, excluding failed-intake rows
        (scan_result='error') which represent files that never arrived.
        """
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM downloads WHERE released=0 "
            "AND COALESCE(scan_result, '') != 'error' "
            "ORDER BY fetched_at DESC").fetchall()]

    def list_all(self, limit: int = 200) -> list:
        return [dict(r) for r in self._db.execute(
            "SELECT * FROM downloads "
            "ORDER BY fetched_at DESC LIMIT ?",
            (limit,)).fetchall()]

    def get(self, row_id: int) -> Optional[dict]:
        row = self._db.execute(
            "SELECT * FROM downloads WHERE id=?", (row_id,)).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:
            pass


# -- scan ---------------------------------------------------------------


def run_scan(scan_command: str, path: str,
             timeout: float = 60.0) -> str:
    """Run ``scan_command path``. Returns the scan result token:

      ``"clean"`` — exit 0
      ``"bad"``   — non-zero exit
      ``"skipped"`` — empty scan_command
      ``"error"`` — scanner couldn't run / timed out
    """
    if not scan_command:
        return "skipped"
    try:
        proc = subprocess.run(
            [scan_command, path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired,
            OSError) as exc:
        log.warning("scan failed cmd=%r path=%r: %s",
                    scan_command, path, exc)
        return "error"
    return "clean" if proc.returncode == 0 else "bad"


# -- release ------------------------------------------------------------


def check_release_authorized(action: str = POLKIT_RELEASE_ACTION,
                             pkcheck: str = "pkcheck") -> bool:
    """Ask polkit (``pkcheck``) whether the caller may release a
    quarantined file. Returns True on authorization, False otherwise.

    The test suite stubs this by monkey-patching the function — the
    helper exists so production code has one entry point and tests
    have one knob.
    """
    pid = os.getpid()
    try:
        proc = subprocess.run(
            [pkcheck, "--action-id", action,
             "--process", str(pid),
             "--allow-user-interaction"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120.0,
            check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired,
            OSError) as exc:
        log.warning("pkcheck unavailable: %s", exc)
        return False
    return proc.returncode == 0


def release(store: QuarantineStore,
            row_id: int,
            release_dir: str,
            authorized: Optional[bool] = None) -> Optional[str]:
    """Move a quarantined file to ``release_dir`` after polkit consent.

    Returns the final path on success, ``None`` on denial.

    ``authorized`` is the test seam: pass ``True``/``False`` to skip the
    pkcheck call.
    """
    row = store.get(row_id)
    if not row:
        log.warning("release: unknown id=%s", row_id)
        return None
    if row.get("scan_result") == "bad":
        log.warning("release: refusing bad file id=%s", row_id)
        return None
    if authorized is None:
        authorized = check_release_authorized()
    if not authorized:
        log.warning(
            "qdbrowser.quarantine release_denied id=%s reason=polkit",
            row_id)
        return None
    src = row["quarantine_path"]
    os.makedirs(release_dir, exist_ok=True)
    # Defence-in-depth: re-sanitize the stored filename so legacy or
    # manually-inserted rows cannot escape release_dir via path
    # traversal (e.g. "../../../etc/cron.d/evil").
    safe_filename = _sanitize_name(row["filename"])
    dst = os.path.join(release_dir, safe_filename)
    # Avoid clobber in the release dir.
    base, ext = os.path.splitext(dst)
    n = 1
    while os.path.exists(dst):
        dst = f"{base}.{n}{ext}"
        n += 1
    try:
        shutil.move(src, dst)
    except OSError as exc:
        log.warning("release move failed: %s", exc)
        return None
    store.mark_released(row_id, dst)
    return dst


# -- helpers ------------------------------------------------------------


def _sanitize_name(name: str) -> str:
    """Drop path separators and control characters from a server-
    suggested filename. Empty input becomes ``download``."""
    name = (name or "").strip().replace("\x00", "")
    # Strip directory components — Qt may pass a path-like name.
    name = os.path.basename(name)
    # Drop shell-disasters even though we never invoke a shell.
    cleaned = "".join(c for c in name if c.isprintable() and c not in "/\\")
    return cleaned or "download"


def hash_file(path: str, chunk: int = 1 << 20) -> str:
    """SHA-256 a file on disk; returns hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()
