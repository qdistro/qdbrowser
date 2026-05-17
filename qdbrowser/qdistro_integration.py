"""Wire qdbrowser into the qdistro App1 launcher contract.

On registration, qdbrowser claims ``com.qdistro.QdBrowser.uid<NNNN>``
on the session bus. Inbound payloads with a URL-ish kind are opened
in a new tab. Mirrors qfileman/qterminator/qnotebook's
``qdistro_integration.py`` (P03 pattern).

Degrades to a no-op when ``dbus-python`` is missing or the session
bus isn't reachable.
"""
from __future__ import annotations

import os
import sys

from PyQt6.QtCore import QTimer

try:  # pragma: no cover — VM-only path
    from qdistro_app import app_receiver as _app_receiver
except ImportError:
    _app_receiver = None  # type: ignore[assignment]


APP_FRIENDLY_NAME = "QdBrowser"
APP_SUPPORTED_KINDS = (
    "text/uri-list",
    "text/x-uri",
    "text/plain",
    "text/html",
)


def maybe_install(window) -> object | None:
    """Register the App1 receiver. Safe to call exactly once per window.

    Returns the live :class:`AppReceiver` (caller stores it for the
    lifetime of the app — letting it GC drops the bus claim) or
    ``None`` when the SDK / session bus aren't reachable. We never
    raise: a missing bus must not crash the browser.
    """
    if _app_receiver is None:
        print("[qdbrowser/qdistro] qdistro_app SDK not importable; "
              "App1 registration skipped",
              file=sys.stderr, flush=True)
        return None

    def on_receive(kind: str, payload: str) -> None:
        # Dbus dispatches on its own (GLib) thread; bounce onto the Qt
        # main loop before touching the QtWebEngine view tree.
        QTimer.singleShot(0, lambda: _open_payload(window, kind, payload))

    receiver = _app_receiver.register_app(
        APP_FRIENDLY_NAME,
        on_receive=on_receive,
        friendly_name=APP_FRIENDLY_NAME,
        supported_kinds=APP_SUPPORTED_KINDS,
    )
    if receiver is None:
        return None
    print(f"[qdbrowser/qdistro] App1 receiver registered as "
          f"{receiver.service_name} (silo={receiver.silo!r})",
          flush=True)
    return receiver


def _open_payload(window, kind: str, payload: str) -> None:
    """Open ``payload`` in a new tab. Payload semantics by kind:

    - ``text/uri-list``: newline-separated URIs; we open each in a tab.
    - ``text/x-uri`` / ``text/plain``: single URI string.
    - ``text/html``: ignored for v1 (no data: URL injection path —
      compositor-popup design forbids that). Surfaces a status line.

    Best-effort: any failure is logged but never raised back into the
    dbus dispatcher (Qt would treat that as a fatal handler error and
    the receiver would be torn down).
    """
    try:
        new_tab = getattr(window, "new_tab", None)
        if new_tab is None or not callable(new_tab):
            print("[qdbrowser/qdistro] window has no new_tab; drop payload",
                  file=sys.stderr, flush=True)
            return

        k = (kind or "").lower()
        if k == "text/html":
            # See module docstring — no data: URL injection. The
            # admin-attested "open URL" verb is the only inbound shape
            # browser.md endorses.
            print("[qdbrowser/qdistro] text/html receive not supported; "
                  "dropping payload",
                  file=sys.stderr, flush=True)
            return

        urls = _extract_urls(kind, payload)
        for url in urls:
            try:
                new_tab(url=url)
            except Exception as e:  # noqa: BLE001
                print(f"[qdbrowser/qdistro] new_tab({url!r}) failed: {e}",
                      file=sys.stderr, flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"[qdbrowser/qdistro] deliver failed: {e}",
              file=sys.stderr, flush=True)


def _extract_urls(kind: str, payload: str) -> list[str]:
    """Split a payload into a list of URL candidates.

    ``text/uri-list`` is the canonical "drop-targets" MIME — newline-
    separated, with optional ``#`` comments. The others are treated
    as a single trimmed string and only accepted if they look like a
    URL (presence of a scheme; bare paths are rejected so a malicious
    sender can't induce ``file://`` access by sending ``/etc/shadow``).
    """
    if not payload:
        return []
    k = (kind or "").lower()
    out: list[str] = []
    if k == "text/uri-list":
        for raw in payload.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if _looks_like_url(line):
                out.append(line)
        return out
    line = payload.strip()
    if not line:
        return []
    if _looks_like_url(line):
        out.append(line)
    return out


def _looks_like_url(s: str) -> bool:
    """Accept ``http(s)://``, ``ftp://``, ``about:``, ``data:``? No.

    Only schemes that don't grant filesystem access. ``data:`` and
    ``file:`` are rejected for the same reason a hostile silo
    shouldn't be able to drive us to a local file. Returns ``False``
    on anything ambiguous — caller drops the URL.
    """
    s = (s or "").strip().lower()
    if not s:
        return False
    if s.startswith("http://") or s.startswith("https://"):
        return True
    if s.startswith("ftp://") or s.startswith("ftps://"):
        return True
    if s.startswith("about:"):
        return True
    return False


def send_to_targets(*, kind: str = "text/uri-list") -> list[dict]:
    """Return rows for a "Send link to..." menu inside qdbrowser.

    The menu builder calls this from the URL-bar context menu / a
    page-context "send to other app" entry. Same shape as the other
    qdistro apps return.
    """
    if _app_receiver is None:
        return []
    try:
        self_service = f"com.qdistro.{APP_FRIENDLY_NAME}.uid{os.geteuid()}"
        return _app_receiver.send_to_menu_targets(
            self_service=self_service, kind=kind)
    except Exception as e:  # noqa: BLE001
        print(f"[qdbrowser/qdistro] send_to_menu_targets failed: {e}",
              file=sys.stderr, flush=True)
        return []


def send_payload(target_uid: int, target_service: str, payload: str, *,
                 kind: str = "text/uri-list") -> bool:
    if _app_receiver is None:
        return False
    try:
        return bool(_app_receiver.send_to(int(target_uid),
                                          str(target_service),
                                          str(kind), str(payload)))
    except Exception as e:  # noqa: BLE001
        print(f"[qdbrowser/qdistro] send_to({target_service}) failed: {e}",
              file=sys.stderr, flush=True)
        return False
