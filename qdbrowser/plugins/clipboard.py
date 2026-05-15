"""Clipboard plugin: tag system clipboard writes with qdistro origin
metadata so the compositor-side ClipboardGate can apply finer-grained
policy.

Phase-1 deliverable for track-04. Scope:

- Observe copy events from the QtWebEngine page (via
  ``QWebEnginePage.selectionChanged`` and the page's clipboard hook).
- On copy, set custom MIME types on the system clipboard:
    * ``x-qdistro-origin-url``       — the page URL at copy-time
    * ``x-qdistro-origin-tab-id``    — qdbrowser's stable webview id
    * ``x-qdistro-fetched-at``       — ISO-8601 timestamp

The compositor's ``selection_set`` event sees the new MIME-list and
qdshell's ClipboardGate forwards it as ``mime_types=`` in the journal
line. Phase-2 will add semantic tags (is_password_field, code_block,
content_editable) from the JS ``selectionchange`` handler described in
``todo/browser/04-compositor-clipboard.md``.

Note: Phase-1 does NOT block paste — the compositor handles that side
via ``clear_selection``. The plugin only attaches origin metadata at
copy-time.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from PyQt6.QtCore import QMimeData, QByteArray
from PyQt6.QtGui import QClipboard, QGuiApplication
from PyQt6.QtWidgets import QApplication

from qdbrowser.plugin import PageObserver

log = logging.getLogger(__name__)


# MIME types we tag. Keep these prefixed `x-qdistro-` so other clipboard
# consumers (e.g. wl-paste) see them as advisory metadata, not the
# payload type.
MIME_ORIGIN_URL = "x-qdistro-origin-url"
MIME_ORIGIN_TAB_ID = "x-qdistro-origin-tab-id"
MIME_FETCHED_AT = "x-qdistro-fetched-at"


class ClipboardOriginPlugin(PageObserver):
    """Attach origin metadata to clipboard writes from web pages.

    Subscribes per-webview to selection changes; when the selection is
    non-empty and the user issues a copy command (which writes to the
    Qt application clipboard), we re-stamp the clipboard with extra
    MIME types pointing back at the source.
    """

    name = "clipboard"
    description = "Tag clipboard writes with qdistro origin metadata."
    capabilities = ["page_observer"]
    version = "0.1"

    def __init__(self):
        super().__init__()
        self._window = None
        self._wired_views: dict = {}  # id(webview) -> webview
        self._last_url_by_view: dict = {}  # id(webview) -> url string
        self._clipboard_conn = None

    # -- lifecycle ------------------------------------------------------

    def activate(self, app_controller):
        self._window = app_controller
        clip = QGuiApplication.clipboard()
        if clip is not None:
            # When QtWebEngine writes the clipboard via the Copy action,
            # the clipboard's `dataChanged` fires AFTER the payload
            # lands. We hook there to re-stamp the MimeData with our
            # extra types — keeping the original `text/plain` /
            # `text/html` etc. payload intact.
            self._clipboard_conn = clip.dataChanged.connect(
                self._on_clipboard_changed)

        # Walk any existing tabs so re-activated plugins see them.
        if hasattr(app_controller, "_tabs"):
            try:
                for i in range(app_controller._tabs.count()):
                    w = app_controller._tabs.widget(i)
                    if w is not None:
                        self._wire_view(w)
            except Exception as exc:
                log.debug("clipboard: initial tab walk failed: %s", exc)

    def deactivate(self):
        clip = QGuiApplication.clipboard()
        if clip is not None and self._clipboard_conn is not None:
            try:
                clip.dataChanged.disconnect(self._clipboard_conn)
            except (RuntimeError, TypeError):
                pass
        self._clipboard_conn = None
        self._wired_views.clear()
        self._last_url_by_view.clear()

    # -- page observer hooks --------------------------------------------

    def on_navigation(self, webview, url):
        self._last_url_by_view[id(webview)] = url
        self._wire_view(webview)

    def on_load_finished(self, webview, ok):
        self._wire_view(webview)

    # -- internals ------------------------------------------------------

    def _wire_view(self, webview):
        vid = id(webview)
        if vid in self._wired_views:
            return
        self._wired_views[vid] = webview
        # Keep a current-URL fallback for the case where on_navigation
        # never fired (initial tab with no nav yet).
        try:
            current = webview.view.url().toString() if webview.view else ""
            if current:
                self._last_url_by_view[vid] = current
        except Exception:
            pass

    def _focused_view(self):
        """Best-effort lookup of the webview that just wrote the
        clipboard. We don't get a direct signal from QtWebEngine that
        identifies the source view, so we approximate by the currently-
        active tab — which is virtually always the source for a
        user-driven Copy."""
        win = self._window
        if win is None:
            return None
        getter = getattr(win, "_active_webview", None)
        return getter

    def _on_clipboard_changed(self):
        clip = QGuiApplication.clipboard()
        if clip is None:
            return
        # Ownership check: only stamp clipboard payloads that *we* set.
        # Qt's QClipboard.ownsClipboard() is true only when the current
        # owner is this process. Avoid stamping system-clipboard writes
        # from other apps (e.g. a terminal `xclip`) which would attach
        # bogus "browser tab" metadata.
        try:
            if not clip.ownsClipboard():
                return
        except Exception:
            return

        existing = clip.mimeData()
        if existing is None:
            return
        # Guard re-entry: if our origin MIME is already on the
        # clipboard, we already stamped this payload.
        if existing.hasFormat(MIME_ORIGIN_URL):
            return

        view = self._focused_view()
        if view is None:
            return
        vid = id(view)
        url = self._last_url_by_view.get(vid, "")
        try:
            stable_id = getattr(view, "_stable_id", None)
        except Exception:
            stable_id = None
        tab_id = str(stable_id) if stable_id is not None else ""
        fetched_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")

        # Build a NEW QMimeData carrying both the existing payload AND
        # our metadata. We can't mutate `existing` in place — Qt owns
        # the lifecycle. Copy each format across.
        clone = QMimeData()
        for fmt in existing.formats():
            try:
                data = existing.data(fmt)
                clone.setData(fmt, data)
            except Exception:
                continue
        clone.setData(MIME_ORIGIN_URL, QByteArray(url.encode("utf-8")))
        clone.setData(MIME_ORIGIN_TAB_ID, QByteArray(tab_id.encode("utf-8")))
        clone.setData(MIME_FETCHED_AT, QByteArray(fetched_at.encode("utf-8")))

        # Setting mime data triggers `dataChanged` again — the re-entry
        # guard above (`hasFormat(MIME_ORIGIN_URL)`) prevents an
        # infinite loop.
        clip.setMimeData(clone, QClipboard.Mode.Clipboard)

    # TODO(track-04-phase-2): inject a `selectionchange` JS handler on
    # every page load that stashes window.__qdistro_clipboard_meta with
    # is_password_field, is_code_block, is_content_editable. Read it
    # synchronously here and surface as extra MIME types
    # (x-qdistro-tag-password, x-qdistro-tag-code) so the compositor
    # policy can match them via the broker rule's `content_tags:`
    # selector.
    #
    # TODO(track-04-phase-3): forward the same metadata via D-Bus
    # directly to the compositor so the gate doesn't have to parse
    # custom MIME types — useful for clients that strip unknown MIMEs.
