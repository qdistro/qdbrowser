"""Tests for the clipboard origin plugin (Phase-1 + Phase-3 semantic metadata).

Uses mock objects to avoid requiring a running QtWebEngine page — the
plugin's DOM-metadata path is pure Python + cached dict lookups.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from PyQt6.QtCore import QMimeData, QByteArray
from PyQt6.QtGui import QGuiApplication

from qdbrowser.plugins.clipboard import (
    ClipboardOriginPlugin,
    MIME_ORIGIN_URL,
    MIME_ORIGIN_TAB_ID,
    MIME_FETCHED_AT,
    MIME_IS_PASSWORD_FIELD,
    MIME_IS_CODE_BLOCK,
    MIME_IS_CONTENT_EDITABLE,
    _SELECTIONCHANGE_JS,
)


# -- helpers ---------------------------------------------------------------

def _make_mock_webview(url="https://example.com", stable_id=42):
    """Build a mock WebView with the minimum attributes the plugin needs."""
    wv = MagicMock()
    wv._stable_id = stable_id
    wv.view.url().toString.return_value = url
    wv.view.page().selectionChanged = MagicMock()
    wv.view.page().selectionChanged.connect = MagicMock()
    wv.view.page().runJavaScript = MagicMock()
    return wv


class _FakeClipboard:
    """Minimal stand-in for QClipboard that tracks setMimeData calls."""

    def __init__(self, *, owns=True, mime_data=None):
        self._owns = owns
        self._mime_data = mime_data or QMimeData()
        self.set_calls: list = []

    def ownsClipboard(self):
        return self._owns

    def mimeData(self):
        return self._mime_data

    def setMimeData(self, data, mode):
        self.set_calls.append((data, mode))

    @property
    def dataChanged(self):
        return MagicMock()


# -- constants / JS --------------------------------------------------------

class TestConstants:
    def test_mime_type_strings(self):
        assert MIME_IS_PASSWORD_FIELD == "x-qdistro-is-password-field"
        assert MIME_IS_CODE_BLOCK == "x-qdistro-is-code-block"
        assert MIME_IS_CONTENT_EDITABLE == "x-qdistro-is-content-editable"

    def test_selectionchange_js_is_iife(self):
        assert _SELECTIONCHANGE_JS.startswith("(function()")
        assert _SELECTIONCHANGE_JS.endswith(")()")

    def test_selectionchange_js_has_guard_variable(self):
        assert "__qdistro_selectionchange_wired" in _SELECTIONCHANGE_JS

    def test_selectionchange_js_sets_meta_property(self):
        assert "__qdistro_clipboard_meta" in _SELECTIONCHANGE_JS

    def test_selectionchange_js_detects_password_field(self):
        assert "password" in _SELECTIONCHANGE_JS

    def test_selectionchange_js_detects_code_block(self):
        assert "pre, code" in _SELECTIONCHANGE_JS

    def test_selectionchange_js_detects_content_editable(self):
        assert "isContentEditable" in _SELECTIONCHANGE_JS


# -- plugin construction / lifecycle ---------------------------------------

class TestLifecycle:
    def test_init_sets_empty_dicts(self):
        plug = ClipboardOriginPlugin()
        assert plug._dom_meta_by_view == {}
        assert plug._wired_views == {}
        assert plug._last_url_by_view == {}

    def test_deactivate_clears_dom_meta(self):
        plug = ClipboardOriginPlugin()
        plug._dom_meta_by_view[123] = {"isPasswordField": True}
        plug._wired_views[123] = MagicMock()
        plug._last_url_by_view[123] = "https://example.com"
        plug.deactivate()
        assert plug._dom_meta_by_view == {}
        assert plug._wired_views == {}
        assert plug._last_url_by_view == {}


# -- JS injection ---------------------------------------------------------

class TestJSInjection:
    def test_inject_selectionchange_handler_calls_runJavaScript(self):
        plug = ClipboardOriginPlugin()
        wv = _make_mock_webview()
        plug._inject_selectionchange_handler(wv)
        wv.view.page().runJavaScript.assert_called_once_with(_SELECTIONCHANGE_JS)

    def test_inject_selectionchange_handler_none_page_no_crash(self):
        plug = ClipboardOriginPlugin()
        wv = MagicMock()
        wv.view.page.return_value = None
        plug._inject_selectionchange_handler(wv)  # should not raise

    def test_inject_selectionchange_handler_no_view_no_crash(self):
        plug = ClipboardOriginPlugin()
        wv = MagicMock()
        wv.view = None
        plug._inject_selectionchange_handler(wv)  # should not raise

    def test_on_load_finished_injects_js_when_ok(self):
        plug = ClipboardOriginPlugin()
        wv = _make_mock_webview()
        plug.on_load_finished(wv, True)
        # runJavaScript should have been called with the selectionchange JS
        calls = wv.view.page().runJavaScript.call_args_list
        js_args = [c[0][0] for c in calls]
        assert _SELECTIONCHANGE_JS in js_args

    def test_on_load_finished_skips_js_when_not_ok(self):
        plug = ClipboardOriginPlugin()
        wv = _make_mock_webview()
        plug.on_load_finished(wv, False)
        # Should only call connect for selectionChanged, not runJavaScript
        # for the injection.
        for call in wv.view.page().runJavaScript.call_args_list:
            assert call[0][0] != _SELECTIONCHANGE_JS


# -- selection changed / DOM metadata caching ------------------------------

class TestDomMetaCaching:
    def test_cache_dom_meta_stores_dict(self):
        plug = ClipboardOriginPlugin()
        meta = {"isPasswordField": True, "isCodeBlock": False,
                "isContentEditable": False}
        plug._cache_dom_meta(42, meta)
        assert plug._dom_meta_by_view[42] == meta

    def test_cache_dom_meta_stores_none(self):
        plug = ClipboardOriginPlugin()
        plug._cache_dom_meta(42, None)
        assert plug._dom_meta_by_view[42] is None

    def test_on_selection_changed_triggers_js_read(self):
        plug = ClipboardOriginPlugin()
        wv = _make_mock_webview()
        plug._on_selection_changed(id(wv), wv)
        # The runJavaScript call should read the meta property.
        wv.view.page().runJavaScript.assert_called_once()
        args = wv.view.page().runJavaScript.call_args[0]
        assert args[0] == "window.__qdistro_clipboard_meta"

    def test_read_dom_meta_invokes_callback_on_none_page(self):
        plug = ClipboardOriginPlugin()
        wv = MagicMock()
        wv.view.page.return_value = None
        results = []
        plug._read_dom_meta(wv, lambda m: results.append(m))
        assert results == [None]


# -- clipboard stamping with semantic metadata ----------------------------

class TestClipboardStamping:
    """Test _on_clipboard_changed stamps Phase-3 MIME types."""

    def _make_plugin_with_view(self, *, url="https://x.com", stable_id=7,
                                dom_meta=None):
        """Return (plugin, fake_view) ready for _on_clipboard_changed."""
        plug = ClipboardOriginPlugin()
        wv = _make_mock_webview(url=url, stable_id=stable_id)
        vid = id(wv)
        plug._window = MagicMock()
        plug._window._active_webview = wv
        plug._wired_views[vid] = wv
        plug._last_url_by_view[vid] = url
        if dom_meta is not None:
            plug._dom_meta_by_view[vid] = dom_meta
        return plug, wv

    def _run_clipboard_changed(self, plug, existing_mime=None):
        """Simulate a clipboard change and return the stamped QMimeData."""
        if existing_mime is None:
            existing_mime = QMimeData()
            existing_mime.setText("hello")

        fake_clip = _FakeClipboard(owns=True, mime_data=existing_mime)
        with patch.object(QGuiApplication, "clipboard",
                          return_value=fake_clip):
            plug._on_clipboard_changed()

        assert len(fake_clip.set_calls) == 1, (
            "Expected exactly one setMimeData call")
        return fake_clip.set_calls[0][0]

    def test_stamps_origin_url(self):
        plug, _ = self._make_plugin_with_view(url="https://test.dev")
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_ORIGIN_URL)) == b"https://test.dev"

    def test_stamps_tab_id(self):
        plug, _ = self._make_plugin_with_view(stable_id=99)
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_ORIGIN_TAB_ID)) == b"99"

    def test_stamps_fetched_at(self):
        plug, _ = self._make_plugin_with_view()
        stamped = self._run_clipboard_changed(plug)
        ts = bytes(stamped.data(MIME_FETCHED_AT)).decode()
        # Should be ISO-8601-ish (at minimum YYYY-MM-DD).
        assert len(ts) >= 10
        assert ts[4] == "-"

    def test_stamps_password_field_false_by_default(self):
        plug, _ = self._make_plugin_with_view()
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_PASSWORD_FIELD)) == b"false"

    def test_stamps_code_block_false_by_default(self):
        plug, _ = self._make_plugin_with_view()
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_CODE_BLOCK)) == b"false"

    def test_stamps_content_editable_false_by_default(self):
        plug, _ = self._make_plugin_with_view()
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_CONTENT_EDITABLE)) == b"false"

    def test_stamps_password_field_true_from_meta(self):
        meta = {"isPasswordField": True, "isCodeBlock": False,
                "isContentEditable": False}
        plug, _ = self._make_plugin_with_view(dom_meta=meta)
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_PASSWORD_FIELD)) == b"true"
        assert bytes(stamped.data(MIME_IS_CODE_BLOCK)) == b"false"
        assert bytes(stamped.data(MIME_IS_CONTENT_EDITABLE)) == b"false"

    def test_stamps_code_block_true_from_meta(self):
        meta = {"isPasswordField": False, "isCodeBlock": True,
                "isContentEditable": False}
        plug, _ = self._make_plugin_with_view(dom_meta=meta)
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_PASSWORD_FIELD)) == b"false"
        assert bytes(stamped.data(MIME_IS_CODE_BLOCK)) == b"true"

    def test_stamps_content_editable_true_from_meta(self):
        meta = {"isPasswordField": False, "isCodeBlock": False,
                "isContentEditable": True}
        plug, _ = self._make_plugin_with_view(dom_meta=meta)
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_CONTENT_EDITABLE)) == b"true"

    def test_stamps_all_true_from_meta(self):
        meta = {"isPasswordField": True, "isCodeBlock": True,
                "isContentEditable": True}
        plug, _ = self._make_plugin_with_view(dom_meta=meta)
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_PASSWORD_FIELD)) == b"true"
        assert bytes(stamped.data(MIME_IS_CODE_BLOCK)) == b"true"
        assert bytes(stamped.data(MIME_IS_CONTENT_EDITABLE)) == b"true"

    def test_none_meta_yields_all_false(self):
        plug, _ = self._make_plugin_with_view(dom_meta=None)
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_PASSWORD_FIELD)) == b"false"
        assert bytes(stamped.data(MIME_IS_CODE_BLOCK)) == b"false"
        assert bytes(stamped.data(MIME_IS_CONTENT_EDITABLE)) == b"false"

    def test_non_dict_meta_yields_all_false(self):
        """If JS returns something unexpected, default to false."""
        plug, wv = self._make_plugin_with_view()
        plug._dom_meta_by_view[id(wv)] = "unexpected string"
        stamped = self._run_clipboard_changed(plug)
        assert bytes(stamped.data(MIME_IS_PASSWORD_FIELD)) == b"false"

    def test_preserves_existing_text_payload(self):
        plug, _ = self._make_plugin_with_view()
        stamped = self._run_clipboard_changed(plug)
        assert stamped.hasFormat("text/plain")

    def test_reentry_guard_prevents_double_stamp(self):
        """If clipboard already has MIME_ORIGIN_URL, skip stamping."""
        plug, _ = self._make_plugin_with_view()
        existing = QMimeData()
        existing.setText("already stamped")
        existing.setData(MIME_ORIGIN_URL, QByteArray(b"https://old.com"))

        fake_clip = _FakeClipboard(owns=True, mime_data=existing)
        with patch.object(QGuiApplication, "clipboard",
                          return_value=fake_clip):
            plug._on_clipboard_changed()
        assert len(fake_clip.set_calls) == 0

    def test_not_owns_clipboard_skips(self):
        """Don't stamp if another process owns the clipboard."""
        plug, _ = self._make_plugin_with_view()
        existing = QMimeData()
        existing.setText("from xclip")

        fake_clip = _FakeClipboard(owns=False, mime_data=existing)
        with patch.object(QGuiApplication, "clipboard",
                          return_value=fake_clip):
            plug._on_clipboard_changed()
        assert len(fake_clip.set_calls) == 0

    def test_no_focused_view_skips(self):
        """Don't stamp if no active webview."""
        plug = ClipboardOriginPlugin()
        plug._window = MagicMock()
        plug._window._active_webview = None

        existing = QMimeData()
        existing.setText("some text")
        fake_clip = _FakeClipboard(owns=True, mime_data=existing)
        with patch.object(QGuiApplication, "clipboard",
                          return_value=fake_clip):
            plug._on_clipboard_changed()
        assert len(fake_clip.set_calls) == 0


# -- wire_view connects selectionChanged -----------------------------------

class TestWireView:
    def test_wire_view_connects_selection_changed(self):
        plug = ClipboardOriginPlugin()
        wv = _make_mock_webview()
        plug._wire_view(wv)
        wv.view.page().selectionChanged.connect.assert_called_once()

    def test_wire_view_idempotent(self):
        plug = ClipboardOriginPlugin()
        wv = _make_mock_webview()
        plug._wire_view(wv)
        plug._wire_view(wv)  # second call is a no-op
        # connect called exactly once
        assert wv.view.page().selectionChanged.connect.call_count == 1

    def test_wire_view_records_url(self):
        plug = ClipboardOriginPlugin()
        wv = _make_mock_webview(url="https://docs.python.org")
        plug._wire_view(wv)
        assert plug._last_url_by_view[id(wv)] == "https://docs.python.org"
