"""MainWindow smoke + tab/split lifecycle."""

from PyQt6.QtCore import Qt

from qdbrowser.webview import WebView


def test_window_starts_with_one_tab(window):
    assert window._tabs.count() == 1


def test_new_tab_focuses_new(window):
    a = window._active_webview
    b = window.new_tab(url="about:blank")
    assert b is not a
    assert window._active_webview is b
    assert window._tabs.count() == 2


def test_close_current_tab_keeps_window_alive(window):
    window.new_tab()
    assert window._tabs.count() == 2
    window._close_current_tab()
    assert window._tabs.count() == 1


def test_split_creates_pane(window):
    before = len(window._tabs.widget(0).find_webviews())
    window._split(Qt.Orientation.Horizontal)
    after = len(window._tabs.widget(0).find_webviews())
    assert after == before + 1


def test_close_split_decrements(window):
    window._split(Qt.Orientation.Horizontal)
    before = len(window._tabs.widget(0).find_webviews())
    window._close_active_split()
    after = len(window._tabs.widget(0).find_webviews())
    assert after == before - 1


def test_default_plugins_enabled(window):
    enabled = window.plugins.enabled_plugins()
    for p in ("bookmarks", "history", "downloads", "notes",
              "command_palette", "content_blocker", "sessions",
              "screenshot", "reader_mode", "dark_mode",
              "picture_in_picture", "tab_list", "translate"):
        assert p in enabled, f"{p} should be enabled by default"


def test_side_panel_has_panels(window):
    panels = window._side_panel.panel_ids()
    for needed in ("bookmarks", "history", "downloads", "notes",
                   "tab_list", "web_panels"):
        assert needed in panels
