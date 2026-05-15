"""URL bar / WebView.navigate smart-URL handling.

Runs through the window fixture so the webview has a real parent and
QtWebEngine cleanup is well-defined.
"""

from unittest.mock import patch


def test_full_url_passes_through(window):
    wv = window._active_webview
    with patch.object(wv.view, "setUrl") as set_url:
        wv.navigate("https://example.com/foo")
        assert set_url.call_args[0][0].toString() == "https://example.com/foo"


def test_bare_domain_gets_https(window):
    wv = window._active_webview
    with patch.object(wv.view, "setUrl") as set_url:
        wv.navigate("example.com")
        assert set_url.call_args[0][0].toString().startswith("https://example.com")


def test_search_query_goes_to_engine(window, fresh_config):
    from qdbrowser.config import Config
    Config().set("general", "search_engine",
                 "https://search.invalid/?q={query}")
    wv = window._active_webview
    with patch.object(wv.view, "setUrl") as set_url:
        wv.navigate("hello world")
        assert set_url.call_args[0][0].toString().startswith(
            "https://search.invalid/?q=hello")
