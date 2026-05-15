"""Track-02 unit tests for the bridge_adapter D-Bus handler surface.

These exercise the pure-Python dispatcher with mocked proxies. The
goal is to nail the protocol contract — method names, argument
counts, return signatures, polkit gating — without standing up a real
session bus.
"""

from __future__ import annotations

import pytest

from qdbrowser.plugins import bridge_adapter as ba


# --------------------------------------------------------------------- #
# Tiny fakes for the four proxies.
# --------------------------------------------------------------------- #


class _FakeTabs:
    def __init__(self):
        self._tabs = [(1, "Home", "https://example.com"),
                      (2, "Docs", "https://docs.example.com")]
        self.opened: list = []
        self.closed: list = []

    def list(self):
        return list(self._tabs)

    def open(self, url):
        new_id = max((t[0] for t in self._tabs), default=0) + 1
        self._tabs.append((new_id, "New", url))
        self.opened.append(url)
        return new_id

    def close(self, tab_id):
        before = len(self._tabs)
        self._tabs = [t for t in self._tabs if t[0] != tab_id]
        self.closed.append(tab_id)
        return len(self._tabs) < before


class _FakePages:
    def __init__(self):
        self.last_call = None

    def extract(self, tab_id, mode):
        self.last_call = (tab_id, mode)
        return (f"title-{tab_id}", f"https://t/{tab_id}",
                f"content-{mode}")


class _FakeDownloads:
    def list(self):
        return [(0, "report.pdf", 1), (1, "movie.mkv", 2)]


class _FakeMedia:
    def status(self):
        return ("My Track", "An Artist", "playing")


def _make_handlers(polkit_allow=True):
    return ba.BridgeAdapterHandlers(
        _FakeTabs(), _FakePages(), _FakeDownloads(), _FakeMedia(),
        polkit=lambda action, pid: polkit_allow,
    )


# --------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------- #


def test_introspection_xml_lists_all_methods():
    xml = ba.QDBROWSER_INTROSPECTION_XML
    for method in ("TabsList", "TabsOpen", "TabsClose",
                   "PageExtract", "DownloadsList", "MediaStatus"):
        assert f'name="{method}"' in xml
    # Signal names must match the emit_* helpers.
    for sig in ("TabAdded", "TabRemoved",
                "DownloadStarted", "MediaStateChanged"):
        assert f'name="{sig}"' in xml


def test_method_to_action_table_is_complete():
    # Every method we introspect must map to a polkit action.
    for method in ("TabsList", "TabsOpen", "TabsClose",
                   "PageExtract", "DownloadsList", "MediaStatus"):
        assert method in ba.METHOD_TO_ACTION


def test_tabs_list_returns_signature_and_payload():
    h = _make_handlers()
    body, sig = h.dispatch("TabsList", ())
    assert sig == "a(uss)"
    (tabs,) = body
    assert tabs == [(1, "Home", "https://example.com"),
                    (2, "Docs", "https://docs.example.com")]


def test_tabs_open_returns_new_id():
    h = _make_handlers()
    body, sig = h.dispatch("TabsOpen", ("https://new.example",))
    assert sig == "u"
    (new_id,) = body
    assert new_id == 3
    assert h.tabs.opened == ["https://new.example"]


def test_tabs_close_returns_bool():
    h = _make_handlers()
    body, sig = h.dispatch("TabsClose", (1,))
    assert sig == "b"
    assert body == (True,)
    # Closing a missing tab → False.
    body, _ = h.dispatch("TabsClose", (999,))
    assert body == (False,)


def test_page_extract_modes_round_trip():
    h = _make_handlers()
    body, sig = h.dispatch("PageExtract", (1, "text"))
    assert sig == "sss"
    title, url, content = body
    assert title == "title-1"
    assert url == "https://t/1"
    assert content == "content-text"
    # html / selection also round-trip.
    for mode in ("html", "selection"):
        body, _ = h.dispatch("PageExtract", (1, mode))
        assert body[2] == f"content-{mode}"


def test_downloads_list_signature():
    h = _make_handlers()
    body, sig = h.dispatch("DownloadsList", ())
    assert sig == "a(usu)"
    (dls,) = body
    assert dls == [(0, "report.pdf", 1), (1, "movie.mkv", 2)]


def test_media_status_returns_three_strings():
    h = _make_handlers()
    body, sig = h.dispatch("MediaStatus", ())
    assert sig == "sss"
    assert body == ("My Track", "An Artist", "playing")


def test_unknown_method_raises():
    h = _make_handlers()
    with pytest.raises(LookupError):
        h.dispatch("NoSuchMethod", ())


def test_polkit_denies_blocks_dispatch():
    h = _make_handlers(polkit_allow=False)
    # Mutating method → blocked.
    with pytest.raises(PermissionError):
        h.dispatch("TabsOpen", ("https://x",))


def test_polkit_skipped_for_internal_caller():
    """caller_pid=None means 'internal call' — read-only actions still
    pass, mutating ones still consult the polkit hook (which here is
    a stub that returns True)."""
    h = _make_handlers(polkit_allow=True)
    body, _ = h.dispatch("TabsList", (), caller_pid=None)
    (tabs,) = body
    assert len(tabs) == 2


def test_polkit_check_short_circuits_read_only():
    """polkit_check skips pkcheck for read-only inventory actions even
    if a caller PID is supplied — the policy file says allow:yes."""
    assert ba.polkit_check("org.qdistro.qdbrowser.tabs.list", 1) is True
    assert ba.polkit_check("org.qdistro.qdbrowser.media.status", 1) is True
    assert ba.polkit_check("org.qdistro.qdbrowser.downloads.list", 1) is True


def test_polkit_check_internal_call_bypass():
    """caller_pid=None always returns True (internal call)."""
    assert ba.polkit_check("org.qdistro.qdbrowser.tabs.open", None) is True


def test_polkit_check_uses_pkcheck_for_mutating(monkeypatch):
    """For mutating actions with a real caller pid, pkcheck is shelled
    out to. We monkeypatch subprocess.run to a fake."""
    calls: list = []

    class _FakeResult:
        def __init__(self, rc):
            self.returncode = rc
            self.stdout = b""
            self.stderr = b""

    def fake_run(args, capture_output=True, timeout=None):
        calls.append(args)
        return _FakeResult(0)

    monkeypatch.setattr(ba.subprocess, "run", fake_run)
    assert ba.polkit_check("org.qdistro.qdbrowser.tabs.open", 4242) is True
    assert any("org.qdistro.qdbrowser.tabs.open" in a for a in calls[0])
    assert "4242" in calls[0]


def test_polkit_check_pkcheck_denies(monkeypatch):
    class _FakeResult:
        def __init__(self):
            self.returncode = 1
            self.stdout = b""
            self.stderr = b""

    monkeypatch.setattr(ba.subprocess, "run",
                        lambda *a, **kw: _FakeResult())
    assert ba.polkit_check(
        "org.qdistro.qdbrowser.tabs.open", 4242) is False


def test_polkit_check_pkcheck_oserror_denies(monkeypatch):
    def boom(*a, **kw):
        raise OSError("no pkcheck on PATH")
    monkeypatch.setattr(ba.subprocess, "run", boom)
    assert ba.polkit_check(
        "org.qdistro.qdbrowser.tabs.open", 4242) is False


# --------------------------------------------------------------------- #
# Proxy unit tests — verify the duck-typed adapters.
# --------------------------------------------------------------------- #


class _FakeWebView:
    def __init__(self, tid, title, url):
        self.stable_id = tid
        self._title = title
        self._url = url

    def title(self):
        return self._title

    def url(self):
        return self._url


class _FakeSplit:
    def __init__(self, views):
        self._views = views

    def find_webviews(self):
        return list(self._views)


class _FakeTabsWidget:
    def __init__(self, splits):
        self._splits = splits

    def count(self):
        return len(self._splits)

    def widget(self, i):
        return self._splits[i]


class _FakeWindow:
    def __init__(self, splits):
        self._tabs = _FakeTabsWidget(splits)
        self.opened: list = []
        self.closed: list = []
        self._next_id = 100

    def new_tab(self, url, **kw):
        wv = _FakeWebView(self._next_id, "x", url)
        self._next_id += 1
        self._tabs._splits.append(_FakeSplit([wv]))
        self.opened.append(url)
        return wv

    def _on_tab_close_requested(self, idx):
        self.closed.append(idx)
        self._tabs._splits.pop(idx)


def test_tabs_proxy_list_open_close():
    wv1 = _FakeWebView(1, "T1", "https://1/")
    wv2 = _FakeWebView(2, "T2", "https://2/")
    win = _FakeWindow([_FakeSplit([wv1]), _FakeSplit([wv2])])
    proxy = ba.TabsProxy(win)
    assert proxy.list() == [(1, "T1", "https://1/"),
                             (2, "T2", "https://2/")]
    new_id = proxy.open("https://3/")
    assert new_id == 100
    assert win.opened == ["https://3/"]
    assert proxy.close(2) is True
    assert win.closed == [1]
    assert proxy.close(9999) is False


def test_pages_proxy_extract_invokes_run_js():
    wv = _FakeWebView(5, "Title", "https://5/")
    win = _FakeWindow([_FakeSplit([wv])])
    seen: list = []

    def fake_run_js(wv, script):
        seen.append(script)
        return "BODY-TEXT"

    proxy = ba.PagesProxy(win, run_js=fake_run_js)
    title, url, content = proxy.extract(5, "text")
    assert title == "Title"
    assert url == "https://5/"
    assert content == "BODY-TEXT"
    assert "innerText" in seen[0]


def test_pages_proxy_unknown_mode_rejected():
    win = _FakeWindow([])
    proxy = ba.PagesProxy(win, run_js=None)
    with pytest.raises(ValueError):
        proxy.extract(1, "screenshot")


def test_pages_proxy_missing_tab_raises():
    win = _FakeWindow([])
    proxy = ba.PagesProxy(win, run_js=lambda *a: "")
    with pytest.raises(LookupError):
        proxy.extract(999, "text")


def test_downloads_proxy_empty_when_no_plugin():
    proxy = ba.DownloadsProxy(None)
    assert proxy.list() == []


def test_media_proxy_update_and_status():
    media = ba.MediaProxy()
    assert media.status() == ("", "", "stopped")
    media.update("Song", "Band", "playing")
    assert media.status() == ("Song", "Band", "playing")
