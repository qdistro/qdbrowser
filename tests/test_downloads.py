"""Downloads plugin: panel + command."""


class _Plugins:
    def __init__(self, bridge):
        self._instances = {"bridge_adapter": bridge}


class _Window:
    def __init__(self, bridge):
        self.plugins = _Plugins(bridge)


class _Bridge:
    active = True

    def __init__(self):
        self.calls = []
        self.forward_calls = []

    def emit_download_started(self, download_id, filename, state=0, **kw):
        self.calls.append((download_id, filename, state, kw))

    def forward_download_state(self, download_id, filename, state=0, **kw):
        self.forward_calls.append((download_id, filename, state, kw))


class _LegacyBridge:
    active = True

    def __init__(self):
        self.calls = []

    def emit_download_started(self, download_id, filename, state=0, **kw):
        self.calls.append((download_id, filename, state, kw))


class _Signal:
    def __init__(self):
        self.callbacks = []

    def connect(self, callback):
        self.callbacks.append(callback)

    def emit(self):
        for callback in self.callbacks:
            callback()


class _Url:
    def host(self):
        return "example.test"

    def toString(self):
        return "https://example.test/file.zip"


class _Request:
    def __init__(self, *, state=0, finished=False, finish_on_accept=False):
        self._state = state
        self._finished = finished
        self._finish_on_accept = finish_on_accept
        self.accepted = False
        self.isFinishedChanged = _Signal()

    def id(self):
        return 42

    def state(self):
        return self._state

    def isFinished(self):
        return self._finished

    def downloadDirectory(self):
        return "/tmp/downloads"

    def setDownloadDirectory(self, directory):
        self._directory = directory

    def downloadFileName(self):
        return "file.zip"

    def setDownloadFileName(self, filename):
        self._filename = filename

    def totalBytes(self):
        return 100

    def receivedBytes(self):
        return 100 if self._finished else 10

    def url(self):
        return _Url()

    def mimeType(self):
        return "application/zip"

    def accept(self):
        self.accepted = True
        if self._finish_on_accept:
            self._state = 2
            self._finished = True
            self.isFinishedChanged.emit()


def test_panel_starts_empty(window):
    plug = window.plugins._instances["downloads"]
    panel = plug._panel
    assert panel is not None
    assert panel._list.count() == 0


def test_clear_finished_removes_historical_rows(window):
    """Historical (already-finished) rows go away on Clear; nothing
    else is left to assert about active rows since this test doesn't
    construct a real QWebEngineDownloadRequest."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QListWidgetItem

    plug = window.plugins._instances["downloads"]
    panel = plug._panel
    panel._list.clear()
    item = QListWidgetItem("✓ done.zip")
    item.setData(Qt.ItemDataRole.UserRole,
                 {"path": "/x/done.zip", "historical": True})
    panel._list.addItem(item)
    assert panel._list.count() == 1
    panel._clear_finished()
    assert panel._list.count() == 0


def test_commands_provided(window):
    plug = window.plugins._instances["downloads"]
    labels = [l for l, _ in plug.get_commands(window)]
    assert any("downloads" in l.lower() for l in labels)


def test_bridge_notifies_terminal_download_state(window):
    plug = window.plugins._instances["downloads"]
    bridge = _Bridge()
    plug._window = _Window(bridge)
    plug._notify_bridge_finished(_Request(state=2, finished=True))
    assert bridge.forward_calls == [
        (42, "file.zip", 2, {
            "url": "https://example.test/file.zip",
            "mime": "application/zip",
            "total_bytes": 100,
            "bytes_received": 100,
        })
    ]


def test_bridge_does_not_notify_unfinished_download(window):
    plug = window.plugins._instances["downloads"]
    bridge = _Bridge()
    plug._window = _Window(bridge)
    plug._notify_bridge_finished(_Request(state=1, finished=False))
    assert bridge.calls == []
    assert bridge.forward_calls == []


def test_bridge_finished_requires_forward_only_method(window):
    plug = window.plugins._instances["downloads"]
    bridge = _LegacyBridge()
    plug._window = _Window(bridge)
    plug._notify_bridge_finished(_Request(state=2, finished=True))
    assert bridge.calls == []


def test_bridge_finish_hook_connected_before_accept(window):
    plug = window.plugins._instances["downloads"]
    bridge = _Bridge()
    plug._window = _Window(bridge)
    plug._panel = None
    req = _Request(state=0, finished=False)
    plug._on_download_requested(req)
    assert req.accepted is True
    assert req.isFinishedChanged.callbacks


def test_bridge_fast_completion_does_not_duplicate_terminal_state(window):
    plug = window.plugins._instances["downloads"]
    bridge = _Bridge()
    plug._window = _Window(bridge)
    plug._panel = None
    req = _Request(state=0, finished=False, finish_on_accept=True)
    plug._on_download_requested(req)
    assert bridge.calls == [
        (42, "file.zip", 0, {
            "url": "https://example.test/file.zip",
            "mime": "application/zip",
            "total_bytes": 100,
            "bytes_received": 10,
        })
    ]
    assert bridge.forward_calls == [
        (42, "file.zip", 2, {
            "url": "https://example.test/file.zip",
            "mime": "application/zip",
            "total_bytes": 100,
            "bytes_received": 100,
        })
    ]
