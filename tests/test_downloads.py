"""Downloads plugin: panel + command."""


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
