"""History store + page-observer behavior."""

import json
import os


def test_store_load_missing_file(tmp_path, monkeypatch):
    import qdbrowser.plugins.history as h
    monkeypatch.setattr(h, "HISTORY_PATH", str(tmp_path / "missing"))
    store = h._Store()
    assert store.all() == []


def test_store_add_persists(tmp_path, monkeypatch):
    import qdbrowser.plugins.history as h
    monkeypatch.setattr(h, "HISTORY_PATH", str(tmp_path / "hist.jsonl"))
    store = h._Store()
    store.add("https://example.com", "Example")
    assert any("example.com" in r["url"] for r in store.all())
    # File written.
    with open(tmp_path / "hist.jsonl") as f:
        first = json.loads(f.readline())
    assert first["url"] == "https://example.com"


def test_store_skips_aboutblank(tmp_path, monkeypatch):
    import qdbrowser.plugins.history as h
    monkeypatch.setattr(h, "HISTORY_PATH", str(tmp_path / "h.jsonl"))
    store = h._Store()
    store.add("about:blank", "blank")
    store.add("data:text/html,foo", "data")
    assert store.all() == []


def test_store_caps_memory(tmp_path, monkeypatch):
    import qdbrowser.plugins.history as h
    monkeypatch.setattr(h, "HISTORY_PATH", str(tmp_path / "h.jsonl"))
    monkeypatch.setattr(h, "MAX_HISTORY", 5)
    store = h._Store()
    for i in range(10):
        store.add(f"https://example.com/{i}", f"page-{i}")
    assert len(store.all()) <= 5


def test_store_load_skips_broken_lines(tmp_path, monkeypatch):
    import qdbrowser.plugins.history as h
    p = tmp_path / "h.jsonl"
    p.write_text(
        '{"url": "https://a.com", "title": "A", "ts": 1}\n'
        'NOT_JSON\n'
        '{"url": "https://b.com", "title": "B", "ts": 2}\n')
    monkeypatch.setattr(h, "HISTORY_PATH", str(p))
    store = h._Store()
    urls = [r["url"] for r in store.all()]
    assert "https://a.com" in urls
    assert "https://b.com" in urls


def test_panel_filter(window, tmp_path, monkeypatch):
    import qdbrowser.plugins.history as h
    monkeypatch.setattr(h, "HISTORY_PATH", str(tmp_path / "h.jsonl"))
    store = h._Store()
    store.add("https://apple.com", "Apple")
    store.add("https://banana.com", "Banana")
    panel = h.HistoryPanel(window, store)
    panel._refresh()
    assert panel._list.count() == 2
    panel._filter.setText("apple")
    assert panel._list.count() == 1


def test_plugin_on_title_changed_updates_last(window, tmp_path, monkeypatch):
    import qdbrowser.plugins.history as h
    monkeypatch.setattr(h, "HISTORY_PATH", str(tmp_path / "h.jsonl"))
    plug = h.HistoryPlugin()
    plug.activate(window)

    # Insert a record with no title, then notify a title change.
    plug._store._records.append({"url": "https://x.test", "title": "",
                                  "ts": 0})

    class FakeWv:
        def url(self):
            return "https://x.test"

    plug.on_title_changed(FakeWv(), "New Title")
    assert plug._store._records[-1]["title"] == "New Title"


def test_plugin_on_navigation_appends(window, tmp_path, monkeypatch):
    import qdbrowser.plugins.history as h
    monkeypatch.setattr(h, "HISTORY_PATH", str(tmp_path / "h.jsonl"))
    plug = h.HistoryPlugin()
    plug.activate(window)
    plug.build_panel(window)

    class FakeWv:
        def title(self):
            return "Title"

    plug.on_navigation(FakeWv(), "https://navtest.example")
    urls = [r["url"] for r in plug._store.all()]
    assert "https://navtest.example" in urls
