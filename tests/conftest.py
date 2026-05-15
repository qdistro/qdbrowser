"""Shared pytest fixtures. Mirrors qterminator/tests/conftest.py."""

import gc
import os
import sys

# Make sure QtWebEngineWidgets is imported before QApplication.
import PyQt6.QtWebEngineWidgets  # noqa: F401

import pytest

# Force offscreen and headless Chromium for every test process.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault(
    "QTWEBENGINE_CHROMIUM_FLAGS",
    "--no-sandbox --disable-gpu --headless --in-process-gpu")

from PyQt6.QtWidgets import QApplication


def pytest_collection_modifyitems(config, items):
    """Mark every test with qt_no_exception_capture by default.

    QtWebEngine's internal Chromium signals fire 'NoneType is not
    callable' during teardown — they're benign but pytest-qt would
    otherwise fail every test.
    """
    import pytest as _pytest
    marker = _pytest.mark.qt_no_exception_capture
    for item in items:
        item.add_marker(marker)


@pytest.fixture(autouse=True)
def _cleanup_after_test():
    """Drain pending events after every test so widget deleteLater() calls
    actually run before the next case opens new web profiles."""
    yield
    app = QApplication.instance()
    if app:
        for _ in range(3):
            app.processEvents()
            gc.collect()
            app.processEvents()


@pytest.fixture
def fresh_config(tmp_path, monkeypatch):
    """Isolate config for a test. Clears the Config singleton and points
    CONFIG_DIR / CONFIG_FILE at a tmp path.
    """
    from qdbrowser import config as cfg_mod
    monkeypatch.setattr(cfg_mod, "CONFIG_DIR", str(tmp_path / "qdbrowser"))
    monkeypatch.setattr(
        cfg_mod, "CONFIG_FILE",
        str(tmp_path / "qdbrowser" / "config.toml"))
    cfg_mod.Config._instance = None
    yield cfg_mod
    cfg_mod.Config._instance = None


@pytest.fixture
def themed_app(qapp):
    from qdbrowser.theme import apply_theme
    apply_theme(qapp, "dark")
    return qapp


@pytest.fixture
def window(qtbot, themed_app, fresh_config):
    from qdbrowser.window import MainWindow
    w = MainWindow()
    w.new_tab(url="about:blank")
    qtbot.addWidget(w)
    w.show()
    qtbot.waitExposed(w)
    return w
