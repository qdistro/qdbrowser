"""Shared pytest fixtures. Mirrors qterminator/tests/conftest.py."""

import gc
import os
import shutil
import sys
import tempfile
import time


_ENV_KEYS = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
)
_ORIGINAL_ENV = {key: os.environ.get(key) for key in _ENV_KEYS}
_TEST_HOME = tempfile.mkdtemp(prefix="qdbrowser-pytest-home-")
_TEST_RUNTIME_DIR = os.path.join(_TEST_HOME, "run")
os.makedirs(_TEST_RUNTIME_DIR, mode=0o700, exist_ok=True)
os.chmod(_TEST_RUNTIME_DIR, 0o700)

# Keep browser config, downloads, WebEngine cache/profile state, and default
# sockets out of the real user's home and /tmp. Several qdbrowser modules
# compute paths at import time, so this must happen before importing them.
os.environ["HOME"] = _TEST_HOME
os.environ["XDG_CONFIG_HOME"] = os.path.join(_TEST_HOME, ".config")
os.environ["XDG_CACHE_HOME"] = os.path.join(_TEST_HOME, ".cache")
os.environ["XDG_DATA_HOME"] = os.path.join(_TEST_HOME, ".local", "share")
os.environ["XDG_RUNTIME_DIR"] = _TEST_RUNTIME_DIR


def _merge_chromium_flags(existing: str, required: list[str]) -> str:
    parts = existing.split()
    for flag in required:
        if flag not in parts:
            parts.append(flag)
    return " ".join(parts)


# Force offscreen and headless Chromium for every test process.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = _merge_chromium_flags(
    os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", ""),
    [
        "--no-sandbox",
        "--disable-gpu",
        "--headless",
        "--in-process-gpu",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-sync",
        "--metrics-recording-only",
        "--disable-default-apps",
    ],
)

# Make sure QtWebEngineWidgets is imported before QApplication.
import PyQt6.QtWebEngineWidgets  # noqa: F401

import pytest

from PyQt6.QtCore import QCoreApplication
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication


def _restore_env():
    for key, value in _ORIGINAL_ENV.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def pytest_sessionfinish(session, exitstatus):
    _restore_env()
    shutil.rmtree(_TEST_HOME, ignore_errors=True)


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
        for _ in range(8):
            QCoreApplication.sendPostedEvents(None, 0)
            app.processEvents()
            gc.collect()
            QTest.qWait(5)
            app.processEvents()


@pytest.fixture
def wait_for_qt(qtbot):
    """Poll a predicate while pumping Qt, with a named timeout failure."""
    def _wait(predicate, *, timeout_ms=10000, interval_ms=10,
              description="condition"):
        deadline = time.monotonic() + (timeout_ms / 1000.0)
        last_error = None
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except Exception as exc:
                last_error = exc
            qtbot.wait(interval_ms)
        detail = f"; last predicate error: {last_error!r}" if last_error else ""
        pytest.fail(
            f"timed out waiting for {description} after {timeout_ms} ms"
            f"{detail}")
    return _wait


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
    from qdbrowser.config import Config
    from qdbrowser.window import MainWindow
    # Keep smart-search tests deterministic and offline when a test drives a
    # bare query through a real window fixture.
    Config().set("general", "search_engine",
                 "https://search.invalid/?q={query}")
    w = MainWindow()
    w.new_tab(url="about:blank")
    qtbot.addWidget(w)
    w.show()
    qtbot.waitExposed(w)
    return w
