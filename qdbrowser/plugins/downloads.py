"""Downloads plugin — intake from every web profile, persistent log,
progress bar per item, pause/resume/cancel, open-on-finish.

Connects to ``downloadRequested`` on every ``QWebEngineProfile`` we
have created via ``qdbrowser.webview.get_profile`` — Qt only fires the
signal on the profile that owns the requesting page, so wiring just
``defaultProfile()`` (the old behaviour) silently dropped downloads
from private mode and any named profile.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from typing import Optional


log = logging.getLogger("qdbrowser.downloads")


def _xdg_open(path: str) -> None:
    """Safely open ``path`` via xdg-open. No shell, no quoting traps —
    the path is one argv element. Detached: parent does not wait.

    Server-suggested download filenames can contain shell metacharacters
    or `$(...)` substitutions; passing them through a shell is RCE.
    """
    if not path:
        return
    try:
        subprocess.Popen(
            ["xdg-open", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        log.warning("xdg-open failed for %r: %s", path, exc)

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
    QPushButton, QLabel, QProgressBar,
)
from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest, QWebEngineProfile

from qdbrowser.config import Config, CONFIG_DIR
from qdbrowser.plugin import SidePanelProvider, CommandProvider
from qdbrowser import webview as wv_mod


HISTORY_PATH = os.path.join(CONFIG_DIR, "downloads.json")


def _load_history() -> list:
    if not os.path.exists(HISTORY_PATH):
        return []
    try:
        with open(HISTORY_PATH) as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_history(items: list):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(HISTORY_PATH, "w") as f:
        json.dump(items, f, indent=2)


class _DownloadItem(QWidget):
    """One row in the downloads panel: filename, progress, controls."""

    cancelled = pyqtSignal(object)  # self

    def __init__(self, request: QWebEngineDownloadRequest, parent=None):
        super().__init__(parent)
        self._request = request
        self._path = os.path.join(request.downloadDirectory(),
                                   request.downloadFileName())
        self._finished = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(2)

        self._name = QLabel(self._render_label())
        self._name.setStyleSheet("font-weight: 600;")
        layout.addWidget(self._name)

        row = QHBoxLayout()
        row.setSpacing(4)
        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setMaximumHeight(8)
        self._bar.setTextVisible(False)
        row.addWidget(self._bar, 1)

        self._pause_btn = QPushButton("⏸")
        self._pause_btn.setMaximumWidth(28)
        self._pause_btn.setToolTip("Pause / resume")
        self._pause_btn.clicked.connect(self._toggle_pause)
        row.addWidget(self._pause_btn)

        self._cancel_btn = QPushButton("✕")
        self._cancel_btn.setMaximumWidth(28)
        self._cancel_btn.setToolTip("Cancel")
        self._cancel_btn.clicked.connect(self._cancel)
        row.addWidget(self._cancel_btn)

        layout.addLayout(row)

        # Signal wiring — every QWebEngineDownloadRequest signal is
        # zero-arg; we read state synchronously when it fires.
        request.receivedBytesChanged.connect(self._on_progress)
        request.totalBytesChanged.connect(self._on_progress)
        request.stateChanged.connect(self._on_state_changed)
        request.isFinishedChanged.connect(self._on_finished)

    def path(self) -> str:
        return self._path

    def is_finished(self) -> bool:
        return self._finished

    def _render_label(self) -> str:
        return f"⬇  {os.path.basename(self._path)}"

    def _on_progress(self):
        total = self._request.totalBytes()
        received = self._request.receivedBytes()
        if total > 0:
            pct = int(received * 100 / total)
            self._bar.setValue(pct)
            self._name.setText(
                f"⬇  {os.path.basename(self._path)}  "
                f"({_human(received)} / {_human(total)})")
        else:
            # Unknown total: indeterminate-looking.
            self._bar.setRange(0, 0)
            self._name.setText(
                f"⬇  {os.path.basename(self._path)}  ({_human(received)})")

    def _on_state_changed(self):
        s = self._request.state()
        DR = QWebEngineDownloadRequest
        if s == DR.DownloadState.DownloadCancelled:
            self._name.setText(f"✕  {os.path.basename(self._path)}  (cancelled)")
            self._pause_btn.setEnabled(False)
            self._cancel_btn.setEnabled(False)
        elif s == DR.DownloadState.DownloadInterrupted:
            self._name.setText(f"⚠  {os.path.basename(self._path)}  (interrupted)")
        elif s == DR.DownloadState.DownloadCompleted:
            self._on_finished()

    def _on_finished(self):
        if self._finished:
            return
        # Qt fires isFinishedChanged on every state transition that
        # toggles isFinished; coalesce.
        if not self._request.isFinished():
            return
        self._finished = True
        self._bar.setRange(0, 100)
        self._bar.setValue(100)
        self._pause_btn.setEnabled(False)
        self._cancel_btn.setText("📂")
        try:
            self._cancel_btn.clicked.disconnect()
        except (RuntimeError, TypeError):
            pass
        self._cancel_btn.clicked.connect(self._open_path)
        self._cancel_btn.setToolTip("Open file")
        self._name.setText(f"✓  {os.path.basename(self._path)}")

    def _toggle_pause(self):
        if self._request.isPaused():
            self._request.resume()
            self._pause_btn.setText("⏸")
        else:
            self._request.pause()
            self._pause_btn.setText("▶")

    def _cancel(self):
        self._request.cancel()
        self.cancelled.emit(self)

    def _open_path(self):
        if os.path.exists(self._path):
            _xdg_open(self._path)


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


class DownloadsPanel(QWidget):
    def __init__(self, window, history: Optional[list] = None):
        super().__init__()
        self._window = window
        self._items: list = []
        self._history: list = history or []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        self._list = QListWidget()
        self._list.setSpacing(2)
        layout.addWidget(self._list, 1)

        row = QHBoxLayout()
        clear_btn = QPushButton("Clear finished")
        clear_btn.clicked.connect(self._clear_finished)
        row.addWidget(clear_btn)
        open_dir_btn = QPushButton("Open dir")
        open_dir_btn.clicked.connect(self._open_dir)
        row.addWidget(open_dir_btn)
        layout.addLayout(row)

        # Replay completed history as static rows so the panel isn't
        # empty after a restart.
        for entry in self._history[-50:]:
            item = QListWidgetItem(
                f"✓  {os.path.basename(entry.get('path',''))}  "
                f"({entry.get('size_str','')})")
            item.setData(Qt.ItemDataRole.UserRole,
                          {"path": entry.get("path"), "historical": True})
            self._list.addItem(item)

        # Open-on-double-click for historical rows.
        self._list.itemActivated.connect(self._on_activated)

    def add_active(self, request: QWebEngineDownloadRequest):
        widget = _DownloadItem(request)
        item = QListWidgetItem()
        item.setSizeHint(widget.sizeHint())
        item.setData(Qt.ItemDataRole.UserRole,
                      {"path": widget.path(), "historical": False})
        self._list.insertItem(0, item)
        self._list.setItemWidget(item, widget)
        self._items.append((item, widget))

        # When the request finishes, persist to history.
        request.isFinishedChanged.connect(
            lambda r=request, w=widget: self._on_finished_persist(r, w))

    def _on_finished_persist(self, request, widget):
        if not request.isFinished():
            return
        if request.state() != QWebEngineDownloadRequest.DownloadState.DownloadCompleted:
            return
        entry = {
            "path": widget.path(),
            "size": request.totalBytes(),
            "size_str": _human(request.totalBytes()),
            "url": request.url().toString(),
            "ts": time.time(),
        }
        self._history.append(entry)
        _save_history(self._history)

    def _clear_finished(self):
        # Remove rows whose widget says finished OR rows whose userrole
        # says historical.
        to_remove = []
        for i in range(self._list.count()):
            item = self._list.item(i)
            data = item.data(Qt.ItemDataRole.UserRole) or {}
            widget = self._list.itemWidget(item)
            if widget is None:
                # historical row
                if data.get("historical"):
                    to_remove.append(i)
            elif isinstance(widget, _DownloadItem) and widget.is_finished():
                to_remove.append(i)
        for i in reversed(to_remove):
            self._list.takeItem(i)

    def _open_dir(self):
        target = Config().get(
            "general", "downloads_dir",
            default=os.path.expanduser("~/Downloads"))
        _xdg_open(target)

    def _on_activated(self, item):
        data = item.data(Qt.ItemDataRole.UserRole) or {}
        p = data.get("path")
        if p and os.path.exists(p):
            _xdg_open(p)


class DownloadsPlugin(SidePanelProvider, CommandProvider):
    name = "downloads"
    description = "Track downloads from every profile."
    capabilities = ["side_panel", "command_provider"]
    panel_id = "downloads"
    panel_label = "Downloads"
    panel_icon = "↓"

    def __init__(self):
        super().__init__()
        self._panel: Optional[DownloadsPanel] = None
        self._window = None
        self._wired_profiles: set = set()
        self._history = _load_history()

    def activate(self, window):
        self._window = window
        # Subscribe to "profile created" so every present and future
        # QWebEngineProfile gets its ``downloadRequested`` signal
        # wired without rebinding ``wv_mod.get_profile``. The webview
        # module replays its current cache to us synchronously.
        wv_mod.on_profile_created(self._wire)
        # Qt creates a defaultProfile() of its own before any
        # ``get_profile`` call; include it explicitly.
        self._wire(QWebEngineProfile.defaultProfile())

    def deactivate(self):
        wv_mod.off_profile_created(self._wire)

    def _wire(self, profile: QWebEngineProfile):
        if id(profile) in self._wired_profiles:
            return
        try:
            profile.downloadRequested.connect(self._on_download_requested)
        except Exception as exc:
            log.warning("could not wire profile: %s", exc)
            return
        self._wired_profiles.add(id(profile))

    def build_panel(self, window):
        self._panel = DownloadsPanel(window, history=self._history)
        return self._panel

    def _on_download_requested(self, request: QWebEngineDownloadRequest):
        target_dir = Config().get(
            "general", "downloads_dir",
            default=os.path.expanduser("~/Downloads"))
        os.makedirs(target_dir, exist_ok=True)
        request.setDownloadDirectory(target_dir)
        if self._panel:
            self._panel.add_active(request)
        request.accept()

    def get_commands(self, window):
        return [
            ("Show downloads panel",
             lambda: window._side_panel.show_panel(self.panel_id)),
            ("Open downloads directory",
             lambda: self._panel._open_dir() if self._panel else None),
            ("Clear finished downloads",
             lambda: self._panel._clear_finished() if self._panel else None),
        ]
