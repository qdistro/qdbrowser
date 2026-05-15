"""Thin wrapper around QWebEngineView that owns a per-tab profile and
emits a coherent set of signals (mirrors the wrapper-style of qterminator's
TerminalWidget around QTermWidget).

The wrapper supplies:
  - per-instance "group" (for tab stacks)
  - pinned / muted state
  - synchronous title/icon/url accessors
  - one place to inject the per-tab UrlRequestInterceptor

Profiles default to a shared off-the-record profile so private mode is
simple; persistent profiles (cookies, cache, history) attach via
``set_profile``.
"""

from __future__ import annotations

import os
from typing import Optional

from PyQt6.QtCore import (
    Qt, QUrl, pyqtSignal, QObject, QPointF, QEvent, QPoint, QTimer,
    QSize,
)
from PyQt6.QtGui import QIcon, QPainter
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QSizePolicy
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEnginePage, QWebEngineSettings,
    QWebEngineUrlRequestInterceptor,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView


_PROFILES: dict = {}

# Subscribers (plain Python callables) for "a new profile was created"
# events. Used by downloads.py to wire ``downloadRequested`` on every
# profile we mint, without monkey-patching ``get_profile``.
_PROFILE_LISTENERS: list = []


def on_profile_created(callback) -> None:
    """Register ``callback(profile)`` to be invoked for every profile
    qdbrowser creates from now on. Also invoked retroactively for
    every profile already in the cache, so the subscriber doesn't
    miss the default profile that was minted before activation.
    """
    if callback not in _PROFILE_LISTENERS:
        _PROFILE_LISTENERS.append(callback)
    for prof in list(_PROFILES.values()):
        try:
            callback(prof)
        except Exception:
            pass


def off_profile_created(callback) -> None:
    """Unregister a ``callback`` previously passed to
    ``on_profile_created``."""
    try:
        _PROFILE_LISTENERS.remove(callback)
    except ValueError:
        pass


def _notify_profile_created(profile) -> None:
    for cb in list(_PROFILE_LISTENERS):
        try:
            cb(profile)
        except Exception:
            pass


# Monotonic webview id source. ``id()`` is unsafe to expose to agents
# because Python may reuse the memory address after a tab is closed,
# so an agent holding a stale tab_id could end up driving an unrelated
# WebView. We assign a process-unique integer at construction time.
_NEXT_WEBVIEW_ID: int = 1


def _alloc_webview_id() -> int:
    global _NEXT_WEBVIEW_ID
    out = _NEXT_WEBVIEW_ID
    _NEXT_WEBVIEW_ID += 1
    return out


def get_profile(name: str = "default") -> QWebEngineProfile:
    """Return a singleton named profile. Persistent storage under
    ``~/.local/share/qdbrowser/profiles/<name>``. Pass ``"private"`` for
    an off-the-record profile.
    """
    if name in _PROFILES:
        return _PROFILES[name]
    if name == "private":
        prof = QWebEngineProfile()  # off-the-record, no name
    else:
        prof = QWebEngineProfile(name)
        base = os.path.expanduser(f"~/.local/share/qdbrowser/profiles/{name}")
        os.makedirs(base, exist_ok=True)
        prof.setPersistentStoragePath(os.path.join(base, "storage"))
        prof.setCachePath(os.path.join(base, "cache"))
        prof.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
        prof.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies)
    _PROFILES[name] = prof
    _notify_profile_created(prof)
    return prof


class _ChainInterceptor(QWebEngineUrlRequestInterceptor):
    """Fans every URL request through a list of UrlInterceptor plugins.

    Owned by ``WebView`` (so it lives at least as long as the page).
    Plugins register/unregister via ``add`` / ``remove``.
    """

    def __init__(self):
        super().__init__()
        self._handlers: list = []

    def add(self, handler):
        if handler not in self._handlers:
            self._handlers.append(handler)

    def remove(self, handler):
        try:
            self._handlers.remove(handler)
        except ValueError:
            pass

    def interceptRequest(self, info):  # noqa: N802 (Qt API)
        for h in list(self._handlers):
            try:
                h.intercept(info)
            except Exception:
                # A misbehaving plugin must not break navigation.
                pass


class WebView(QWidget):
    """One web view + its title bar.

    Carries Qt signals the window connects to:
      title_changed, icon_changed, url_changed, load_started,
      load_progress, load_finished, focus_gained, close_requested.
    """

    title_changed = pyqtSignal(object, str)            # (self, title)
    icon_changed = pyqtSignal(object, object)          # (self, QIcon)
    url_changed = pyqtSignal(object, str)              # (self, url)
    load_started = pyqtSignal(object)                  # (self,)
    load_progress = pyqtSignal(object, int)            # (self, percent)
    load_finished = pyqtSignal(object, bool)           # (self, ok)
    focus_gained = pyqtSignal(object)                  # (self,)
    close_requested = pyqtSignal(object)               # (self,)

    def __init__(self,
                 url: Optional[str] = None,
                 profile_name: str = "default",
                 parent=None):
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Expanding)
        self._profile = get_profile(profile_name)
        self._profile_name = profile_name
        self._stable_id: int = _alloc_webview_id()
        self.group: Optional[str] = None  # tab-stack name
        self.pinned: bool = False
        self.muted: bool = False
        self._zoom: float = 1.0
        self._page_load_seq: int = 0
        self._last_focus_seen = False

        # Per-page interceptor: owned by this WebView, dies with it. We
        # deliberately do NOT call setUrlRequestInterceptor on the
        # shared profile — that would clobber every other view's chain
        # and leave dangling pointers when the profile outlives the view.
        self._interceptor = _ChainInterceptor()

        self.view = QWebEngineView(self)
        page = QWebEnginePage(self._profile, self.view)
        try:
            page.setUrlRequestInterceptor(self._interceptor)
        except AttributeError:
            # Very old PyQt6 — fall back to profile, accepting the
            # cross-view clobber risk.
            try:
                self._profile.setUrlRequestInterceptor(self._interceptor)
            except AttributeError:
                pass
        self.view.setPage(page)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.view)

        self._wire_signals()

        if url:
            self.navigate(url)

    # -- signals --------------------------------------------------------

    def _wire_signals(self):
        page = self.view.page()
        self.view.titleChanged.connect(self._on_title)
        self.view.iconChanged.connect(self._on_icon)
        self.view.urlChanged.connect(self._on_url)
        self.view.loadStarted.connect(self._on_load_started)
        self.view.loadProgress.connect(self._on_load_progress)
        self.view.loadFinished.connect(self._on_load_finished)

    def _on_title(self, title: str):
        self.title_changed.emit(self, title)

    def _on_icon(self, icon: QIcon):
        self.icon_changed.emit(self, icon)

    def _on_url(self, url: QUrl):
        self.url_changed.emit(self, url.toString())

    def _on_load_started(self):
        self.load_started.emit(self)

    def _on_load_progress(self, percent: int):
        self.load_progress.emit(self, percent)

    def _on_load_finished(self, ok: bool):
        self._page_load_seq += 1
        self.load_finished.emit(self, ok)

    # -- accessors ------------------------------------------------------

    @property
    def profile_name(self) -> str:
        return self._profile_name

    @property
    def stable_id(self) -> int:
        """Process-unique webview id, safe to expose to agents."""
        return self._stable_id

    def title(self) -> str:
        return self.view.title() or self.url() or "New Tab"

    def url(self) -> str:
        return self.view.url().toString()

    def icon(self) -> QIcon:
        return self.view.icon()

    def is_loading(self) -> bool:
        # Qt doesn't expose a stable accessor in all versions; track
        # loadStarted / loadFinished if needed. Default false-on-no-info.
        try:
            return bool(self.view.page().loading())  # type: ignore[attr-defined]
        except Exception:
            return False

    def page_load_seq(self) -> int:
        return self._page_load_seq

    def can_go_back(self) -> bool:
        return self.view.history().canGoBack()

    def can_go_forward(self) -> bool:
        return self.view.history().canGoForward()

    # -- actions --------------------------------------------------------

    def navigate(self, url: str):
        url = url.strip()
        if not url:
            return
        if "://" not in url and not url.startswith("about:"):
            if "." in url and " " not in url:
                url = "https://" + url
            else:
                # Treat as search query.
                from qdbrowser.config import Config
                engine = Config().get(
                    "general", "search_engine",
                    default="https://duckduckgo.com/?q={query}")
                from urllib.parse import quote_plus
                url = engine.replace("{query}", quote_plus(url))
        self.view.setUrl(QUrl(url))

    def reload(self):
        self.view.reload()

    def stop(self):
        self.view.stop()

    def go_back(self):
        self.view.back()

    def go_forward(self):
        self.view.forward()

    def set_zoom(self, factor: float):
        factor = max(0.25, min(5.0, factor))
        self._zoom = factor
        self.view.setZoomFactor(factor)

    def zoom(self) -> float:
        return self._zoom

    def set_muted(self, muted: bool):
        self.muted = muted
        try:
            self.view.page().setAudioMuted(muted)
        except Exception:
            pass

    def set_pinned(self, pinned: bool):
        self.pinned = pinned

    def add_interceptor(self, handler):
        self._interceptor.add(handler)

    def remove_interceptor(self, handler):
        self._interceptor.remove(handler)

    # -- focus ----------------------------------------------------------

    def focusInEvent(self, event):  # noqa: N802 (Qt)
        self.focus_gained.emit(self)
        super().focusInEvent(event)
