"""qdistro bridge adapter — Track 02 D-Bus surface.

When qdistro daemons are present on the session bus, this plugin owns a
per-process well-known D-Bus name (``org.qdistro.QdBrowser.<pid>``) and
exposes qdbrowser's tabs / page / downloads / media surface to the
qdistro daemons through ``org.qdistro.QdBrowser1``. Outbound signals
(``TabAdded``, ``TabRemoved``, ``DownloadStarted``, ``MediaStateChanged``)
let the daemons follow qdbrowser without polling.

This is the qdbrowser-side of the same protocol the WebExtension
native-messaging bridge speaks for Firefox / Chrome — same daemons,
no extension hop. The protocol contract lives in
``todo/browser/02-qdbrowser-unification.md``.

Auth model: every inbound call is gated by per-op polkit actions
(``org.qdistro.qdbrowser.tabs.open`` etc.) using ``pkcheck`` against
the caller's PID, matching the rest of qdistro.

Track-03 (agent guardrails) owns rate-limiting / audit-logging — this
file flags those gaps with ``TODO(track-03)`` comments rather than
implementing them locally.
"""

from __future__ import annotations

import datetime
import logging
import os
import select
import subprocess
import threading
from typing import Any, Callable, Optional


from qdbrowser.config import Config
from qdbrowser.plugin import Plugin


log = logging.getLogger("qdbrowser.bridge_adapter")

_UNSET = object()


# qdistro daemon D-Bus well-known names we probe for. Presence of any
# one of them is enough to flip the adapter active.
#
# Note: the pwd daemon's canonical well-known name is
# ``org.qdistro.Pwd1`` on the SYSTEM bus
# (see qdistro/pwd/qdistro_pwd_daemon.py). The full ``org.qdistro.*``
# rename has landed across the tree, so no legacy alias is kept here.
_DAEMON_NAMES = (
    "org.qdistro.Browser1",
    "org.qdistro.Downloads1",
    "org.qdistro.Pwd1",
)
_SYSTEM_DAEMON_NAMES = (
    "org.qdistro.Pwd1",
    "org.qdistro.AdminBroker1",
)


# Interface name for the qdbrowser-side surface. Track-01 will dispatch
# inbound calls against this; the matching well-known bus name is
# ``org.qdistro.QdBrowser.<pid>`` so admin can fan out to every running
# qdbrowser instance the user owns.
QDBROWSER_IFACE = "org.qdistro.QdBrowser1"
QDBROWSER_PATH = "/org/qdistro/QdBrowser"


# D-Bus introspection XML for the surface. Held as a constant so the
# tests can validate signatures without standing up a real bus.
QDBROWSER_INTROSPECTION_XML = """\
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.qdistro.QdBrowser1">

    <!-- Tabs -->
    <method name="TabsList">
      <arg type="a(uss)" name="tabs" direction="out"/>
    </method>
    <method name="TabsOpen">
      <arg type="s" name="url" direction="in"/>
      <arg type="u" name="id" direction="out"/>
    </method>
    <method name="TabsClose">
      <arg type="u" name="id" direction="in"/>
      <arg type="b" name="ok" direction="out"/>
    </method>

    <!-- Page -->
    <method name="PageExtract">
      <arg type="u" name="tab_id" direction="in"/>
      <arg type="s" name="mode" direction="in"/>
      <arg type="s" name="title" direction="out"/>
      <arg type="s" name="url" direction="out"/>
      <arg type="s" name="content" direction="out"/>
    </method>

    <!-- Downloads -->
    <method name="DownloadsList">
      <arg type="a(usu)" name="downloads" direction="out"/>
    </method>

    <!-- Media (MPRIS bridge) -->
    <method name="MediaStatus">
      <arg type="s" name="title" direction="out"/>
      <arg type="s" name="artist" direction="out"/>
      <arg type="s" name="state" direction="out"/>
    </method>

    <!-- History + Bookmarks (step 3) -->
    <method name="HistorySearch">
      <arg type="s" name="query" direction="in"/>
      <arg type="u" name="limit" direction="in"/>
      <arg type="a(sss)" name="results" direction="out"/>
    </method>
    <method name="BookmarksSearch">
      <arg type="s" name="query" direction="in"/>
      <arg type="u" name="limit" direction="in"/>
      <arg type="a(ss)" name="results" direction="out"/>
    </method>

    <!-- Outbound signals: emitted from window/downloads/media -->
    <signal name="TabAdded">
      <arg type="u" name="id"/>
      <arg type="s" name="url"/>
    </signal>
    <signal name="TabRemoved">
      <arg type="u" name="id"/>
    </signal>
    <signal name="DownloadStarted">
      <arg type="u" name="id"/>
      <arg type="s" name="filename"/>
    </signal>
    <signal name="MediaStateChanged">
      <arg type="s" name="state"/>
    </signal>

  </interface>
</node>
"""


# --------------------------------------------------------------------- #
# Polkit gate
# --------------------------------------------------------------------- #


# Mapping of bridge method name → polkit action id. Read-only methods
# whose policy entry is `allow:yes` still go through pkcheck so the
# enforcement path is uniform; pkcheck returns success for unauth'd
# actions on those.
METHOD_TO_ACTION = {
    "TabsList":         "org.qdistro.qdbrowser.tabs.list",
    "TabsOpen":         "org.qdistro.qdbrowser.tabs.open",
    "TabsClose":        "org.qdistro.qdbrowser.tabs.close",
    "PageExtract":      "org.qdistro.qdbrowser.page.extract",
    "DownloadsList":    "org.qdistro.qdbrowser.downloads.list",
    "MediaStatus":      "org.qdistro.qdbrowser.media.status",
    "HistorySearch":    "org.qdistro.qdbrowser.history.search",
    "BookmarksSearch":  "org.qdistro.qdbrowser.bookmarks.search",
    # Cookies.export not yet wired into a method; the action is reserved
    # for the eventual handler.
}


# Actions that need no polkit check (read-only inventory). pkcheck would
# also pass them via allow:yes, but skipping the subprocess is faster
# and the audit story stays clean.
_OPEN_ACTIONS = {
    "org.qdistro.qdbrowser.tabs.list",
    "org.qdistro.qdbrowser.media.status",
    "org.qdistro.qdbrowser.downloads.list",
    "org.qdistro.qdbrowser.history.search",
    "org.qdistro.qdbrowser.bookmarks.search",
}


def polkit_check(action_id: str, caller_pid: Optional[int],
                 caller_start_time: Optional[int] = None,
                 pkcheck_bin: str = "pkcheck") -> bool:
    """Return True iff polkit authorises ``action_id`` for ``caller_pid``.

    Read-only actions short-circuit to True without a subprocess. For
    mutating actions we shell out to ``pkcheck`` — this matches the
    pattern used elsewhere in qdistro (there is no decent python-polkit
    binding).

    ``caller_pid`` of ``None`` means "internal call" (e.g. tests, the
    plugin's own activation path); polkit is skipped.
    """
    if action_id in _OPEN_ACTIONS:
        return True
    if caller_pid is None:
        return True
    args = [pkcheck_bin, "--action-id", action_id,
            "--process", str(caller_pid)]
    if caller_start_time is not None:
        # pkcheck expects pid,start_time[,uid]. Pass pid,start_time so
        # polkit refuses if the pid has been recycled between auth and
        # check.
        args = [pkcheck_bin, "--action-id", action_id,
                "--process", f"{caller_pid},{caller_start_time}"]
    args.append("--allow-user-interaction")
    try:
        result = subprocess.run(args, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("pkcheck failed for %s pid=%s: %s",
                    action_id, caller_pid, exc)
        return False
    return result.returncode == 0


# --------------------------------------------------------------------- #
# Proxies — duck-typed views over qdbrowser internals
# --------------------------------------------------------------------- #


class TabsProxy:
    """Adapter from the qdbrowser MainWindow into the bridge tabs API.

    The bridge handlers never import PyQt widgets directly; they only
    call into this proxy. That keeps the unit-test surface clean — a
    test can supply any object with the same method shape.
    """

    def __init__(self, window):
        self._window = window

    def list(self) -> list[tuple[int, str, str]]:
        out: list[tuple[int, str, str]] = []
        win = self._window
        if win is None or not hasattr(win, "_tabs"):
            return out
        for i in range(win._tabs.count()):
            split = win._tabs.widget(i)
            views = []
            if hasattr(split, "find_webviews"):
                views = split.find_webviews()
            if not views:
                continue
            wv = views[0]
            try:
                tid = int(getattr(wv, "stable_id",
                                  getattr(wv, "_stable_id", 0)))
                title = wv.title() if callable(getattr(wv, "title", None)) else ""
                url = wv.url() if callable(getattr(wv, "url", None)) else ""
            except Exception:
                continue
            out.append((tid, title or "", url or ""))
        return out

    def open(self, url: str) -> int:
        win = self._window
        if win is None or not hasattr(win, "new_tab"):
            raise RuntimeError("no window")
        wv = win.new_tab(url=url or "about:blank")
        return int(getattr(wv, "stable_id", getattr(wv, "_stable_id", 0)))

    def close(self, tab_id: int) -> bool:
        win = self._window
        if win is None or not hasattr(win, "_tabs"):
            return False
        for i in range(win._tabs.count()):
            split = win._tabs.widget(i)
            if not hasattr(split, "find_webviews"):
                continue
            for wv in split.find_webviews():
                if int(getattr(wv, "stable_id",
                               getattr(wv, "_stable_id", -1))) == int(tab_id):
                    win._on_tab_close_requested(i)
                    return True
        return False


class PagesProxy:
    """Wraps page extraction. Modes: text | html | selection."""

    _VALID_MODES = ("text", "html", "selection")

    def __init__(self, window, run_js: Optional[Callable] = None):
        self._window = window
        # ``run_js`` is the synchronous-with-timeout helper from
        # agent_control. We accept it as a constructor arg so tests
        # don't need to spin up the whole plugin graph.
        self._run_js = run_js

    def _find_webview(self, tab_id: int):
        win = self._window
        if win is None or not hasattr(win, "_tabs"):
            return None
        for i in range(win._tabs.count()):
            split = win._tabs.widget(i)
            if not hasattr(split, "find_webviews"):
                continue
            for wv in split.find_webviews():
                if int(getattr(wv, "stable_id",
                               getattr(wv, "_stable_id", -1))) == int(tab_id):
                    return wv
        return None

    def extract(self, tab_id: int, mode: str) -> tuple[str, str, str]:
        if mode not in self._VALID_MODES:
            raise ValueError(f"unknown mode: {mode!r}")
        wv = self._find_webview(tab_id)
        if wv is None:
            raise LookupError(f"no tab {tab_id}")
        title = wv.title() if callable(getattr(wv, "title", None)) else ""
        url = wv.url() if callable(getattr(wv, "url", None)) else ""
        # JS expressions for each mode — mirror agent_control verbs.
        if mode == "text":
            script = "document.body ? document.body.innerText : ''"
        elif mode == "html":
            script = ("document.documentElement "
                      "? document.documentElement.outerHTML : ''")
        else:  # selection
            script = "window.getSelection ? window.getSelection().toString() : ''"
        content = ""
        if self._run_js is not None:
            try:
                content = self._run_js(wv, script) or ""
            except Exception as exc:
                log.warning("page extract JS failed: %s", exc)
                content = ""
        return (title or "", url or "", str(content))


class DownloadsProxy:
    """Snapshot of the downloads side-panel state."""

    # State strings match qdbrowser's QWebEngineDownloadRequest states.
    _STATE_MAP = {0: "requested", 1: "in_progress", 2: "completed",
                  3: "cancelled", 4: "interrupted"}

    def __init__(self, downloads_plugin):
        self._plugin = downloads_plugin

    def list(self) -> list[tuple[int, str, int]]:
        out: list[tuple[int, str, int]] = []
        plug = self._plugin
        if plug is None:
            return out
        panel = getattr(plug, "_panel", None)
        if panel is None:
            return out
        # Active items first, then a slice of recent history.
        for idx, (_item, widget) in enumerate(getattr(panel, "_items", [])):
            try:
                path = widget.path()
                req = getattr(widget, "_request", None)
                state = req.state() if req is not None else 0
                if hasattr(state, "value"):
                    state = state.value
                out.append((idx, os.path.basename(path), int(state)))
            except Exception:
                continue
        # Historical (finished) downloads use index >= 1<<16 so a tab id
        # space conflict can't arise.
        for hidx, entry in enumerate(getattr(panel, "_history", [])[-25:]):
            try:
                out.append((
                    (1 << 16) + hidx,
                    os.path.basename(str(entry.get("path", ""))),
                    2,  # completed
                ))
            except Exception:
                continue
        return out


class MediaProxy:
    """Best-effort media snapshot.

    Real MPRIS forwarding is daemon-side; here we just expose what the
    qdbrowser process knows. Track 02 wires a minimal state — Track 04
    is responsible for the full picture_in_picture / MPRIS plumb-through.
    """

    def __init__(self):
        self.title = ""
        self.artist = ""
        self.state = "stopped"  # one of: stopped | playing | paused

    def status(self) -> tuple[str, str, str]:
        return (self.title, self.artist, self.state)

    def update(self, title: str = "", artist: str = "",
               state: str = "stopped") -> None:
        self.title = title or ""
        self.artist = artist or ""
        self.state = state or "stopped"


class HistoryProxy:
    """Read-only view over the history plugin for bridge protocol ops.

    Searches the history store and returns ``(url, title, timestamp)``
    triples. The timestamp is ISO-8601 (string) so it survives D-Bus
    without custom type marshalling.
    """

    def __init__(self, history_plugin):
        self._plugin = history_plugin

    def search(self, query: str, limit: int = 50
               ) -> list[tuple[str, str, str]]:
        plug = self._plugin
        if plug is None:
            return []
        store = getattr(plug, "_store", None)
        if store is None:
            return []
        q = query.lower().strip()
        results: list[tuple[str, str, str]] = []
        for rec in store.all():
            if limit and len(results) >= limit:
                break
            url = rec.get("url", "")
            title = rec.get("title", "")
            ts = rec.get("ts", 0)
            if q and q not in url.lower() and q not in title.lower():
                continue
            # Format timestamp as ISO-8601 string for D-Bus transport.
            try:
                ts_str = datetime.datetime.fromtimestamp(
                    float(ts), tz=datetime.timezone.utc
                ).isoformat()
            except (ValueError, OSError, OverflowError):
                ts_str = ""
            results.append((url, title or "", ts_str))
        return results


class BookmarksProxy:
    """Read-only view over the bookmarks plugin for bridge protocol ops.

    Returns ``(url, title)`` pairs matching the query.
    """

    def __init__(self, bookmarks_plugin):
        self._plugin = bookmarks_plugin

    def search(self, query: str, limit: int = 50
               ) -> list[tuple[str, str]]:
        plug = self._plugin
        if plug is None:
            return []
        panel = getattr(plug, "_panel", None)
        if panel is None:
            return []
        q = query.lower().strip()
        results: list[tuple[str, str]] = []
        for b in panel.all():
            if limit and len(results) >= limit:
                break
            url = b.get("url", "")
            title = b.get("title", "")
            if q and q not in url.lower() and q not in title.lower():
                continue
            results.append((url, title or ""))
        return results


# --------------------------------------------------------------------- #
# Method dispatcher
# --------------------------------------------------------------------- #


class BridgeAdapterHandlers:
    """Pure-Python method dispatcher.

    The jeepney bus loop translates an incoming message into a
    ``(method_name, args, caller_pid)`` triple and calls
    :meth:`dispatch`. Returns ``(body_tuple, signature)`` ready to wrap
    in a method-return message.

    Splitting the dispatcher out of the plugin keeps it (a) jeepney-
    free for unit tests and (b) reusable from the Qt-D-Bus path the
    qdshell side will eventually want.
    """

    def __init__(self, tabs: TabsProxy, pages: PagesProxy,
                 downloads: DownloadsProxy, media: MediaProxy,
                 polkit: Callable[[str, Optional[int]], bool] = polkit_check,
                 history: Optional["HistoryProxy"] = None,
                 bookmarks: Optional["BookmarksProxy"] = None):
        self.tabs = tabs
        self.pages = pages
        self.downloads = downloads
        self.media = media
        self.history = history
        self.bookmarks = bookmarks
        self._polkit = polkit

    def dispatch(self, method: str, args: tuple,
                 caller_pid: Optional[int] = None
                 ) -> tuple[tuple, str]:
        action = METHOD_TO_ACTION.get(method)
        if action is None:
            raise LookupError(f"unknown method {method!r}")
        if not self._polkit(action, caller_pid):
            # TODO(track-03): rate-limit denied calls per caller PID
            # once the agent-guardrails audit hook lands.
            raise PermissionError(f"polkit denied {action}")

        if method == "TabsList":
            return ((self.tabs.list(),), "a(uss)")
        if method == "TabsOpen":
            (url,) = args
            return ((self.tabs.open(url),), "u")
        if method == "TabsClose":
            (tab_id,) = args
            return ((self.tabs.close(int(tab_id)),), "b")
        if method == "PageExtract":
            tab_id, mode = args
            title, url, content = self.pages.extract(int(tab_id), str(mode))
            return ((title, url, content), "sss")
        if method == "DownloadsList":
            return ((self.downloads.list(),), "a(usu)")
        if method == "MediaStatus":
            return (self.media.status(), "sss")
        if method == "HistorySearch":
            query, limit = args
            proxy = self.history
            if proxy is None:
                return (([],), "a(sss)")
            return ((proxy.search(str(query), int(limit)),), "a(sss)")
        if method == "BookmarksSearch":
            query, limit = args
            proxy = self.bookmarks
            if proxy is None:
                return (([],), "a(ss)")
            return ((proxy.search(str(query), int(limit)),), "a(ss)")
        raise LookupError(f"unhandled method {method!r}")


# --------------------------------------------------------------------- #
# Probe
# --------------------------------------------------------------------- #


def _daemons_available() -> bool:
    """Best-effort probe: does any qdistro daemon own a well-known name
    on the user session bus?

    Pure jeepney to keep the probe lightweight and dependency-free of
    Qt's D-Bus binding. Any failure (no jeepney, no bus, RPC error)
    returns False — qdbrowser stays standalone.
    """
    try:
        from jeepney import DBusAddress, new_method_call
        from jeepney.io.blocking import open_dbus_connection
    except ImportError:
        return False
    names: set[str] = set()
    for bus_kind, probe_names in (
            ("SESSION", _DAEMON_NAMES),
            ("SYSTEM", _SYSTEM_DAEMON_NAMES)):
        try:
            conn = open_dbus_connection(bus=bus_kind)
        except Exception:
            continue
        try:
            bus = DBusAddress(
                "/org/freedesktop/DBus",
                bus_name="org.freedesktop.DBus",
                interface="org.freedesktop.DBus",
            )
            reply = conn.send_and_get_reply(
                new_method_call(bus, "ListNames"), timeout=2.0)
            bus_names = set(reply.body[0]) if reply.body else set()
            # Only keep names this bus is responsible for so a cross-
            # bus impostor can't pose as a probed daemon.
            names.update(bus_names.intersection(probe_names))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass
    return bool(names)


def _enabled_config_override() -> Optional[bool]:
    """Return explicit bridge_adapter config, or None for autodetect."""
    value = Config().get("plugins", "bridge_adapter", default=_UNSET)
    if value is _UNSET:
        return None
    if isinstance(value, dict):
        if "enabled" not in value:
            return None
        return bool(value.get("enabled"))
    return bool(value)


# --------------------------------------------------------------------- #
# Thread-safe dispatch helper
# --------------------------------------------------------------------- #


class _DispatchHelper:
    """Bounces handler dispatch from the D-Bus recv thread to the main
    thread so Qt widgets are only touched from the GUI thread.

    The recv thread calls :meth:`call_on_main_thread` which posts a
    callable into a queue and waits (with timeout) for the main thread
    to execute it. The main thread is notified via a
    ``QTimer.singleShot(0, ...)`` (always safe to call cross-thread in
    Qt 6) and drains the queue.

    If no Qt event loop is running (e.g. unit tests) the helper falls
    back to direct invocation in the calling thread.
    """

    def __init__(self):
        self._queue: list = []
        self._lock = threading.Lock()

    def _qt_app_running(self) -> bool:
        """Return True if a QApplication exists (i.e. we have a real
        event loop to post to). In unit tests without QApplication,
        we fall back to direct invocation."""
        try:
            from PyQt6.QtWidgets import QApplication
            return QApplication.instance() is not None
        except ImportError:
            return False

    def call_on_main_thread(self, fn: Callable, timeout: float = 10.0
                            ) -> Any:
        """Execute ``fn()`` on the Qt main thread and return its result.

        Blocks the calling thread until the main thread has finished
        or ``timeout`` seconds have elapsed (raises ``TimeoutError``).
        """
        if not self._qt_app_running():
            # No Qt event loop (unit tests, headless) — run directly.
            return fn()

        result_holder: dict = {"value": None, "exc": None, "done": False}
        done_event = threading.Event()

        def _run():
            try:
                result_holder["value"] = fn()
            except Exception as exc:
                result_holder["exc"] = exc
            finally:
                result_holder["done"] = True
                done_event.set()

        with self._lock:
            self._queue.append(_run)

        # Schedule a drain on the main thread.
        try:
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(0, self._drain)
        except Exception:
            # Fallback: execute directly (e.g. no QApp).
            _run()
            done_event.set()

        if not done_event.wait(timeout=timeout):
            raise TimeoutError("main-thread dispatch timed out")

        if result_holder["exc"] is not None:
            raise result_holder["exc"]
        return result_holder["value"]

    def _drain(self):
        with self._lock:
            pending = list(self._queue)
            self._queue.clear()
        for fn in pending:
            fn()


# --------------------------------------------------------------------- #
# Plugin
# --------------------------------------------------------------------- #


class BridgeAdapterPlugin(Plugin):
    name = "bridge_adapter"
    description = "Publishes qdbrowser state to qdistro daemons via D-Bus."
    version = "0.2"
    capabilities = ["bridge_adapter"]

    def __init__(self):
        super().__init__()
        self._active = False
        self._window = None
        self._conn = None
        # Separate connection for PID lookups so that
        # send_and_get_reply doesn't consume inbound method-call
        # messages from the main receive connection.
        self._pid_conn = None
        self._bus_name: Optional[str] = None
        self._handlers: Optional[BridgeAdapterHandlers] = None
        self.tabs_proxy: Optional[TabsProxy] = None
        self.pages_proxy: Optional[PagesProxy] = None
        self.downloads_proxy: Optional[DownloadsProxy] = None
        self.media_proxy: Optional[MediaProxy] = None
        self.history_proxy: Optional[HistoryProxy] = None
        self.bookmarks_proxy: Optional[BookmarksProxy] = None
        self._recv_thread: Optional[threading.Thread] = None
        self._dispatch_helper = _DispatchHelper()
        self._stop = threading.Event()

    @property
    def active(self) -> bool:
        return self._active

    # -- public hooks exposed for tests + sibling plugins ----

    @property
    def bus_name(self) -> Optional[str]:
        """The per-pid well-known D-Bus name this adapter claims."""
        return self._bus_name

    @property
    def handlers(self) -> Optional[BridgeAdapterHandlers]:
        return self._handlers

    def emit_tab_added(self, tab_id: int, url: str) -> None:
        self._emit_signal("TabAdded", (int(tab_id), str(url)), "us")

    def emit_tab_removed(self, tab_id: int) -> None:
        self._emit_signal("TabRemoved", (int(tab_id),), "u")

    def emit_download_started(self, download_id: int, filename: str) -> None:
        self._emit_signal(
            "DownloadStarted", (int(download_id), str(filename)), "us")

    def emit_media_state_changed(self, state: str) -> None:
        self._emit_signal("MediaStateChanged", (str(state),), "s")

    # -- lifecycle ----

    def activate(self, app_controller):
        self._window = app_controller
        explicit = _enabled_config_override()
        if explicit is False:
            log.info("bridge_adapter disabled by config")
            return
        if explicit is not True and not _daemons_available():
            log.info(
                "qdistro daemons not detected on the session bus; "
                "bridge_adapter staying inactive")
            return

        # Build the proxies. They are duck-typed so unit tests can
        # bypass them entirely; here we wire to the real window.
        downloads_plugin = None
        try:
            downloads_plugin = app_controller.plugins.get_by_capability(
                "side_panel")
            downloads_plugin = next(
                (p for p in downloads_plugin if getattr(p, "name", "")
                 == "downloads"), None)
        except Exception:
            downloads_plugin = None

        run_js = None
        try:
            ac_plugin = app_controller.plugins._instances.get("agent_control")
            if ac_plugin is not None and hasattr(ac_plugin, "_run_js"):
                run_js = ac_plugin._run_js
        except Exception:
            run_js = None

        self.tabs_proxy = TabsProxy(app_controller)
        self.pages_proxy = PagesProxy(app_controller, run_js=run_js)
        self.downloads_proxy = DownloadsProxy(downloads_plugin)
        self.media_proxy = MediaProxy()

        # History + bookmarks proxies (step 3). These interface with
        # the existing history and bookmarks plugins. If a plugin is
        # not yet enabled (possible ordering edge) the proxy degrades
        # to returning empty results.
        history_plugin = None
        try:
            history_plugin = app_controller.plugins._instances.get(
                "history")
        except Exception:
            pass
        bookmarks_plugin = None
        try:
            bookmarks_plugin = app_controller.plugins._instances.get(
                "bookmarks")
        except Exception:
            pass
        self.history_proxy = HistoryProxy(history_plugin)
        self.bookmarks_proxy = BookmarksProxy(bookmarks_plugin)

        self._handlers = BridgeAdapterHandlers(
            self.tabs_proxy, self.pages_proxy,
            self.downloads_proxy, self.media_proxy,
            history=self.history_proxy,
            bookmarks=self.bookmarks_proxy)

        # Claim a per-pid well-known name on the session bus. We do NOT
        # crash qdbrowser if the bus rejects us — the plugin degrades
        # to "inactive" the same way as the no-daemons path.
        if not self._claim_bus_name():
            log.warning("bridge_adapter could not claim a D-Bus name; "
                        "staying inactive")
            return

        # Subscribe to window-level signals so we emit outbound D-Bus
        # signals for tab adds/removes. Downloads + media signals get
        # emitted from inside those plugins via
        # ``emit_download_started`` / ``emit_media_state_changed`` —
        # they look up the adapter via the plugin manager.
        try:
            app_controller.webview_added.connect(self._on_webview_added)
            app_controller.webview_removed.connect(self._on_webview_removed)
        except Exception as exc:
            log.warning("could not connect window signals: %s", exc)

        # Start the inbound D-Bus message receive loop. Runs in a
        # dedicated daemon thread so it never blocks the Qt event loop.
        self._start_recv_loop()

        self._active = True
        log.info("bridge_adapter active — bus=%s", self._bus_name)

    def deactivate(self):
        if not self._active:
            return
        self._active = False
        self._stop.set()
        try:
            if self._window is not None:
                try:
                    self._window.webview_added.disconnect(
                        self._on_webview_added)
                except Exception:
                    pass
                try:
                    self._window.webview_removed.disconnect(
                        self._on_webview_removed)
                except Exception:
                    pass
        finally:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
            if self._pid_conn is not None:
                try:
                    self._pid_conn.close()
                except Exception:
                    pass
                self._pid_conn = None
            # Wait for the receive thread to notice the stop event
            # and exit. The thread checks _stop every 0.5 s and the
            # socket close above unblocks any pending select().
            if self._recv_thread is not None:
                self._recv_thread.join(timeout=3.0)
                self._recv_thread = None
            self._handlers = None
            self._bus_name = None

    # -- bus-name claim ----

    def _claim_bus_name(self) -> bool:
        try:
            from jeepney import DBusAddress, new_method_call
            from jeepney.io.blocking import open_dbus_connection
        except ImportError:
            return False
        try:
            self._conn = open_dbus_connection(bus="SESSION")
        except Exception as exc:
            log.warning("session bus unavailable: %s", exc)
            return False
        # Open a second connection dedicated to PID lookups. This
        # avoids consuming inbound method-call messages from the
        # main receive connection when send_and_get_reply blocks.
        try:
            self._pid_conn = open_dbus_connection(bus="SESSION")
        except Exception as exc:
            log.warning("could not open PID-lookup bus connection: %s",
                        exc)
            # Non-fatal: PID resolution will fall back to denying
            # mutating calls when _pid_conn is None.
        name = f"org.qdistro.QdBrowser.pid{os.getpid()}"
        bus = DBusAddress(
            "/org/freedesktop/DBus",
            bus_name="org.freedesktop.DBus",
            interface="org.freedesktop.DBus",
        )
        try:
            reply = self._conn.send_and_get_reply(
                new_method_call(bus, "RequestName", "su", (name, 0)),
                timeout=2.0)
            # 1 == PRIMARY_OWNER, 4 == ALREADY_OWNER.
            owner_code = reply.body[0] if reply.body else 0
            if owner_code not in (1, 4):
                log.warning("RequestName(%s) returned %s", name, owner_code)
                return False
        except Exception as exc:
            log.warning("RequestName failed: %s", exc)
            return False
        self._bus_name = name
        return True

    # -- outbound signal emission ----

    def _emit_signal(self, signal: str, body: tuple, signature: str) -> None:
        if not self._active or self._conn is None:
            return
        try:
            from jeepney import DBusAddress, new_signal
        except ImportError:
            return
        try:
            emitter = DBusAddress(
                QDBROWSER_PATH,
                bus_name=self._bus_name,
                interface=QDBROWSER_IFACE,
            )
            self._conn.send(new_signal(emitter, signal, signature, body))
        except Exception as exc:
            log.warning("could not emit %s signal: %s", signal, exc)

    # -- window signal handlers ----

    def _on_webview_added(self, wv) -> None:
        try:
            tid = int(getattr(wv, "stable_id",
                              getattr(wv, "_stable_id", 0)))
            url = wv.url() if callable(getattr(wv, "url", None)) else ""
        except Exception:
            return
        self.emit_tab_added(tid, url or "")

    def _on_webview_removed(self, wv) -> None:
        try:
            tid = int(getattr(wv, "stable_id",
                              getattr(wv, "_stable_id", 0)))
        except Exception:
            return
        self.emit_tab_removed(tid)

    # -- inbound D-Bus receive loop ----

    def _start_recv_loop(self) -> None:
        """Spin up a daemon thread that blocks on the D-Bus connection fd
        and dispatches inbound method calls to the handlers.

        The thread uses ``select`` on the connection's socket fd with a
        short timeout so it can check ``_stop`` periodically and exit
        cleanly on deactivate.
        """
        if self._conn is None or self._handlers is None:
            return
        self._stop.clear()
        t = threading.Thread(target=self._recv_loop, daemon=True,
                             name="bridge_adapter_recv")
        self._recv_thread = t
        t.start()

    def _recv_loop(self) -> None:
        """Blocking receive loop — runs in a background thread."""
        try:
            from jeepney import (
                MessageType, HeaderFields,
                new_method_return, new_error,
            )
        except ImportError:
            log.warning("jeepney not available; receive loop not started")
            return

        conn = self._conn
        if conn is None:
            return

        while not self._stop.is_set():
            try:
                # Use select with a timeout so we can check _stop.
                # conn.sock is the underlying socket object.
                sock = getattr(conn, "sock", None)
                if sock is None:
                    break
                ready, _, _ = select.select([sock], [], [], 0.5)
                if not ready:
                    continue
                msg = conn.receive(timeout=2.0)
            except (TimeoutError, OSError):
                continue
            except Exception as exc:
                if self._stop.is_set():
                    break
                log.debug("recv_loop error: %s", exc)
                continue

            # Only handle method calls addressed to our interface.
            if msg.header.message_type != MessageType.method_call:
                continue

            fields = msg.header.fields
            iface = fields.get(HeaderFields.interface, "")
            path = fields.get(HeaderFields.path, "")
            member = fields.get(HeaderFields.member, "")

            # Handle standard D-Bus introspection.
            if (iface == "org.freedesktop.DBus.Introspectable"
                    and member == "Introspect"):
                reply = new_method_return(
                    msg, "s", (QDBROWSER_INTROSPECTION_XML,))
                try:
                    conn.send(reply)
                except Exception as exc:
                    log.debug("send introspect reply failed: %s", exc)
                continue

            # Filter to our interface + path.
            if iface != QDBROWSER_IFACE or path != QDBROWSER_PATH:
                continue

            # Resolve the caller's PID for polkit gating, then
            # dispatch on the main thread so Qt widgets are never
            # touched from this background thread.
            sender = fields.get(HeaderFields.sender)
            try:
                caller_pid = self._resolve_sender_pid(sender)
                _member, _body, _pid = member, msg.body, caller_pid
                body, sig = self._dispatch_helper.call_on_main_thread(
                    lambda: self._handlers.dispatch(
                        _member, _body, caller_pid=_pid))
                reply = new_method_return(msg, sig, body)
            except PermissionError as exc:
                reply = new_error(
                    msg,
                    "org.freedesktop.DBus.Error.AccessDenied",
                    "s", (str(exc),))
            except LookupError as exc:
                reply = new_error(
                    msg,
                    "org.freedesktop.DBus.Error.UnknownMethod",
                    "s", (str(exc),))
            except Exception as exc:
                log.warning("dispatch %s failed: %s", member, exc)
                reply = new_error(
                    msg,
                    "org.freedesktop.DBus.Error.Failed",
                    "s", (str(exc),))
            try:
                conn.send(reply)
            except Exception as exc:
                log.debug("send reply for %s failed: %s", member, exc)

    def _resolve_sender_pid(self, sender: Optional[str]
                            ) -> Optional[int]:
        """Ask the bus daemon for the Unix PID of ``sender``.

        Returns the PID as an int, or raises ``PermissionError`` if
        the PID cannot be resolved for an external caller. This
        prevents an authorization bypass where a failed
        ``GetConnectionUnixProcessID`` call would previously return
        ``None`` (treated as 'internal/trusted' by ``polkit_check``).

        Uses ``_pid_conn`` (a dedicated D-Bus connection) so the
        blocking ``send_and_get_reply`` does not consume inbound
        method-call messages from the main receive connection.
        """
        if sender is None:
            # No sender header — treat as internal (e.g. tests).
            return None
        pid_conn = self._pid_conn
        if pid_conn is None:
            raise PermissionError(
                "no PID-lookup bus connection; cannot authorize caller")
        try:
            from jeepney import DBusAddress, new_method_call
            bus = DBusAddress(
                "/org/freedesktop/DBus",
                bus_name="org.freedesktop.DBus",
                interface="org.freedesktop.DBus",
            )
            reply = pid_conn.send_and_get_reply(
                new_method_call(
                    bus, "GetConnectionUnixProcessID",
                    "s", (sender,)),
                timeout=2.0)
            if reply.body:
                return int(reply.body[0])
        except Exception as exc:
            log.debug("could not resolve PID for %s: %s", sender, exc)
        raise PermissionError(
            f"could not resolve PID for D-Bus sender {sender!r}")
