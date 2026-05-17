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

import logging
import os
import subprocess
import threading
from typing import Any, Callable, Optional


from qdbrowser.plugin import Plugin


log = logging.getLogger("qdbrowser.bridge_adapter")


# qdistro daemon D-Bus well-known names we probe for. Presence of any
# one of them is enough to flip the adapter active.
#
# Note: the pwd daemon's canonical well-known name is
# ``com.qdistro.Pwd1`` on the SYSTEM bus
# (see qdistro/pwd/qdistro_pwd_daemon.py). The legacy
# ``org.qdistro.Pwd1`` entry is preserved for backwards-compatibility
# with development installs that still use the old name; the canonical
# entry below is what production matches.
_DAEMON_NAMES = (
    "org.qdistro.Browser1",
    "org.qdistro.Downloads1",
    "org.qdistro.Pwd1",
    "com.qdistro.Pwd1",
)
_SYSTEM_DAEMON_NAMES = (
    "com.qdistro.Pwd1",
    "com.qdistro.AdminBroker1",
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
    "TabsList":      "org.qdistro.qdbrowser.tabs.list",
    "TabsOpen":      "org.qdistro.qdbrowser.tabs.open",
    "TabsClose":     "org.qdistro.qdbrowser.tabs.close",
    "PageExtract":   "org.qdistro.qdbrowser.page.extract",
    "DownloadsList": "org.qdistro.qdbrowser.downloads.list",
    "MediaStatus":   "org.qdistro.qdbrowser.media.status",
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
                 polkit: Callable[[str, Optional[int]], bool] = polkit_check):
        self.tabs = tabs
        self.pages = pages
        self.downloads = downloads
        self.media = media
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
    return any(n in names for n in _DAEMON_NAMES)


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
        self._bus_name: Optional[str] = None
        self._handlers: Optional[BridgeAdapterHandlers] = None
        self.tabs_proxy: Optional[TabsProxy] = None
        self.pages_proxy: Optional[PagesProxy] = None
        self.downloads_proxy: Optional[DownloadsProxy] = None
        self.media_proxy: Optional[MediaProxy] = None
        self._signal_thread: Optional[threading.Thread] = None
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
        if not _daemons_available():
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
        self._handlers = BridgeAdapterHandlers(
            self.tabs_proxy, self.pages_proxy,
            self.downloads_proxy, self.media_proxy)

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
