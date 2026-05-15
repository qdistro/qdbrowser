"""qdistro bridge adapter — Phase 10 skeleton.

When qdistro daemons are present on the session bus, this plugin
publishes qdbrowser state (tabs, history, downloads, media) to them and
accepts inbound D-Bus calls for ``tabs.list`` / ``tabs.open`` /
``tabs.close`` etc. It is the qdbrowser-side counterpart to the Firefox/
Chrome WebExtension + native-messaging bridge — same protocol, no
extension hop.

Current status: **skeleton**. The plugin auto-detects whether qdistro
daemons are running and stays inactive if none are. The full inbound /
outbound D-Bus surface lands in Phase 10 once the daemons exist; see
``todo/browser/02-qdbrowser-unification.md`` for the protocol and the
per-op polkit policy (``com.qdistro.browser.tabs_list`` etc.).

Auth model for inbound D-Bus calls follows the qdistro-pwd precedent:
``SO_PEERCRED`` + ``/proc/<pid>/exe`` + per-op polkit action. SELinux
labels are audit-only.
"""

from __future__ import annotations

import logging

from qdbrowser.plugin import Plugin


log = logging.getLogger("qdbrowser.bridge_adapter")


# qdistro daemon D-Bus well-known names we probe for. Presence of any
# one of them is enough to flip the adapter active.
_DAEMON_NAMES = (
    "org.qdistro.Browser1",
    "org.qdistro.Downloads1",
    "org.qdistro.Pwd1",
)


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
    try:
        conn = open_dbus_connection(bus="SESSION")
    except Exception:
        return False
    try:
        bus = DBusAddress(
            "/org/freedesktop/DBus",
            bus_name="org.freedesktop.DBus",
            interface="org.freedesktop.DBus",
        )
        reply = conn.send_and_get_reply(
            new_method_call(bus, "ListNames"), timeout=2.0)
        names = set(reply.body[0]) if reply.body else set()
    except Exception:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return any(n in names for n in _DAEMON_NAMES)


class BridgeAdapterPlugin(Plugin):
    name = "bridge_adapter"
    description = "Publishes qdbrowser state to qdistro daemons via D-Bus."
    version = "0.1"
    capabilities = ["bridge_adapter"]

    def __init__(self):
        super().__init__()
        self._active = False
        self._window = None

    @property
    def active(self) -> bool:
        return self._active

    def activate(self, app_controller):
        self._window = app_controller
        if not _daemons_available():
            log.info(
                "qdistro daemons not detected on the session bus; "
                "bridge_adapter staying inactive")
            return
        self._active = True
        log.info("bridge_adapter active — qdistro daemons detected")
        # Phase 10 deliverables:
        #   - Register as a browser source with org.qdistro.Browser1
        #     (RegisterSource(name='qdbrowser', uid=getuid(),
        #     binary='/usr/bin/qdbrowser')).
        #   - Claim a per-process well-known D-Bus name so daemons can
        #     dispatch inbound tabs.list / tabs.open / tabs.close.
        #   - Subscribe to window tab/download/media signals and forward
        #     to the relevant daemon.
        #   - Per-op polkit gate (com.qdistro.browser.tabs_list etc.)
        #     before honouring any inbound call.

    def deactivate(self):
        if not self._active:
            return
        self._active = False
        # Phase 10: unregister source, drop the D-Bus name, disconnect
        # signal handlers.
