"""Track-02 step-4 tests — DownloadsProxy/MediaProxy forwarding.

Exercises the ``DaemonForwarder`` that publishes qdbrowser downloads +
media to the Phase-9e SESSION-bus daemons (``org.qdistro.Downloads`` /
``org.qdistro.Mpris``). The D-Bus ``call`` is injected so the field
mapping + state translation + fire-and-forget error handling test
without a real session bus — the same injectable-client pattern the
bridge's ``_dbus_client`` uses.
"""

from __future__ import annotations

import json

from qdbrowser.plugins import bridge_adapter as ba


class _RecordingCall:
    """Records every D-Bus call; returns a canned daemon reply."""

    def __init__(self, reply=None, raise_exc=None):
        self.calls = []
        self._reply = reply if reply is not None else {"ok": True}
        self._raise = raise_exc

    def __call__(self, bus, service, path, interface, method, body_json):
        if self._raise is not None:
            raise self._raise
        self.calls.append({
            "bus": bus, "service": service, "path": path,
            "interface": interface, "method": method,
            "body": json.loads(body_json),
        })
        return dict(self._reply)


# --------------------------------------------------------------------- #
# Downloads forwarding
# --------------------------------------------------------------------- #

def test_notify_download_maps_completed_state():
    call = _RecordingCall({"ok": True, "notified": True})
    fwd = ba.DaemonForwarder(call=call)
    reply = fwd.notify_download(
        7, "/home/u/Downloads/a.zip", 2,
        url="https://x/a.zip", mime="application/zip",
        total_bytes=1024, bytes_received=1024)
    assert reply["ok"] is True
    assert len(call.calls) == 1
    c = call.calls[0]
    assert c["bus"] == "SESSION"
    assert c["service"] == "org.qdistro.Downloads"
    assert c["interface"] == "org.qdistro.Downloads1"
    assert c["method"] == "Notify"
    assert c["body"]["download_id"] == 7
    assert c["body"]["state"] == "complete"   # state int 2 -> "complete"
    assert c["body"]["filename"] == "/home/u/Downloads/a.zip"
    assert c["body"]["total_bytes"] == 1024
    # Advisory qdbrowser marker so the daemon can tell it apart.
    assert c["body"]["parent_exe"] == "qdbrowser"


def test_notify_download_state_translation():
    call = _RecordingCall()
    fwd = ba.DaemonForwarder(call=call)
    for state_int, wire in ((0, "in_progress"), (1, "in_progress"),
                            (2, "complete"), (3, "interrupted"),
                            (4, "interrupted")):
        fwd.notify_download(1, "f", state_int)
    states = [c["body"]["state"] for c in call.calls]
    assert states == ["in_progress", "in_progress", "complete",
                      "interrupted", "interrupted"]


def test_notify_download_unknown_state_defaults_in_progress():
    call = _RecordingCall()
    fwd = ba.DaemonForwarder(call=call)
    fwd.notify_download(1, "f", 99)
    assert call.calls[0]["body"]["state"] == "in_progress"


# --------------------------------------------------------------------- #
# MPRIS forwarding
# --------------------------------------------------------------------- #

def test_publish_media_shape():
    call = _RecordingCall({"ok": True, "player": "..."})
    fwd = ba.DaemonForwarder(call=call)
    reply = fwd.publish_media(
        title="Song", artist="Band", state="playing",
        position_us=5_000_000, tab_id=3)
    assert reply["ok"] is True
    c = call.calls[0]
    assert c["service"] == "org.qdistro.Mpris"
    assert c["interface"] == "org.qdistro.Mpris1"
    assert c["method"] == "Publish"
    assert c["body"]["title"] == "Song"
    assert c["body"]["artist"] == "Band"
    assert c["body"]["playback_status"] == "playing"
    assert c["body"]["position_us"] == 5_000_000
    assert c["body"]["tab_id"] == 3


# --------------------------------------------------------------------- #
# Fire-and-forget error handling
# --------------------------------------------------------------------- #

def test_forward_swallows_transport_error():
    call = _RecordingCall(raise_exc=RuntimeError("no bus"))
    fwd = ba.DaemonForwarder(call=call)
    # Must not raise — a daemon outage can't break a download.
    reply = fwd.notify_download(1, "f", 2)
    assert reply["ok"] is False
    assert reply["error"] == "forward_failed"

    reply2 = fwd.publish_media(title="x", state="playing")
    assert reply2["ok"] is False
    assert reply2["error"] == "forward_failed"


def test_forward_propagates_daemon_deny():
    call = _RecordingCall({"ok": False, "error": "parent_not_allowed"})
    fwd = ba.DaemonForwarder(call=call)
    reply = fwd.notify_download(1, "f", 2)
    assert reply["ok"] is False
    assert reply["error"] == "parent_not_allowed"


# --------------------------------------------------------------------- #
# Plugin emit-method integration (forwarder wired in)
# --------------------------------------------------------------------- #

def test_plugin_emit_download_forwards():
    call = _RecordingCall()
    plugin = ba.BridgeAdapterPlugin()
    plugin.forwarder = ba.DaemonForwarder(call=call)
    # _emit_signal is a no-op while inactive; the forward still fires.
    plugin.emit_download_started(5, "report.pdf", state=2,
                                 url="https://x/report.pdf")
    assert len(call.calls) == 1
    assert call.calls[0]["body"]["download_id"] == 5
    assert call.calls[0]["body"]["state"] == "complete"


def test_plugin_emit_media_pulls_metadata_from_proxy():
    call = _RecordingCall()
    plugin = ba.BridgeAdapterPlugin()
    plugin.forwarder = ba.DaemonForwarder(call=call)
    plugin.media_proxy = ba.MediaProxy()
    plugin.media_proxy.update("Track", "Artist", "playing")
    plugin.emit_media_state_changed("playing")
    body = call.calls[0]["body"]
    assert body["title"] == "Track"
    assert body["artist"] == "Artist"
    assert body["playback_status"] == "playing"


def test_plugin_emit_without_forwarder_is_safe():
    # No forwarder bound (daemons absent) — emit must not raise.
    plugin = ba.BridgeAdapterPlugin()
    assert plugin.forwarder is None
    plugin.emit_download_started(1, "f", state=2)
    plugin.emit_media_state_changed("playing")
