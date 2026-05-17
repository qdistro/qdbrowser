"""pwd autofill plugin — wire qdbrowser to the qdistro pwd vault.

Phase-C of plan2/tasks/P04-browser-integration.md.

Flow (high level):

  1. A password field in any tab fires a "focus" event (via a content
     script injected by the WebView). The plugin's
     :meth:`request_fill` is called with the page URL + caller field id.
  2. The plugin mints an intent token (HMAC against the per-session
     secret it fetched during the bridge handshake), then calls
     ``pwd.fill`` on the qdbrowser browser_bridge.
  3. The bridge forwards to ``com.qdistro.Pwd1.Fill`` via D-Bus.
  4. The pwd daemon either returns a candidate credential set OR
     reports ``vault_locked`` — in which case it has already
     triggered the polkit unlock prompt.
  5. The plugin asks the compositor-popup service to render the
     "Autofill <site>?" admin prompt (NOT an in-page DOM element —
     password-manager.md §"Delivery mechanism" forbids that).
  6. On admin approve → plugin pushes the credential into the field
     via ``runJavaScript``. On admin deny → plugin tells the
     content script "no credentials"; the page sees an empty fill
     and the content script surfaces a small toast.

Compositor popup: in production we route through
``org.qdistro.Compositor1.PromptAutofill`` (see browser_bridge.py
§ ``_handle_screenlock_inhibit``-style forward). The plugin defers
the actual D-Bus call through an injectable
:class:`AutofillPromptClient` so unit tests cover the deny + allow
branches without a live compositor.

Cross-references:
  - plan2/research/browser-compositor-autofill-popup.md — open
    question: which exact wp_security_context_v1 toplevel will the
    compositor parent the prompt to? Today the prompt is parented
    to the qdshell admin layer; longer-term it should attach to the
    qdbrowser toplevel so a user can see "this site asked for fill"
    without context-switching.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


log = logging.getLogger("qdbrowser.pwd_autofill")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BRIDGE_BUS_PREFIX = "org.qdistro.BrowserBridge."
BRIDGE_OBJ_PATH = "/org/qdistro/BrowserBridge"
BRIDGE_IFACE = "org.qdistro.BrowserBridge"

PWD_BUS = "com.qdistro.Pwd1"
PWD_OBJ_PATH = "/com/qdistro/Pwd1"
PWD_IFACE = "com.qdistro.Pwd1"

COMPOSITOR_BUS = "org.qdistro.Compositor"
COMPOSITOR_OBJ_PATH = "/org/qdistro/Compositor"
COMPOSITOR_IFACE = "org.qdistro.Compositor1"

INTENT_TOKEN_TTL_S = 5.0


# ---------------------------------------------------------------------------
# Errors surfaced to the caller / extension
# ---------------------------------------------------------------------------

class AutofillError(Exception):
    """Base error for the autofill plugin."""


class AutofillDenied(AutofillError):
    """Admin rejected the autofill prompt."""


class AutofillVaultLocked(AutofillError):
    """Vault is locked and polkit-unlock failed or was cancelled."""


class AutofillNoMatch(AutofillError):
    """No credential matched the URL — falls back to no-op fill."""


# ---------------------------------------------------------------------------
# Intent token (mirrors browser_bridge._compute_token_hmac)
# ---------------------------------------------------------------------------

@dataclass
class IntentToken:
    request_id: str
    ts: float
    op: str
    hmac_hex: str

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "ts": self.ts,
            "op": self.op,
            "hmac": self.hmac_hex,
        }


def mint_intent_token(secret: bytes, op: str,
                      now_fn: Callable[[], float] = time.time
                      ) -> IntentToken:
    """Build an intent token whose HMAC matches the bridge's verify path.

    The canonical message is ``"<request_id>|<ts>|<op>"`` and the MAC is
    SHA-256 against ``secret``. The bridge sweeps an in-memory replay
    map keyed by ``request_id``, so we need only ensure uniqueness
    within the 5-second TTL window — 16 random hex bytes is more than
    enough.
    """
    request_id = secrets.token_hex(16)
    ts = now_fn()
    canonical = f"{request_id}|{ts}|{op}".encode("utf-8")
    mac = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    return IntentToken(request_id=request_id, ts=ts, op=op, hmac_hex=mac)


# ---------------------------------------------------------------------------
# Compositor-popup client (injectable for tests)
# ---------------------------------------------------------------------------

@dataclass
class AutofillPrompt:
    """The content of an autofill prompt rendered by the compositor.

    The compositor displays site + candidate username + an
    allow/deny pair. The selected username (when the user picks one
    from a 1-of-N drop-down) is returned in :class:`AutofillDecision`.
    """
    url: str
    candidate_usernames: tuple[str, ...]
    silo: str


@dataclass
class AutofillDecision:
    allow: bool
    selected_username: Optional[str] = None
    reason: str = ""


class AutofillPromptClient:
    """Interface for asking the compositor to render an autofill prompt.

    Production wires this to ``org.qdistro.Compositor1.PromptAutofill``
    via jeepney. Tests inject a fake that records calls + answers
    synchronously. The method is **blocking** — the caller (the
    plugin's request_fill) parks on the response.

    Justification: even with a polkit-style async surface, the password
    field can't be filled until the user has decided. A synchronous
    block here keeps the dispatch single-threaded; the Qt event loop
    keeps pumping because the prompt runs in qdshell, not in
    qdbrowser's process.
    """

    def prompt(self, payload: AutofillPrompt) -> AutofillDecision:
        raise NotImplementedError


class JeepneyAutofillPromptClient(AutofillPromptClient):
    """jeepney-backed production client.

    Routes through ``org.qdistro.Compositor1.PromptAutofill``. The
    compositor is responsible for rendering the dialog as a floating
    surface, NOT a wp_layer_surface_v1 toplevel that a malicious page
    could fake (see password-manager.md §"Render path").

    On any failure (jeepney missing, compositor absent, RPC timeout)
    the result is ``allow=False, reason="prompt_unreachable"`` —
    fail-closed by design.
    """

    def __init__(self, timeout_s: float = 60.0):
        self._timeout_s = float(timeout_s)

    def prompt(self, payload: AutofillPrompt) -> AutofillDecision:
        try:
            from jeepney import DBusAddress, new_method_call
            from jeepney.io.blocking import open_dbus_connection
        except ImportError:
            return AutofillDecision(
                allow=False, reason="jeepney_missing")
        body_json = json.dumps({
            "url": payload.url,
            "candidate_usernames": list(payload.candidate_usernames),
            "silo": payload.silo,
        })
        try:
            conn = open_dbus_connection(bus="SESSION")
        except Exception as exc:
            log.warning("compositor prompt: SESSION bus unavailable: %s",
                        exc)
            return AutofillDecision(
                allow=False, reason="session_bus_unreachable")
        try:
            addr = DBusAddress(
                COMPOSITOR_OBJ_PATH,
                bus_name=COMPOSITOR_BUS,
                interface=COMPOSITOR_IFACE,
            )
            msg = new_method_call(addr, "PromptAutofill", "s",
                                  (body_json,))
            try:
                reply = conn.send_and_get_reply(
                    msg, timeout=self._timeout_s)
            except Exception as exc:
                log.warning("compositor PromptAutofill failed: %s", exc)
                return AutofillDecision(
                    allow=False, reason="prompt_unreachable")
            if reply.header.message_type.name == "ERROR":
                return AutofillDecision(
                    allow=False, reason="prompt_error")
            try:
                body = (reply.body[0]
                        if reply.body
                        and isinstance(reply.body[0], str)
                        else "{}")
                obj = json.loads(body)
            except Exception:
                return AutofillDecision(
                    allow=False, reason="prompt_bad_reply")
            return AutofillDecision(
                allow=bool(obj.get("allow", False)),
                selected_username=obj.get("username"),
                reason=str(obj.get("reason") or ""),
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Bridge client (injectable for tests)
# ---------------------------------------------------------------------------

class BridgeClient:
    """Surface qdbrowser uses to call the local bridge daemon.

    Production goes through
    :func:`qdistro_browser_bridge_client.call_bridge` which speaks
    ``org.qdistro.BrowserBridge.<ppid>.RequestTabs(op, args_json)``.
    For autofill we keep the same surface so the bridge's
    intent-token verifier sees a regular ``pwd.fill`` op.
    """

    def call(self, op: str, args: dict) -> dict:
        raise NotImplementedError


class JeepneyBridgeClient(BridgeClient):
    """Production client. ppid is the bridge's parent — admin can
    override via ``QDISTRO_BROWSER_BRIDGE_PPID`` for the dev path
    where the bridge is launched standalone."""

    def __init__(self, ppid: Optional[int] = None,
                 timeout_s: float = 10.0):
        self._ppid = ppid
        self._timeout_s = float(timeout_s)

    def _resolve_ppid(self) -> int:
        if self._ppid is not None:
            return int(self._ppid)
        env = os.environ.get("QDISTRO_BROWSER_BRIDGE_PPID", "").strip()
        if env.isdigit():
            return int(env)
        # The bridge claims org.qdistro.BrowserBridge.<browser_ppid>;
        # if we're co-resident with the bridge then our parent is
        # qdbrowser itself, so we have to enumerate the bus.
        return 0

    def call(self, op: str, args: dict) -> dict:
        try:
            from jeepney import DBusAddress, new_method_call
            from jeepney.bus_messages import message_bus
            from jeepney.io.blocking import open_dbus_connection
        except ImportError:
            return {"ok": False, "error": "jeepney_missing"}
        try:
            conn = open_dbus_connection(bus="SESSION")
        except Exception as exc:
            return {"ok": False, "error": "session_bus_unreachable",
                    "detail": str(exc)[:200]}
        try:
            # Resolve the bridge bus name. Prefer an explicit ppid,
            # else scan bus names for the BrowserBridge prefix.
            target = ""
            ppid = self._resolve_ppid()
            if ppid:
                target = f"{BRIDGE_BUS_PREFIX}{ppid}"
            else:
                try:
                    reply = conn.send_and_get_reply(
                        message_bus.ListNames(), timeout=2.0)
                    names = list(reply.body[0]) if reply.body else []
                    for n in names:
                        if n.startswith(BRIDGE_BUS_PREFIX):
                            target = n
                            break
                except Exception as exc:
                    return {"ok": False, "error": "bridge_not_found",
                            "detail": str(exc)[:200]}
            if not target:
                return {"ok": False, "error": "bridge_not_found"}
            addr = DBusAddress(
                BRIDGE_OBJ_PATH,
                bus_name=target,
                interface=BRIDGE_IFACE,
            )
            msg = new_method_call(addr, "RequestTabs", "ss",
                                  (op, json.dumps(args)))
            try:
                reply = conn.send_and_get_reply(
                    msg, timeout=self._timeout_s)
            except Exception as exc:
                return {"ok": False, "error": "bridge_call_failed",
                        "detail": str(exc)[:200]}
            if reply.header.message_type.name == "ERROR":
                return {"ok": False, "error": "bridge_error",
                        "detail": str(reply.body)[:200]}
            if reply.body and isinstance(reply.body[0], str):
                try:
                    return json.loads(reply.body[0])
                except json.JSONDecodeError:
                    return {"ok": False, "error": "bridge_bad_reply"}
            return {"ok": False, "error": "bridge_empty_reply"}
        finally:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Pwd autofill orchestrator
# ---------------------------------------------------------------------------

@dataclass
class FillResult:
    ok: bool
    username: str = ""
    password: str = ""
    error: str = ""

    def to_extension_reply(self) -> dict:
        """Shape the extension sees on the native-messaging port.

        Deny / no-match / locked all collapse to ``{ok: False,
        error: <code>}`` so the content script's UI surface only
        needs a single error branch (browser.md §"deny UX").
        """
        if self.ok:
            return {"ok": True, "username": self.username,
                    "password": self.password}
        return {"ok": False, "error": self.error or "autofill_failed"}


@dataclass
class AutofillOrchestrator:
    """Drives the pwd.fill round-trip + compositor popup.

    Both client surfaces are injected so unit tests cover every branch
    without a real bridge / compositor. The session secret is set via
    :meth:`set_session_secret` after the qdistro.handshake completes.
    """

    bridge: BridgeClient
    prompt: AutofillPromptClient
    silo: str = "user"
    _session_secret: Optional[bytes] = field(default=None, repr=False)

    def set_session_secret(self, secret_hex: str) -> None:
        if not isinstance(secret_hex, str) or not secret_hex:
            self._session_secret = None
            return
        try:
            self._session_secret = bytes.fromhex(secret_hex)
        except ValueError:
            self._session_secret = None

    def has_session(self) -> bool:
        return self._session_secret is not None

    def fill(self, url: str, *, username: Optional[str] = None,
             ) -> FillResult:
        """Run the pwd.fill round-trip end-to-end.

        Returns a :class:`FillResult` whose ``to_extension_reply()``
        the caller forwards back to the WebExtension (or to the
        in-process content-script bridge).

        Steps:

          1. Without a session secret → fail with
             ``no_session``. Caller must handshake first.
          2. Mint an intent token; ``pwd.fill`` requires one.
          3. Call the bridge. Vault-locked is treated as a hard
             failure for this attempt; the pwd daemon has already
             triggered the polkit unlock prompt asynchronously so a
             retry after a few seconds may succeed. The plugin
             surfaces ``vault_locked`` so the content script can
             show a "click to unlock" affordance.
          4. With credentials in hand, ask the compositor popup.
          5. On allow → return the credential. On deny → return
             ``autofill_denied``.
        """
        if not isinstance(url, str) or not url:
            return FillResult(ok=False, error="missing_url")
        if not self.has_session():
            return FillResult(ok=False, error="no_session")
        # Step 2: mint token.
        token = mint_intent_token(self._session_secret, "pwd.fill")
        args = {
            "url": url,
            "username": username,
            "intent_token": token.to_dict(),
        }
        # Step 3: call bridge.
        reply = self.bridge.call("pwd.fill", args)
        if not reply.get("ok"):
            err = reply.get("error", "bridge_error")
            if err == "vault_locked":
                return FillResult(ok=False, error="vault_locked")
            return FillResult(ok=False, error=err)
        credentials = reply.get("credentials") or []
        if not credentials:
            return FillResult(ok=False, error="no_match")
        candidate_usernames = tuple(
            str(c.get("username", "")) for c in credentials
            if c.get("username"))
        # Step 4: compositor popup.
        decision = self.prompt.prompt(AutofillPrompt(
            url=url,
            candidate_usernames=candidate_usernames,
            silo=self.silo,
        ))
        if not decision.allow:
            return FillResult(ok=False, error="autofill_denied")
        # Step 5: pick the user's choice (or the first credential if
        # the compositor didn't echo a username back).
        chosen = None
        if decision.selected_username:
            chosen = next(
                (c for c in credentials
                 if str(c.get("username", "")) == decision.selected_username),
                None)
        if chosen is None:
            chosen = credentials[0]
        return FillResult(
            ok=True,
            username=str(chosen.get("username", "")),
            password=str(chosen.get("password", "")),
        )


# ---------------------------------------------------------------------------
# Module-level convenience for the in-tree integration tests
# ---------------------------------------------------------------------------

def perform_handshake(bridge: BridgeClient) -> Optional[str]:
    """Run ``qdistro.handshake`` against the bridge to fetch the
    per-session HMAC secret. Returns the hex secret or ``None`` on
    failure (logged once at WARN).
    """
    try:
        reply = bridge.call("qdistro.handshake", {})
    except Exception as exc:  # noqa: BLE001
        log.warning("handshake failed: %s", exc)
        return None
    if not reply.get("ok"):
        log.warning("handshake bridge reply not ok: %s",
                    reply.get("error"))
        return None
    secret = reply.get("session_secret_hex") or ""
    if not isinstance(secret, str) or not secret:
        return None
    return secret


__all__ = [
    "AutofillDecision",
    "AutofillDenied",
    "AutofillError",
    "AutofillNoMatch",
    "AutofillOrchestrator",
    "AutofillPrompt",
    "AutofillPromptClient",
    "AutofillVaultLocked",
    "BridgeClient",
    "FillResult",
    "IntentToken",
    "JeepneyAutofillPromptClient",
    "JeepneyBridgeClient",
    "mint_intent_token",
    "perform_handshake",
]
