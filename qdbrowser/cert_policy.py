"""Certificate pinning policy for qdbrowser.

The cert policy loads two on-disk admin files:

  - ``/etc/qdistro/cert-pins.json`` — system-wide HPKP-style pin map
    ``{"hostname": ["sha256/<b64-spki>", ...]}``. A pinned host whose
    leaf-cert SPKI doesn't match any listed pin is rejected.
  - ``/etc/qdistro/cert-overrides.json`` — break-glass override file
    listing hostnames that bypass pinning entirely (``["host1", ...]``).

A user-scope override file at
``~/.config/qdbrowser/cert-pins.json`` is merged on top of the system
file (entries override). This lets a dev iterate on pins without
needing root.

The on-disk format mirrors Chromium's HPKP wire format:

    sha256/<base64(SHA256(SubjectPublicKeyInfo DER))>

This module exports:

  - ``load_pin_store(...)`` — returns a ``PinStore`` instance.
  - ``PinStore.is_overridden(host)`` — True if host is in the override
    list (skip pinning entirely).
  - ``PinStore.pins_for(host)`` — list of pin strings or [].
  - ``PinStore.evaluate(host, der_certs)`` — decision for a chain.
  - ``install_cert_policy(profile, store)`` — wires the
    ``selectClientCertificate`` / ``certificateError`` signal on a
    ``QWebEngineProfile``.

The journal is the load-bearing assertion surface: every reject lands
as ``qdbrowser.cert pin_violation host=<h> reason=<r>``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from typing import Iterable, Optional

log = logging.getLogger("qdbrowser.cert")


PIN_PREFIX = "sha256/"


class PinDecision:
    """Result of evaluating a chain against a pin set."""

    OK = "ok"                  # not pinned, or chain matched a pin
    PIN_MISMATCH = "pin_mismatch"
    NO_CERTS = "no_certs"
    OVERRIDDEN = "overridden"  # host in cert-overrides.json

    def __init__(self, kind: str, host: str, detail: str = ""):
        self.kind = kind
        self.host = host
        self.detail = detail

    @property
    def allow(self) -> bool:
        return self.kind in (self.OK, self.OVERRIDDEN)

    def __repr__(self) -> str:
        return (f"PinDecision(kind={self.kind!r}, host={self.host!r}, "
                f"detail={self.detail!r})")


class PinStore:
    """In-memory pin map + override set."""

    def __init__(self,
                 pins: Optional[dict] = None,
                 overrides: Optional[Iterable[str]] = None):
        # Normalize: lowercase host keys, strip any non-canonical pins.
        self._pins: dict = {}
        for host, raw in (pins or {}).items():
            cleaned = [p for p in (raw or [])
                       if isinstance(p, str) and p.startswith(PIN_PREFIX)]
            if cleaned:
                self._pins[host.lower()] = cleaned
        self._overrides: set = {h.lower() for h in (overrides or [])
                                if isinstance(h, str)}

    @property
    def pinned_hosts(self) -> list:
        return sorted(self._pins.keys())

    @property
    def overridden_hosts(self) -> list:
        return sorted(self._overrides)

    def pins_for(self, host: str) -> list:
        return list(self._pins.get((host or "").lower(), []))

    def is_pinned(self, host: str) -> bool:
        return (host or "").lower() in self._pins

    def is_overridden(self, host: str) -> bool:
        return (host or "").lower() in self._overrides

    def evaluate(self, host: str, der_certs: Iterable[bytes]) -> PinDecision:
        """Decide whether to accept a TLS chain for ``host``.

        ``der_certs`` is an iterable of DER-encoded certificate bytes
        (leaf first, then intermediates). For pinning, *any* cert in
        the chain whose SPKI hash matches a pin is sufficient — this
        mirrors Chromium's behaviour and lets pins survive a leaf-key
        rotation when the intermediate is pinned.
        """
        if self.is_overridden(host):
            log.warning("cert override active host=%s", host)
            return PinDecision(PinDecision.OVERRIDDEN, host,
                               "host in cert-overrides.json")
        pins = self.pins_for(host)
        if not pins:
            return PinDecision(PinDecision.OK, host, "host not pinned")
        chain = list(der_certs or [])
        if not chain:
            log.warning("pin check no certs host=%s", host)
            return PinDecision(PinDecision.NO_CERTS, host,
                               "no certificates presented")
        chain_hashes = [spki_hash_from_der(c) for c in chain]
        chain_hashes = [h for h in chain_hashes if h]
        for got in chain_hashes:
            if got in pins:
                return PinDecision(PinDecision.OK, host,
                                   f"matched pin {got}")
        log.warning(
            "qdbrowser.cert pin_violation host=%s reason=pin_mismatch "
            "expected=%s got=%s",
            host, ",".join(pins), ",".join(chain_hashes))
        return PinDecision(PinDecision.PIN_MISMATCH, host,
                           f"none of {chain_hashes} in {pins}")


def spki_hash_from_der(der: bytes) -> Optional[str]:
    """Return the ``sha256/<b64>`` pin string for a DER certificate.

    The SPKI is extracted with a minimal-dependency DER walk:
    Certificate ::= SEQUENCE { tbsCertificate, ... }
    tbsCertificate ::= SEQUENCE {
        [0] version, serialNumber, signature, issuer, validity,
        subject, subjectPublicKeyInfo, ... }
    We walk fields by structure rather than parsing the whole thing —
    a full ASN.1 library would be overkill for a single SPKI extract.

    Returns ``None`` on parse failure; the caller treats that as a
    pin miss (and the journal already logged ``cert_parse_error`` from
    the QWebEngine error signal).
    """
    if not der:
        return None
    try:
        spki = _extract_spki(der)
    except Exception as exc:
        log.warning("spki extract failed: %s", exc)
        return None
    if spki is None:
        return None
    digest = hashlib.sha256(spki).digest()
    return PIN_PREFIX + base64.b64encode(digest).decode("ascii")


def _read_len(buf: bytes, off: int):
    """Read a DER length starting at ``off``. Returns ``(length, new_off)``."""
    first = buf[off]
    off += 1
    if first < 0x80:
        return first, off
    n = first & 0x7F
    if n == 0 or off + n > len(buf):
        raise ValueError("bad DER length")
    length = int.from_bytes(buf[off:off + n], "big")
    return length, off + n


def _read_tlv(buf: bytes, off: int):
    """Return ``(tag, value_bytes, next_off)`` for one DER TLV at ``off``."""
    tag = buf[off]
    length, off = _read_len(buf, off + 1)
    end = off + length
    return tag, buf[off:end], end


def _extract_spki(der: bytes) -> Optional[bytes]:
    """Walk a DER Certificate and return the SubjectPublicKeyInfo bytes
    (the full ``SEQUENCE`` TLV, including outer tag/length — that is
    what HPKP hashes)."""
    # Outer Certificate SEQUENCE
    if not der or der[0] != 0x30:
        return None
    _, tbs_and_more, _ = _read_tlv(der, 0)
    # tbs_and_more is the SEQUENCE contents: tbsCertificate (SEQUENCE),
    # signatureAlgorithm, signatureValue.
    if not tbs_and_more or tbs_and_more[0] != 0x30:
        return None
    _, tbs_inner, _ = _read_tlv(tbs_and_more, 0)
    # tbsCertificate inner sequence:
    #   [0] version (optional, EXPLICIT)
    #   serialNumber, signature, issuer, validity, subject,
    #   subjectPublicKeyInfo, ...
    off = 0
    # Skip optional [0] version
    if off < len(tbs_inner) and tbs_inner[off] == 0xA0:
        _, _, off = _read_tlv(tbs_inner, off)
    # serialNumber
    _, _, off = _read_tlv(tbs_inner, off)
    # signature (AlgorithmIdentifier SEQUENCE)
    _, _, off = _read_tlv(tbs_inner, off)
    # issuer (Name)
    _, _, off = _read_tlv(tbs_inner, off)
    # validity (SEQUENCE)
    _, _, off = _read_tlv(tbs_inner, off)
    # subject (Name)
    _, _, off = _read_tlv(tbs_inner, off)
    # subjectPublicKeyInfo (SEQUENCE) — capture the FULL TLV
    if off >= len(tbs_inner) or tbs_inner[off] != 0x30:
        return None
    start = off
    _, _, off = _read_tlv(tbs_inner, off)
    return bytes(tbs_inner[start:off])


def load_pin_store(system_path: Optional[str] = None,
                   user_path: Optional[str] = None,
                   overrides_path: Optional[str] = None) -> PinStore:
    """Load the pin store. Missing files are treated as empty maps —
    qdbrowser must never refuse to start because the admin file isn't
    there yet.
    """
    pins: dict = {}
    if system_path and os.path.exists(system_path):
        pins.update(_load_json_dict(system_path))
    if user_path and os.path.exists(user_path):
        # User entries override system entries for the same host.
        pins.update(_load_json_dict(user_path))
    overrides: list = []
    if overrides_path and os.path.exists(overrides_path):
        ov = _load_json(overrides_path)
        if isinstance(ov, list):
            overrides = [str(x) for x in ov if isinstance(x, str)]
        elif isinstance(ov, dict) and "hosts" in ov:
            overrides = [str(x) for x in ov["hosts"] if isinstance(x, str)]
    return PinStore(pins=pins, overrides=overrides)


def _load_json(path: str):
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except Exception as exc:
        log.warning("cert-pins file %s unreadable: %s", path, exc)
        return None


def _load_json_dict(path: str) -> dict:
    data = _load_json(path)
    return data if isinstance(data, dict) else {}


def install_cert_policy(profile, store: PinStore) -> None:
    """Wire ``certificateError`` on a ``QWebEngineProfile`` so a pinned
    host's certificate error is logged and rejected.

    QtWebEngine's certificate pipeline doesn't expose the full chain to
    the URL interceptor, so we attach to ``certificateError`` (raised
    when the system store already failed) and additionally inspect the
    chain via ``QWebEngineCertificateError.certificateChain()`` if it's
    available in this Qt version. If a pinned host hits a cert error,
    we never let the user override — pin violations are hard rejects.
    """
    try:
        signal = profile.certificateError  # PyQt6 6.5+
    except AttributeError:
        log.info("profile %s has no certificateError signal; "
                 "cert pinning relies on system store only",
                 getattr(profile, "storageName", lambda: "?")())
        return

    def _on_error(error):
        try:
            host = error.url().host()
        except Exception:
            host = ""
        decision = None
        chain = []
        if hasattr(error, "certificateChain"):
            try:
                chain = [bytes(c.toDer())
                         for c in error.certificateChain()
                         if hasattr(c, "toDer")]
            except Exception:
                chain = []
        if store.is_pinned(host):
            decision = store.evaluate(host, chain)
            if not decision.allow:
                log.warning(
                    "qdbrowser.cert reject host=%s reason=%s",
                    host, decision.kind)
                try:
                    error.rejectCertificate()
                except Exception:
                    pass
                return
        # Not pinned: let the default behaviour decide (Qt will show
        # the standard certificate error UI for users to override on
        # non-pinned hosts).
        log.info("qdbrowser.cert default-handling host=%s", host)

    try:
        signal.connect(_on_error)
    except Exception as exc:
        log.warning("could not connect certificateError on profile: %s", exc)
