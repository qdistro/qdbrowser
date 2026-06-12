"""Cert-pinning policy: SPKI hashing, PinStore, evaluate, loader.

These tests are pure-Python — they do not spin up a QWebEngineProfile.
The Qt side (``install_cert_policy``) is exercised by integration tests.
"""

import base64
import hashlib
import json
import os
from datetime import UTC

import pytest

# ---------------------------------------------------------------------------
# Fixture cert: generate a minimal self-signed DER at test-collection time.
# ---------------------------------------------------------------------------


def _make_cert_der():
    """Build a self-signed DER cert and return (der_bytes, expected_pin)."""
    pytest.importorskip("cryptography")
    from datetime import datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    spki = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(spki).digest()
    expected = "sha256/" + base64.b64encode(digest).decode("ascii")
    return der, expected


@pytest.fixture(scope="module")
def cert_fixture():
    return _make_cert_der()


# ---------------------------------------------------------------------------
# spki_hash_from_der
# ---------------------------------------------------------------------------


def test_spki_hash_from_der_matches_known_value(cert_fixture):
    from qdbrowser.cert_policy import spki_hash_from_der
    der, expected = cert_fixture
    got = spki_hash_from_der(der)
    assert got == expected


def test_spki_hash_from_der_empty_returns_none():
    from qdbrowser.cert_policy import spki_hash_from_der
    assert spki_hash_from_der(b"") is None
    assert spki_hash_from_der(None) is None


def test_spki_hash_from_der_garbage_returns_none():
    from qdbrowser.cert_policy import spki_hash_from_der
    # Not a SEQUENCE — first byte not 0x30.
    assert spki_hash_from_der(b"\x02\x01\x05") is None
    # Truncated SEQUENCE
    assert spki_hash_from_der(b"\x30\x82\xff\xff") is None


# ---------------------------------------------------------------------------
# PinStore basics
# ---------------------------------------------------------------------------


def test_pinstore_normalizes_host_keys():
    from qdbrowser.cert_policy import PinStore
    store = PinStore(pins={"Example.COM": ["sha256/AAAA"]})
    assert store.is_pinned("example.com")
    assert store.is_pinned("EXAMPLE.com")
    assert "example.com" in store.pinned_hosts


def test_pinstore_drops_malformed_pins():
    from qdbrowser.cert_policy import PinStore
    store = PinStore(pins={
        "good.com": ["sha256/abc", "not-a-pin", 42],
        "empty.com": ["bad"],   # all-bad => dropped entirely
        "none.com": None,
    })
    assert store.pins_for("good.com") == ["sha256/abc"]
    assert store.pins_for("empty.com") == []
    assert not store.is_pinned("empty.com")
    assert not store.is_pinned("none.com")


def test_pinstore_overrides_normalized():
    from qdbrowser.cert_policy import PinStore
    store = PinStore(overrides=["FOO.com", "bar.com", 42, None])
    assert store.is_overridden("foo.com")
    assert store.is_overridden("BAR.COM")
    assert store.overridden_hosts == ["bar.com", "foo.com"]


def test_pinstore_pins_for_unknown_host():
    from qdbrowser.cert_policy import PinStore
    store = PinStore(pins={"a.com": ["sha256/abc"]})
    assert store.pins_for("nothing.com") == []
    assert store.pins_for("") == []


# ---------------------------------------------------------------------------
# evaluate()
# ---------------------------------------------------------------------------


def test_evaluate_unpinned_host_is_ok(cert_fixture):
    from qdbrowser.cert_policy import PinDecision, PinStore
    der, _ = cert_fixture
    store = PinStore()
    d = store.evaluate("nothing.example.com", [der])
    assert d.kind == PinDecision.OK
    assert d.allow is True


def test_evaluate_matching_cert_allows(cert_fixture):
    from qdbrowser.cert_policy import PinDecision, PinStore
    der, expected = cert_fixture
    store = PinStore(pins={"test.example.com": [expected]})
    d = store.evaluate("test.example.com", [der])
    assert d.kind == PinDecision.OK
    assert d.allow is True
    assert expected in d.detail


def test_evaluate_mismatched_cert_rejects(cert_fixture, caplog):
    import logging

    from qdbrowser.cert_policy import PinDecision, PinStore
    der, _ = cert_fixture
    store = PinStore(pins={"test.example.com": ["sha256/AAAAdeadbeef"]})
    with caplog.at_level(logging.WARNING, logger="qdbrowser.cert"):
        d = store.evaluate("test.example.com", [der])
    assert d.kind == PinDecision.PIN_MISMATCH
    assert d.allow is False
    # Journal line is the load-bearing assertion.
    assert any("pin_violation" in r.message for r in caplog.records)


def test_evaluate_pinned_but_overridden_accepts(cert_fixture, caplog):
    import logging

    from qdbrowser.cert_policy import PinDecision, PinStore
    der, _ = cert_fixture
    store = PinStore(
        pins={"test.example.com": ["sha256/wrong"]},
        overrides=["test.example.com"],
    )
    with caplog.at_level(logging.WARNING, logger="qdbrowser.cert"):
        d = store.evaluate("test.example.com", [der])
    assert d.kind == PinDecision.OVERRIDDEN
    assert d.allow is True
    assert any("override active" in r.message for r in caplog.records)


def test_evaluate_no_certs_when_pinned():
    from qdbrowser.cert_policy import PinDecision, PinStore
    store = PinStore(pins={"a.com": ["sha256/abc"]})
    d = store.evaluate("a.com", [])
    assert d.kind == PinDecision.NO_CERTS
    assert d.allow is False


def test_evaluate_intermediate_matches(cert_fixture):
    """If a non-leaf cert matches, the chain is accepted."""
    from qdbrowser.cert_policy import PinDecision, PinStore
    der, expected = cert_fixture
    # Leaf is garbage DER (returns None hash), intermediate is the real cert.
    store = PinStore(pins={"test.example.com": [expected]})
    # First entry is a non-cert blob — its hash is None and skipped.
    d = store.evaluate("test.example.com", [b"\x00\x01garbage", der])
    assert d.kind == PinDecision.OK


# ---------------------------------------------------------------------------
# load_pin_store
# ---------------------------------------------------------------------------


def test_load_pin_store_missing_files(tmp_path):
    from qdbrowser.cert_policy import load_pin_store
    store = load_pin_store(
        system_path=str(tmp_path / "no-system.json"),
        user_path=str(tmp_path / "no-user.json"),
        overrides_path=str(tmp_path / "no-over.json"),
    )
    assert store.pinned_hosts == []
    assert store.overridden_hosts == []


def test_load_pin_store_user_overrides_system(tmp_path):
    from qdbrowser.cert_policy import load_pin_store
    sys_path = tmp_path / "system.json"
    user_path = tmp_path / "user.json"
    over_path = tmp_path / "over.json"
    sys_path.write_text(json.dumps({
        "a.com": ["sha256/sysA"],
        "b.com": ["sha256/sysB"],
    }))
    user_path.write_text(json.dumps({
        "a.com": ["sha256/userA"],  # overrides system
        "c.com": ["sha256/userC"],  # net-new
    }))
    over_path.write_text(json.dumps(["override.com"]))

    store = load_pin_store(
        system_path=str(sys_path),
        user_path=str(user_path),
        overrides_path=str(over_path),
    )
    assert store.pins_for("a.com") == ["sha256/userA"]
    assert store.pins_for("b.com") == ["sha256/sysB"]
    assert store.pins_for("c.com") == ["sha256/userC"]
    assert store.is_overridden("override.com")


def test_load_pin_store_overrides_hosts_dict_form(tmp_path):
    from qdbrowser.cert_policy import load_pin_store
    over_path = tmp_path / "over.json"
    over_path.write_text(json.dumps({"hosts": ["a.com", "b.com"]}))
    store = load_pin_store(overrides_path=str(over_path))
    assert store.is_overridden("a.com")
    assert store.is_overridden("b.com")


def test_load_pin_store_malformed_json_treated_as_empty(tmp_path, caplog):
    import logging

    from qdbrowser.cert_policy import load_pin_store
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with caplog.at_level(logging.WARNING, logger="qdbrowser.cert"):
        store = load_pin_store(system_path=str(bad))
    assert store.pinned_hosts == []
    assert any("unreadable" in r.message for r in caplog.records)


def test_load_pin_store_dev_override_under_home(tmp_path, monkeypatch):
    """User-scope override file in ~/.config/qdbrowser/cert-pins.json wins.

    Use $HOME-driven path expansion to exercise the dev-iteration code path.
    """
    from qdbrowser.cert_policy import load_pin_store

    monkeypatch.setenv("HOME", str(tmp_path))
    user_dir = tmp_path / ".config" / "qdbrowser"
    user_dir.mkdir(parents=True)
    user_path = user_dir / "cert-pins.json"
    user_path.write_text(json.dumps({"dev.example.com": ["sha256/devpin"]}))

    # Now use os.path.expanduser to derive the user_path that production
    # code would derive.
    derived = os.path.expanduser("~/.config/qdbrowser/cert-pins.json")
    assert derived == str(user_path)

    store = load_pin_store(user_path=derived)
    assert store.pins_for("dev.example.com") == ["sha256/devpin"]
