# Tests for SR-14 (Ed25519 signatures).
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from utils import signing


def test_valid_signature_verifies():
    sig = signing.sign(b"candidate 4 excluded")
    assert signing.verify(b"candidate 4 excluded", sig) is True


def test_modified_data_fails():
    sig = signing.sign(b"candidate 4 excluded")
    assert signing.verify(b"candidate 5 excluded", sig) is False


def test_modified_signature_fails():
    sig = signing.sign(b"data")
    # change the first character of the signature
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    assert signing.verify(b"data", flipped) is False


def test_garbage_signature_does_not_crash():
    assert signing.verify(b"data", "not-hex") is False
    assert signing.verify(b"data", "") is False


def test_payload_signature_ignores_key_order():
    sig = signing.sign_payload({"a": 1, "b": 2})
    assert signing.verify_payload({"b": 2, "a": 1}, sig) is True


def test_payload_change_fails():
    sig = signing.sign_payload({"a": 1})
    assert signing.verify_payload({"a": 2}, sig) is False


def test_public_key_is_pem():
    assert signing.public_key_pem().startswith("-----BEGIN PUBLIC KEY-----")