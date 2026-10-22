# SR-14: digital signatures using Ed25519.
# old signatures stop verifying after a restart. Fine for testing only.
import base64
import json
import os
import warnings

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_private_key_b64():
    raw = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode()


def _load_private_key():
    b64 = os.environ.get("SIGNING_PRIVATE_KEY")
    if b64:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(b64))
    warnings.warn("SIGNING_PRIVATE_KEY not set: using a temporary signing key")
    return Ed25519PrivateKey.generate()


_private_key = _load_private_key()
_public_key = _private_key.public_key()


def canonical(payload):
    # sorted keys and no spaces, so the same data always gives the same bytes
    # (otherwise we couldn't re-check a signature later)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(data):
    return _private_key.sign(data).hex()


def verify(data, signature_hex):
    # bad or garbled signatures just return False instead of crashing
    try:
        _public_key.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


def sign_payload(payload):
    return sign(canonical(payload))


def verify_payload(payload, signature_hex):
    return verify(canonical(payload), signature_hex)


def public_key_pem():
    # safe to share, anyone can use it to check our signatures
    return _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()