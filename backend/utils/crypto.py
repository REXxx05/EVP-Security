import os
import hashlib
import hmac
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# This file handles all encryption and hashing needs for the EVP system
# SR-02: AES-256 encryption for stored data
# SR-04: SHA-256 hashing for ballot integrity
# SR-18: HMAC pseudonymisation to protect voter identity in logs

ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'encryption-key-must-be-32-bytes!!')
HMAC_KEY = os.environ.get('HMAC_KEY', 'hmac-key-used-for-hashing-voter-pii')


def encrypt_data(plaintext):
    # Encrypts sensitive data using AES-256-GCM before storing in database
    key = ENCRYPTION_KEY.encode()[:32]
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_data(encrypted_text):
    # Decrypts data that was encrypted with encrypt_data
    key = ENCRYPTION_KEY.encode()[:32]
    aesgcm = AESGCM(key)
    data = base64.b64decode(encrypted_text)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def hash_ballot(ballot_data):
    # Creates a SHA-256 hash of a ballot to detect any tampering (SR-04)
    ballot_string = json.dumps(ballot_data, sort_keys=True)
    return hashlib.sha256(ballot_string.encode()).hexdigest()


def pseudonymise_voter(voter_id):
    # Replaces real voter id with an HMAC hash so PII never appears in logs (SR-18)
    key = HMAC_KEY.encode()
    return hmac.new(key, voter_id.encode(), hashlib.sha256).hexdigest()


def hash_log_entry(entry_string):
    # Hashes a log entry so we can build the hash chain (SR-13)
    return hashlib.sha256(entry_string.encode()).hexdigest()