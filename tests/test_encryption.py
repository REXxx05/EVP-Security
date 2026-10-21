from utils.crypto import encrypt_data, decrypt_data

# Tests for AES-256 encryption and decryption
# SR-02: Verifies that sensitive data is encrypted before storing

def test_encrypt_returns_string():
    # Make sure encrypt_data returns a string
    result = encrypt_data('hello world')
    assert isinstance(result, str)

def test_encrypt_does_not_return_plaintext():
    # The encrypted result should not contain the original text
    plaintext = 'sensitive voter data'
    result = encrypt_data(plaintext)
    assert plaintext not in result

def test_decrypt_returns_original():
    # Encrypting then decrypting should give back the original value
    original = 'test voter name'
    encrypted = encrypt_data(original)
    decrypted = decrypt_data(encrypted)
    assert decrypted == original

def test_different_encryptions_of_same_text():
    # Encrypting the same text twice should give different results
    # This is because we use a random nonce each time
    text = 'same text'
    result1 = encrypt_data(text)
    result2 = encrypt_data(text)
    assert result1 != result2

def test_encrypt_empty_string():
    # Should handle empty strings without crashing
    result = encrypt_data('')
    assert isinstance(result, str)
    assert decrypt_data(result) == ''