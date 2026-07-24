"""
Module: tests.test_compliance_crypto
Purpose: Test AES-256-GCM encryption, decryption, and key derivation helpers.
Author:  Compliance Dev Team
"""

import base64
import os

import pytest
from core.security_crypto import decrypt_credential, encrypt_credential


def test_encryption_decryption_flow():
    """Verify that text encrypted can be decrypted back to the original string."""
    plain = "SuperSecretSSHPassword123"
    cipher_b64 = encrypt_credential(plain)

    assert cipher_b64 != plain
    assert len(cipher_b64) > 16

    decrypted = decrypt_credential(cipher_b64)
    assert decrypted == plain


def test_encryption_generates_random_nonces():
    """Verify that encrypting the same text twice yields different ciphertexts due to random nonces."""
    plain = "ConstantString"
    cipher1 = encrypt_credential(plain)
    cipher2 = encrypt_credential(plain)

    assert cipher1 != cipher2
    assert decrypt_credential(cipher1) == plain
    assert decrypt_credential(cipher2) == plain


def test_decryption_malformed_payloads():
    """Verify that decrypting malformed or short payloads raises ValueError or decryption errors."""
    with pytest.raises(ValueError):
        decrypt_credential("short")

    # Generate a payload that has a valid base64 length but is tampered with
    payload = base64.b64encode(os.urandom(20)).decode("utf-8")
    with pytest.raises(ValueError):
        decrypt_credential(payload)
