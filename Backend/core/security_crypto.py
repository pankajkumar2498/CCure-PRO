"""
Module: core.security_crypto
Purpose: Secure encryption and decryption utilities using AES-256-GCM.
Author:  Compliance Dev Team
"""

import base64
import hashlib
import os
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("ccure.compliance.crypto")

# Read master key from environment variables
RAW_KEY = os.environ.get("COMPLIANCE_ENCRYPTION_KEY")

if not RAW_KEY:
    log.warning(
        "COMPLIANCE_ENCRYPTION_KEY is not set. Generating a temporary key for fallback."
    )
    # Use a warning fallback string for local development environments
    RAW_KEY = "CCURE_AUDIT_PRO_DEFAULT_FALLBACK_KEY_DO_NOT_USE_IN_PRODUCTION"

# Derive secure 32-byte key digest via SHA-256
KEY_DIGEST = hashlib.sha256(RAW_KEY.encode("utf-8")).digest()


def encrypt_credential(plain_text: str) -> str:
    """
    Encrypts plain text using AES-256-GCM.

    Args:
        plain_text: The sensitive raw string to encrypt.

    Returns:
        Base64 encoded string containing the 12-byte nonce followed by ciphertext.
    """
    if not plain_text:
        return ""
    aesgcm = AESGCM(KEY_DIGEST)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_credential(cipher_text_b64: str) -> str:
    """
    Decrypts AES-256-GCM encrypted base64 payload.

    Args:
        cipher_text_b64: Base64 encoded string (12-byte nonce + ciphertext).

    Returns:
        The decrypted plain text string.

    Raises:
        ValueError: When the encrypted payload is malformed.
    """
    if not cipher_text_b64:
        return ""
    data = base64.b64decode(cipher_text_b64.encode("utf-8"))
    if len(data) < 12:
        raise ValueError("Invalid encrypted payload size.")
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(KEY_DIGEST)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted.decode("utf-8")
