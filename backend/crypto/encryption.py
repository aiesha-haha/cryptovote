"""
AES-256-GCM Authenticated Symmetric Encryption for Ballots.

AES-GCM (Galois/Counter Mode) provides:
1. Confidentiality: AES in counter mode (CTR) encrypts the vote.
2. Authenticity & Integrity: Galois field MAC (GHASH) generates a 128-bit authentication tag.
3. AEAD (Associated Data): Binds the ciphertext to the election ID, preventing replay attacks.
"""

import json
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class DecryptionError(Exception):
    """Raised when ballot decryption or integrity verification fails."""
    pass


def generate_election_key() -> bytes:
    """
    Generates a cryptographically secure 256-bit (32-byte) AES key.
    """
    return secrets.token_bytes(32)


def key_to_hex(key: bytes) -> str:
    """Encodes a binary key to a hex string for safe storage/display."""
    return key.hex()


def key_from_hex(hex_key: str) -> bytes:
    """Decodes a hex string back to a 32-byte binary key."""
    key = bytes.fromhex(hex_key.strip())
    if len(key) != 32:
        raise ValueError(f"AES-256 requires 32 bytes, received {len(key)} bytes.")
    return key


def encrypt_ballot(ballot_data: dict, key: bytes, associated_data: str = "") -> dict:
    """
    Encrypts a voter's ballot dictionary using AES-256-GCM.
    
    :param ballot_data: Dictionary containing candidate choice, salt, timestamp, etc.
    :param key: 32-byte AES key.
    :param associated_data: Context string (e.g. election_id) bound to the ciphertext.
    :return: Dictionary with hex-encoded ciphertext, nonce, auth_tag, and metadata.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")
    
    # Standard 96-bit (12-byte) initialization vector / nonce
    nonce = secrets.token_bytes(12)
    
    plaintext_bytes = json.dumps(ballot_data, sort_keys=True).encode("utf-8")
    aad_bytes = associated_data.encode("utf-8") if associated_data else None
    
    aesgcm = AESGCM(key)
    # aesgcm.encrypt returns ciphertext with the 16-byte authentication tag appended
    encrypted_blob = aesgcm.encrypt(nonce, plaintext_bytes, aad_bytes)
    
    # Separate ciphertext payload from the 16-byte authentication tag for inspection
    raw_ciphertext = encrypted_blob[:-16]
    auth_tag = encrypted_blob[-16:]
    
    return {
        "ciphertext": raw_ciphertext.hex(),
        "nonce": nonce.hex(),
        "auth_tag": auth_tag.hex(),
        "combined": encrypted_blob.hex(),
        "associated_data": associated_data
    }


def decrypt_ballot(
    ciphertext_hex: str,
    nonce_hex: str,
    auth_tag_hex: str,
    key: bytes,
    associated_data: str = ""
) -> dict:
    """
    Decrypts an AES-256-GCM encrypted ballot and verifies cryptographic tag authenticity.
    
    :raises DecryptionError: If the ciphertext was altered, the key is invalid, or the tag fails.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes.")
    
    try:
        raw_ciphertext = bytes.fromhex(ciphertext_hex)
        nonce = bytes.fromhex(nonce_hex)
        auth_tag = bytes.fromhex(auth_tag_hex)
    except ValueError as e:
        raise DecryptionError(f"Hex decoding error: {e}")
    
    # Reassemble ciphertext + tag for AESGCM decrypt
    encrypted_blob = raw_ciphertext + auth_tag
    aad_bytes = associated_data.encode("utf-8") if associated_data else None
    
    aesgcm = AESGCM(key)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, encrypted_blob, aad_bytes)
        return json.loads(decrypted_bytes.decode("utf-8"))
    except InvalidTag:
        raise DecryptionError(
            "Cryptographic verification failed: Authentication Tag mismatch! "
            "Data has been tampered with or incorrect key/associated data was provided."
        )
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {str(e)}")


def tamper_hex_payload(hex_str: str, byte_index: int = 0) -> str:
    """
    Flips a single byte in a hex string to demonstrate tamper-evidence and authentication failure.
    """
    raw = bytearray.fromhex(hex_str)
    if len(raw) == 0:
        return hex_str
    idx = byte_index % len(raw)
    raw[idx] ^= 0xFF  # Flip all 8 bits of the targeted byte
    return raw.hex()
