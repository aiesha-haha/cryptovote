"""
Unit tests for cryptographic primitives:
- Argon2id Password Hashing
- AES-256-GCM Authenticated Encryption & Decryption (with 1-byte tamper detection)
- Ed25519 Asymmetric Digital Signatures
"""

import pytest
from backend.crypto.passwords import hash_password, verify_password
from backend.crypto.encryption import (
    generate_election_key,
    encrypt_ballot,
    decrypt_ballot,
    tamper_hex_payload,
    DecryptionError
)
from backend.crypto.signatures import (
    generate_ed25519_keypair,
    sign_message,
    verify_signature
)


def test_argon2id_password_hashing():
    pwd = "SecretVoterPassword2026!"
    hashed = hash_password(pwd)
    
    # Must start with standard Argon2id signature
    assert hashed.startswith("$argon2id$")
    
    # Correct password succeeds
    assert verify_password(hashed, pwd) is True
    
    # Wrong password fails
    assert verify_password(hashed, "WrongPassword!") is False
    assert verify_password(hashed, "") is False


def test_aes_256_gcm_encryption_roundtrip():
    key = generate_election_key()
    assert len(key) == 32
    
    ballot = {"election_id": 1, "candidate_id": 42, "note": "Криптографиялық таңдау"}
    encrypted = encrypt_ballot(ballot, key, associated_data="1")
    
    assert "ciphertext" in encrypted
    assert "nonce" in encrypted
    assert "auth_tag" in encrypted
    assert len(bytes.fromhex(encrypted["nonce"])) == 12  # 96-bit IV
    assert len(bytes.fromhex(encrypted["auth_tag"])) == 16  # 128-bit tag
    
    decrypted = decrypt_ballot(
        encrypted["ciphertext"],
        encrypted["nonce"],
        encrypted["auth_tag"],
        key,
        associated_data="1"
    )
    assert decrypted["candidate_id"] == 42
    assert decrypted["election_id"] == 1


def test_aes_256_gcm_tamper_detection():
    key = generate_election_key()
    ballot = {"candidate_id": 10}
    encrypted = encrypt_ballot(ballot, key, associated_data="e1")
    
    # 1. Tamper with ciphertext by flipping 1 byte
    corrupted_ciphertext = tamper_hex_payload(encrypted["ciphertext"], byte_index=0)
    with pytest.raises(DecryptionError):
        decrypt_ballot(
            corrupted_ciphertext,
            encrypted["nonce"],
            encrypted["auth_tag"],
            key,
            associated_data="e1"
        )
        
    # 2. Tamper with authentication tag
    corrupted_tag = tamper_hex_payload(encrypted["auth_tag"], byte_index=0)
    with pytest.raises(DecryptionError):
        decrypt_ballot(
            encrypted["ciphertext"],
            encrypted["nonce"],
            corrupted_tag,
            key,
            associated_data="e1"
        )
        
    # 3. Wrong key
    wrong_key = generate_election_key()
    with pytest.raises(DecryptionError):
        decrypt_ballot(
            encrypted["ciphertext"],
            encrypted["nonce"],
            encrypted["auth_tag"],
            wrong_key,
            associated_data="e1"
        )
        
    # 4. Replay attack with wrong associated data
    with pytest.raises(DecryptionError):
        decrypt_ballot(
            encrypted["ciphertext"],
            encrypted["nonce"],
            encrypted["auth_tag"],
            key,
            associated_data="e2_DIFFERENT_ELECTION"
        )


def test_ed25519_signatures():
    priv_pem, pub_pem = generate_ed25519_keypair()
    message = b"SecureVote Official Election Result 2026"
    
    signature = sign_message(priv_pem, message)
    assert len(signature) == 128  # 64 bytes in hex
    
    # Legitimate verification succeeds
    assert verify_signature(pub_pem, signature, message) is True
    
    # Tampered message fails verification
    assert verify_signature(pub_pem, signature, b"Tampered Message!") is False
    
    # Different keypair fails verification
    _, other_pub = generate_ed25519_keypair()
    assert verify_signature(other_pub, signature, message) is False
