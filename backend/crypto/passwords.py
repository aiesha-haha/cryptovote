"""
Argon2id Password Hashing Module for SecureVote.

Argon2id is the winner of the Password Hashing Competition (PHC) and is recommended
by OWASP. It provides hybrid protection:
- Argon2d protects against GPU/ASIC brute-force cracking
- Argon2i protects against side-channel cache-timing attacks
"""

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Recommended OWASP parameters for web applications
ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID
)


def hash_password(plain_password: str) -> str:
    """
    Hashes a plaintext password using Argon2id with a cryptographically secure random salt.
    
    :param plain_password: The plaintext string password.
    :return: Formatted Argon2id hash string ($argon2id$v=19$m=65536,t=2,p=1$...).
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    return ph.hash(plain_password)


def verify_password(hash_str: str, plain_password: str) -> bool:
    """
    Verifies a plaintext password against an Argon2id hash in constant time.
    
    :param hash_str: Stored Argon2id hash.
    :param plain_password: The user-supplied candidate password.
    :return: True if valid, False otherwise.
    """
    if not hash_str or not plain_password:
        return False
    try:
        return ph.verify(hash_str, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def check_needs_rehash(hash_str: str) -> bool:
    """
    Checks if the hash parameters have become obsolete and require re-hashing.
    """
    try:
        return ph.check_needs_rehash(hash_str)
    except Exception:
        return True
