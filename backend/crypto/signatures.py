"""
Ed25519 Asymmetric Digital Signature Module.

Ed25519 (Edwards-curve Digital Signature Algorithm over Curve25519) provides:
- High performance and immune to timing attacks
- Fast signing and verification
- Strong 128-bit security level
- Deterministic signatures (avoids ECDSA poor-RNG compromise vulnerabilities)
"""

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_ed25519_keypair() -> tuple[str, str]:
    """
    Generates an Ed25519 private/public keypair encoded in PEM format.
    :return: (private_key_pem, public_key_pem)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return priv_pem, pub_pem


def sign_message(private_key_pem: str, message: bytes) -> str:
    """
    Signs a binary message using an Ed25519 private key.
    
    :param private_key_pem: PEM-encoded Ed25519 private key.
    :param message: Bytes of data to sign.
    :return: 64-byte signature encoded in hex.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise TypeError("Key provided is not an Ed25519 private key.")
    
    signature_bytes = private_key.sign(message)
    return signature_bytes.hex()


def verify_signature(public_key_pem: str, signature_hex: str, message: bytes) -> bool:
    """
    Verifies an Ed25519 signature against the original message and public key.
    
    :param public_key_pem: PEM-encoded Ed25519 public key.
    :param signature_hex: Hex-encoded signature (128 hex chars / 64 bytes).
    :param message: Bytes of data verified.
    :return: True if valid, False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            return False
        sig_bytes = bytes.fromhex(signature_hex.strip())
        public_key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
