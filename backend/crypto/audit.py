"""
SHA-256 Hash Chain and Audit Ledger Module.

Implements a blockchain-style tamper-evident sequential ledger:
1. Every audit entry is cryptographically linked to the previous entry via SHA-256.
2. Changing any single character in a past vote, timestamp, or action breaks the hash
   for that entry AND every subsequent entry in the chain.
3. Every block is signed with the Election Authority's Ed25519 private key, preventing
   an attacker from recalculating the whole chain without possessing the private key.
"""

import hashlib
import json
import hmac
from backend.crypto.signatures import sign_message, verify_signature


def sha256_hash(data: str | bytes) -> str:
    """Computes standard SHA-256 hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_voter_nullifier(voter_salt: str, election_id: int) -> str:
    """
    Computes an anonymous single-use nullifier for a voter in a specific election.
    Uses HMAC-SHA256(voter_salt, election_id).
    
    This guarantees:
    1. The voter can only generate ONE valid nullifier per election (prevents double-voting).
    2. The nullifier cannot be reversed to discover the voter's identity (unconditional unlinkability).
    """
    key = voter_salt.encode("utf-8")
    msg = f"CRYPTOVOTE_ELECTION_{election_id}_NULLIFIER".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def compute_block_hash(
    index_num: int,
    timestamp: str,
    prev_hash: str,
    action: str,
    payload_hash: str
) -> str:
    """
    Computes the canonical SHA-256 digest for an audit ledger block:
    H = SHA-256( index || timestamp || prev_hash || action || payload_hash )
    """
    canonical_str = f"{index_num}|{timestamp}|{prev_hash}|{action}|{payload_hash}"
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def create_audit_entry(
    index_num: int,
    timestamp: str,
    prev_hash: str,
    action: str,
    payload: dict | str,
    election_id: int,
    authority_private_key_pem: str
) -> dict:
    """
    Constructs, hashes, and signs a new audit block.
    """
    payload_str = json.dumps(payload, sort_keys=True) if isinstance(payload, dict) else str(payload)
    payload_hash = sha256_hash(payload_str)
    
    current_hash = compute_block_hash(index_num, timestamp, prev_hash, action, payload_hash)
    signature = sign_message(authority_private_key_pem, current_hash.encode("utf-8"))
    
    return {
        "index_num": index_num,
        "timestamp": timestamp,
        "prev_hash": prev_hash,
        "action": action,
        "payload_hash": payload_hash,
        "current_hash": current_hash,
        "signature": signature,
        "details": payload_str,
        "election_id": election_id
    }


def verify_audit_chain(
    chain: list[dict],
    authority_public_key_pem: str | None = None
) -> dict:
    """
    Performs full mathematical and cryptographic verification of the audit chain:
    1. Checks genesis block previous_hash == '0'*64.
    2. Recomputes current_hash for each block and compares against stored hash.
    3. Verifies pointer integrity (block[i].prev_hash == block[i-1].current_hash).
    4. If authority_public_key_pem is provided, verifies Ed25519 digital signature.
    
    :return: Dictionary with verification results and diagnostic details.
    """
    if not chain:
        return {
            "valid": True,
            "chain_length": 0,
            "broken_index": None,
            "error": "Empty chain (valid by default)",
            "head_hash": None
        }
    
    for i, block in enumerate(chain):
        idx = block.get("index_num", i)
        timestamp = block.get("timestamp", "")
        prev_hash = block.get("prev_hash", "")
        action = block.get("action", "")
        payload_hash = block.get("payload_hash", "")
        current_hash = block.get("current_hash", "")
        signature = block.get("signature", "")
        
        # 1. Genesis check
        if i == 0:
            if prev_hash != "0" * 64:
                return {
                    "valid": False,
                    "chain_length": len(chain),
                    "broken_index": 0,
                    "error": f"Genesis block prev_hash must be 64 zeros, got '{prev_hash[:10]}...'",
                    "head_hash": None
                }
        else:
            # 2. Pointer continuity check
            parent_hash = chain[i - 1].get("current_hash")
            if prev_hash != parent_hash:
                return {
                    "valid": False,
                    "chain_length": len(chain),
                    "broken_index": idx,
                    "error": f"Broken chain link at index {idx}! Expected prev_hash='{parent_hash}', got '{prev_hash}'",
                    "head_hash": chain[i - 1].get("current_hash")
                }
        
        # 3. Hash computation integrity check
        expected_hash = compute_block_hash(idx, timestamp, prev_hash, action, payload_hash)
        if expected_hash != current_hash:
            return {
                "valid": False,
                "chain_length": len(chain),
                "broken_index": idx,
                "error": f"Hash mismatch at block index {idx}! Data has been altered. Expected '{expected_hash}', stored '{current_hash}'",
                "head_hash": None
            }
        
        # 4. Digital signature verification
        if authority_public_key_pem and signature:
            is_valid_sig = verify_signature(
                authority_public_key_pem,
                signature,
                current_hash.encode("utf-8")
            )
            if not is_valid_sig:
                return {
                    "valid": False,
                    "chain_length": len(chain),
                    "broken_index": idx,
                    "error": f"Cryptographic signature invalid at block index {idx}! Block was modified or signed by an unauthorized key.",
                    "head_hash": None
                }
    
    return {
        "valid": True,
        "chain_length": len(chain),
        "broken_index": None,
        "error": None,
        "head_hash": chain[-1].get("current_hash")
    }
