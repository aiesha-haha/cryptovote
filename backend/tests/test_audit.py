"""
Unit tests for the SHA-256 Tamper-Evident Hash Chain and Merkle Ledger.
"""

from backend.crypto.audit import (
    create_audit_entry,
    verify_audit_chain,
    sha256_hash,
    compute_voter_nullifier
)
from backend.crypto.signatures import generate_ed25519_keypair


def test_sha256_hashing_and_nullifiers():
    h1 = sha256_hash("SecureVote")
    assert len(h1) == 64
    assert h1 == sha256_hash("SecureVote")
    
    # Nullifier uniqueness & determinism per voter/election
    salt1 = "salt_voter_alpha"
    salt2 = "salt_voter_beta"
    
    n1_e1 = compute_voter_nullifier(salt1, 1)
    n1_e1_repeat = compute_voter_nullifier(salt1, 1)
    n1_e2 = compute_voter_nullifier(salt1, 2)
    n2_e1 = compute_voter_nullifier(salt2, 1)
    
    assert n1_e1 == n1_e1_repeat
    assert n1_e1 != n1_e2
    assert n1_e1 != n2_e1


def test_audit_chain_integrity_and_tamper_detection():
    priv_pem, pub_pem = generate_ed25519_keypair()
    
    # Block 0: Genesis
    b0 = create_audit_entry(
        index_num=0,
        timestamp="2026-10-19T10:00:00Z",
        prev_hash="0" * 64,
        action="GENESIS",
        payload={"msg": "Genesis block"},
        election_id=1,
        authority_private_key_pem=priv_pem
    )
    
    # Block 1: Vote
    b1 = create_audit_entry(
        index_num=1,
        timestamp="2026-10-19T10:01:00Z",
        prev_hash=b0["current_hash"],
        action="VOTE_CAST",
        payload={"receipt": "hash123"},
        election_id=1,
        authority_private_key_pem=priv_pem
    )
    
    # Block 2: Tally
    b2 = create_audit_entry(
        index_num=2,
        timestamp="2026-10-19T10:02:00Z",
        prev_hash=b1["current_hash"],
        action="TALLY",
        payload={"results": "winner"},
        election_id=1,
        authority_private_key_pem=priv_pem
    )
    
    chain = [b0, b1, b2]
    
    # Chain verification should succeed
    res = verify_audit_chain(chain, authority_public_key_pem=pub_pem)
    assert res["valid"] is True
    assert res["chain_length"] == 3
    assert res["broken_index"] is None
    
    # TAMPER TEST 1: Alter payload in block 1
    tampered_chain = [b0.copy(), b1.copy(), b2.copy()]
    tampered_chain[1]["payload_hash"] = "ffff" + tampered_chain[1]["payload_hash"][4:]
    res_tamper1 = verify_audit_chain(tampered_chain, authority_public_key_pem=pub_pem)
    assert res_tamper1["valid"] is False
    assert res_tamper1["broken_index"] == 1
    
    # TAMPER TEST 2: Break link by altering prev_hash in block 2
    tampered_chain2 = [b0.copy(), b1.copy(), b2.copy()]
    tampered_chain2[2]["prev_hash"] = "0" * 64
    res_tamper2 = verify_audit_chain(tampered_chain2, authority_public_key_pem=pub_pem)
    assert res_tamper2["valid"] is False
    assert res_tamper2["broken_index"] == 2
