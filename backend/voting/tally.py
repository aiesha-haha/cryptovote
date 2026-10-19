"""
Cryptographic Vote Tallying and Verification Module.

Performs:
1. Batch AES-256-GCM ballot decryption with Galois/Counter Mode tag verification.
2. Tamper detection: Any ballot whose ciphertext, nonce, or tag was altered will fail
   GHASH authentication, and be recorded as an invalidated/corrupted vote.
3. Candidate vote accumulation.
4. Cryptographic Tally Hash generation (SHA-256) and Ed25519 digital signature.
"""

from datetime import datetime, timezone
import json
from backend.database.db import get_db
from backend.crypto.encryption import decrypt_ballot, key_from_hex, DecryptionError
from backend.crypto.audit import sha256_hash, create_audit_entry
from backend.crypto.signatures import sign_message, verify_signature


def compute_election_tally(election_id: int) -> dict:
    """
    Decrypts all ballots for an election, counts valid votes, detects tampering,
    and publishes an officially signed cryptographic tally proof.
    """
    db = get_db()
    cursor = db.cursor()
    
    # 1. Fetch Election
    cursor.execute("SELECT * FROM elections WHERE id = ?", (election_id,))
    election = cursor.fetchone()
    if not election:
        raise ValueError("Выборы не найдены.")
    
    aes_key = key_from_hex(election["election_key"])
    
    # 2. Fetch Candidates
    cursor.execute("SELECT * FROM candidates WHERE election_id = ? ORDER BY id ASC", (election_id,))
    candidates = [dict(c) for c in cursor.fetchall()]
    candidate_counts = {c["id"]: 0 for c in candidates}
    candidate_names = {c["id"]: c["name"] for c in candidates}
    
    # 3. Fetch All Ballots
    cursor.execute("SELECT * FROM votes WHERE election_id = ? ORDER BY id ASC", (election_id,))
    ballot_rows = cursor.fetchall()
    
    total_votes = len(ballot_rows)
    valid_votes = 0
    invalid_votes = 0
    decryption_failures = []
    
    # 4. Decrypt and Authenticate Each Ballot with AES-256-GCM
    for row in ballot_rows:
        try:
            ballot_data = decrypt_ballot(
                ciphertext_hex=row["ciphertext"],
                nonce_hex=row["nonce"],
                auth_tag_hex=row["auth_tag"],
                key=aes_key,
                associated_data=str(election_id)
            )
            candidate_id = ballot_data.get("candidate_id")
            if candidate_id in candidate_counts:
                candidate_counts[candidate_id] += 1
                valid_votes += 1
            else:
                invalid_votes += 1
                decryption_failures.append({
                    "vote_id": row["id"],
                    "receipt_hash": row["receipt_hash"],
                    "reason": f"Unknown candidate ID: {candidate_id}"
                })
        except DecryptionError as err:
            invalid_votes += 1
            decryption_failures.append({
                "vote_id": row["id"],
                "receipt_hash": row["receipt_hash"],
                "reason": str(err)
            })
    
    # 5. Format Candidate Results
    candidate_breakdown = []
    for c in candidates:
        votes_for_c = candidate_counts.get(c["id"], 0)
        percentage = round((votes_for_c / valid_votes * 100), 2) if valid_votes > 0 else 0.0
        candidate_breakdown.append({
            "id": c["id"],
            "name": c["name"],
            "party": c["party"],
            "avatar_color": c["avatar_color"],
            "votes": votes_for_c,
            "percentage": percentage
        })
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Canonical results dict for signing
    results_payload = {
        "election_id": election_id,
        "total_votes": total_votes,
        "valid_votes": valid_votes,
        "invalid_votes": invalid_votes,
        "candidates": candidate_breakdown,
        "timestamp": timestamp
    }
    
    results_json = json.dumps(results_payload, sort_keys=True)
    tally_hash = sha256_hash(results_json)
    signature = sign_message(election["authority_privkey"], tally_hash.encode("utf-8"))
    
    # 6. Save or Update in tallies table
    cursor.execute("SELECT id FROM tallies WHERE election_id = ?", (election_id,))
    existing_tally = cursor.fetchone()
    if existing_tally:
        cursor.execute(
            """
            UPDATE tallies
            SET total_votes = ?, valid_votes = ?, invalid_votes = ?,
                results_json = ?, tally_hash = ?, signature = ?, tallied_at = ?
            WHERE election_id = ?
            """,
            (total_votes, valid_votes, invalid_votes, results_json, tally_hash, signature, timestamp, election_id)
        )
    else:
        cursor.execute(
            """
            INSERT INTO tallies (
                election_id, total_votes, valid_votes, invalid_votes,
                results_json, tally_hash, signature, tallied_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (election_id, total_votes, valid_votes, invalid_votes, results_json, tally_hash, signature, timestamp)
        )
    
    # 7. Append Tally to Audit Ledger
    cursor.execute(
        "SELECT current_hash, index_num FROM audit_ledger WHERE election_id = ? ORDER BY index_num DESC LIMIT 1",
        (election_id,)
    )
    last_block = cursor.fetchone()
    prev_hash = last_block["current_hash"] if last_block else "0" * 64
    next_index = (last_block["index_num"] + 1) if last_block else 0
    
    audit_block = create_audit_entry(
        index_num=next_index,
        timestamp=timestamp,
        prev_hash=prev_hash,
        action="ELECTION_TALLY_FINALIZED",
        payload={
            "tally_hash": tally_hash,
            "total_votes": total_votes,
            "valid_votes": valid_votes,
            "invalid_votes": invalid_votes
        },
        election_id=election_id,
        authority_private_key_pem=election["authority_privkey"]
    )
    
    cursor.execute(
        """
        INSERT INTO audit_ledger (
            election_id, index_num, timestamp, prev_hash, action,
            payload_hash, current_hash, signature, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            election_id,
            audit_block["index_num"],
            audit_block["timestamp"],
            audit_block["prev_hash"],
            audit_block["action"],
            audit_block["payload_hash"],
            audit_block["current_hash"],
            audit_block["signature"],
            audit_block["details"]
        )
    )
    
    # Mark election status as TALLIED
    cursor.execute("UPDATE elections SET status = 'TALLIED' WHERE id = ?", (election_id,))
    
    db.commit()
    
    return {
        "election_id": election_id,
        "total_votes": total_votes,
        "valid_votes": valid_votes,
        "invalid_votes": invalid_votes,
        "candidates": candidate_breakdown,
        "tally_hash": tally_hash,
        "signature": signature,
        "authority_pubkey": election["authority_pubkey"],
        "decryption_failures": decryption_failures,
        "timestamp": timestamp
    }


def get_tally(election_id: int) -> dict | None:
    """Retrieves the official saved tally for an election."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT t.*, e.authority_pubkey, e.title as election_title
        FROM tallies t
        JOIN elections e ON t.election_id = e.id
        WHERE t.election_id = ?
        """,
        (election_id,)
    )
    row = cursor.fetchone()
    if not row:
        return None
    
    tally_data = dict(row)
    tally_data["results"] = json.loads(tally_data["results_json"])
    
    # Verify the tally signature
    tally_data["signature_valid"] = verify_signature(
        tally_data["authority_pubkey"],
        tally_data["signature"],
        tally_data["tally_hash"].encode("utf-8")
    )
    
    return tally_data
