"""
Ballot casting and anonymity enforcement module.

Implements:
1. Strict 1-person-1-vote enforcement (via voter_participation and nullifier uniqueness).
2. Voter-to-ballot decoupling (anonymity barrier):
   - The votes table has NO foreign key to the voter identity.
   - Nullifier is computed via HMAC-SHA256(voter_salt, election_id).
3. AES-256-GCM authenticated ballot encryption.
4. Tamper-evident receipt generation with Ed25519 signature.
"""

from datetime import datetime, timezone
import sqlite3
from backend.database.db import get_db
from backend.crypto.encryption import encrypt_ballot, key_from_hex
from backend.crypto.audit import compute_voter_nullifier, sha256_hash, create_audit_entry
from backend.crypto.signatures import sign_message


class BallotError(Exception):
    pass


class DoubleVotingError(BallotError):
    pass


class ElectionClosedError(BallotError):
    pass


def has_user_voted(user_id: int, election_id: int) -> bool:
    """Checks whether the voter has already cast a ballot in this election."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT 1 FROM voter_participation WHERE election_id = ? AND user_id = ?",
        (election_id, user_id)
    )
    return cursor.fetchone() is not None


def cast_ballot(user_id: int, election_id: int, candidate_id: int) -> dict:
    """
    Casts an authenticated, encrypted, and anonymous ballot within an ACID transaction.
    
    :return: Receipt dictionary containing cryptographic proof of vote acceptance.
    """
    db = get_db()
    cursor = db.cursor()
    
    # 1. Fetch Election
    cursor.execute("SELECT * FROM elections WHERE id = ?", (election_id,))
    election = cursor.fetchone()
    if not election:
        raise BallotError("Выборы не найдены.")
    if election["status"] != "ACTIVE":
        raise ElectionClosedError("Выборы закрыты или неактивны. Прием голосов не осуществляется.")
    
    # 2. Fetch Candidate
    cursor.execute("SELECT * FROM candidates WHERE id = ? AND election_id = ?", (candidate_id, election_id))
    candidate = cursor.fetchone()
    if not candidate:
        raise BallotError("Выбранный кандидат не найден.")
    
    # 3. Fetch Voter
    cursor.execute("SELECT id, username, voter_salt, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        raise BallotError("Избиратель не зарегистрирован в системе.")
    
    # 4. Check Double-Voting
    if has_user_voted(user_id, election_id):
        raise DoubleVotingError(
            "Вы уже проголосовали в этих выборах! "
            "Принцип «1 избиратель — 1 голос» строго защищен от повторных попыток."
        )
    
    # 5. Compute Voter Nullifier
    nullifier = compute_voter_nullifier(user["voter_salt"], election_id)
    
    # 6. Encrypt Ballot with AES-256-GCM
    timestamp = datetime.now(timezone.utc).isoformat()
    ballot_data = {
        "election_id": election_id,
        "candidate_id": candidate_id,
        "timestamp": timestamp
    }
    aes_key = key_from_hex(election["election_key"])
    # Associated data binds ciphertext to election_id
    encrypted = encrypt_ballot(ballot_data, aes_key, associated_data=str(election_id))
    
    # 7. Generate Cryptographic Receipt Hash
    receipt_preimage = f"{nullifier}|{timestamp}|{encrypted['combined']}"
    receipt_hash = sha256_hash(receipt_preimage)
    receipt_signature = sign_message(election["authority_privkey"], receipt_hash.encode("utf-8"))
    
    # 8. Atomic Database Execution
    try:
        # Step A: Record voter participation (marks voter as having voted)
        cursor.execute(
            "INSERT INTO voter_participation (election_id, user_id) VALUES (?, ?)",
            (election_id, user_id)
        )
        
        # Step B: Record encrypted vote into anonymous ballot box
        cursor.execute(
            """
            INSERT INTO votes (election_id, nullifier, ciphertext, nonce, auth_tag, receipt_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                election_id,
                nullifier,
                encrypted["ciphertext"],
                encrypted["nonce"],
                encrypted["auth_tag"],
                receipt_hash
            )
        )
        
        # Step C: Append tamper-evident block into audit ledger
        cursor.execute(
            "SELECT current_hash, index_num FROM audit_ledger WHERE election_id = ? ORDER BY index_num DESC LIMIT 1",
            (election_id,)
        )
        last_block = cursor.fetchone()
        prev_hash = last_block["current_hash"] if last_block else "0" * 64
        next_index = (last_block["index_num"] + 1) if last_block else 0
        
        audit_payload = {
            "action": "VOTE_CAST",
            "receipt_hash": receipt_hash,
            "nonce": encrypted["nonce"],
            "auth_tag": encrypted["auth_tag"],
            "timestamp": timestamp
        }
        
        audit_entry = create_audit_entry(
            index_num=next_index,
            timestamp=timestamp,
            prev_hash=prev_hash,
            action="VOTE_CAST",
            payload=audit_payload,
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
                audit_entry["index_num"],
                audit_entry["timestamp"],
                audit_entry["prev_hash"],
                audit_entry["action"],
                audit_entry["payload_hash"],
                audit_entry["current_hash"],
                audit_entry["signature"],
                audit_entry["details"]
            )
        )
        
        db.commit()
    except sqlite3.IntegrityError as e:
        db.rollback()
        raise DoubleVotingError(f"Ошибка голосования: обнаружена попытка повторного голосования или отклонен токен ({e}).")
    except Exception as e:
        db.rollback()
        raise BallotError(f"Ошибка при записи бюллетеня: {e}")
    
    return {
        "success": True,
        "receipt_hash": receipt_hash,
        "timestamp": timestamp,
        "nonce": encrypted["nonce"],
        "auth_tag": encrypted["auth_tag"],
        "receipt_signature": receipt_signature,
        "authority_pubkey": election["authority_pubkey"],
        "candidate_name": candidate["name"]
    }


def lookup_receipt(receipt_hash: str) -> dict | None:
    """
    Allows any voter or auditor to lookup a ballot receipt on the public ledger.
    Does NOT reveal the candidate choice, only proves acceptance and cryptographic presence.
    """
    receipt_hash = receipt_hash.strip()
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT v.id, v.election_id, v.receipt_hash, v.timestamp, v.nonce, v.auth_tag,
               e.title as election_title, e.authority_pubkey
        FROM votes v
        JOIN elections e ON v.election_id = e.id
        WHERE v.receipt_hash = ?
        """,
        (receipt_hash,)
    )
    row = cursor.fetchone()
    if not row:
        return None
    
    receipt_data = dict(row)
    # Check corresponding audit block
    cursor.execute(
        "SELECT index_num, current_hash, signature FROM audit_ledger WHERE election_id = ? AND details LIKE ? LIMIT 1",
        (receipt_data["election_id"], f"%{receipt_hash}%")
    )
    audit_row = cursor.fetchone()
    if audit_row:
        receipt_data["audit_index"] = audit_row["index_num"]
        receipt_data["block_hash"] = audit_row["current_hash"]
        receipt_data["signature"] = audit_row["signature"]
    
    return receipt_data
