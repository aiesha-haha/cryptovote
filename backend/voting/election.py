"""
Election management module for SecureVote.
Handles election lifecycle: Creation -> Active Voting -> Closed -> Tallied.
"""

from datetime import datetime, timezone
from backend.database.db import get_db
from backend.crypto.encryption import generate_election_key, key_to_hex
from backend.crypto.signatures import generate_ed25519_keypair
from backend.crypto.audit import create_audit_entry


def create_election(title: str, description: str, candidates: list[dict]) -> int:
    """
    Initializes a new election with its unique AES-256-GCM key, Ed25519 Authority keypair,
    candidates, and genesis block in the audit ledger.
    """
    db = get_db()
    cursor = db.cursor()
    
    election_key = generate_election_key()
    priv_pem, pub_pem = generate_ed25519_keypair()
    
    cursor.execute(
        """
        INSERT INTO elections (title, description, status, election_key, authority_privkey, authority_pubkey)
        VALUES (?, ?, 'ACTIVE', ?, ?, ?)
        """,
        (title.strip(), description.strip(), key_to_hex(election_key), priv_pem, pub_pem)
    )
    election_id = cursor.lastrowid
    
    # Insert candidates
    for c in candidates:
        cursor.execute(
            """
            INSERT INTO candidates (election_id, name, party, manifesto, avatar_color)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                election_id,
                c.get("name", "").strip(),
                c.get("party", "").strip(),
                c.get("manifesto", "").strip(),
                c.get("avatar_color", "#4f46e5")
            )
        )
    
    # Initialize Genesis Block for this election
    timestamp = datetime.now(timezone.utc).isoformat()
    genesis = create_audit_entry(
        index_num=0,
        timestamp=timestamp,
        prev_hash="0" * 64,
        action="GENESIS_ELECTION_INITIALIZED",
        payload={
            "election_id": election_id,
            "title": title,
            "candidate_count": len(candidates),
            "authority_pubkey": pub_pem[:50] + "..."
        },
        election_id=election_id,
        authority_private_key_pem=priv_pem
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
            genesis["index_num"],
            genesis["timestamp"],
            genesis["prev_hash"],
            genesis["action"],
            genesis["payload_hash"],
            genesis["current_hash"],
            genesis["signature"],
            genesis["details"]
        )
    )
    
    db.commit()
    return election_id


def get_election(election_id: int | None = None) -> dict | None:
    """
    Fetches election metadata and associated candidate list.
    If election_id is None, returns the latest active or most recent election.
    """
    db = get_db()
    cursor = db.cursor()
    
    if election_id:
        cursor.execute("SELECT * FROM elections WHERE id = ?", (election_id,))
    else:
        cursor.execute("SELECT * FROM elections ORDER BY id DESC LIMIT 1")
        
    election = cursor.fetchone()
    if not election:
        return None
    
    election_dict = dict(election)
    
    # Fetch candidates
    cursor.execute("SELECT * FROM candidates WHERE election_id = ? ORDER BY id ASC", (election_dict["id"],))
    election_dict["candidates"] = [dict(c) for c in cursor.fetchall()]
    
    # Total votes count
    cursor.execute("SELECT COUNT(*) as count FROM votes WHERE election_id = ?", (election_dict["id"],))
    election_dict["vote_count"] = cursor.fetchone()["count"]
    
    return election_dict


def get_all_elections() -> list[dict]:
    """Returns list of all elections."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, title, description, status, created_at, closed_at FROM elections ORDER BY id DESC")
    elections = [dict(r) for r in cursor.fetchall()]
    for el in elections:
        cursor.execute("SELECT COUNT(*) as cnt FROM votes WHERE election_id = ?", (el["id"],))
        el["vote_count"] = cursor.fetchone()["cnt"]
    return elections


def set_election_status(election_id: int, new_status: str):
    """Updates election status (ACTIVE, CLOSED, TALLIED) and appends audit log."""
    if new_status not in ("ACTIVE", "CLOSED", "TALLIED"):
        raise ValueError("Invalid election status.")
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM elections WHERE id = ?", (election_id,))
    election = cursor.fetchone()
    if not election:
        raise ValueError("Election not found.")
    
    timestamp = datetime.now(timezone.utc).isoformat()
    cursor.execute("UPDATE elections SET status = ? WHERE id = ?", (new_status, election_id))
    
    # Append state change to audit ledger
    cursor.execute(
        "SELECT current_hash, index_num FROM audit_ledger WHERE election_id = ? ORDER BY index_num DESC LIMIT 1",
        (election_id,)
    )
    last_block = cursor.fetchone()
    prev_hash = last_block["current_hash"] if last_block else "0" * 64
    next_index = (last_block["index_num"] + 1) if last_block else 0
    
    audit_entry = create_audit_entry(
        index_num=next_index,
        timestamp=timestamp,
        prev_hash=prev_hash,
        action=f"ELECTION_STATUS_CHANGED_TO_{new_status}",
        payload={"election_id": election_id, "previous_status": election["status"], "new_status": new_status},
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
