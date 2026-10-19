"""
Database management module for SQLite.
Provides connections, initialization, and initial cryptographic seeding.
"""

import sqlite3
import os
import secrets
from flask import g
from backend.crypto.passwords import hash_password
from backend.crypto.encryption import generate_election_key, key_to_hex
from backend.crypto.signatures import generate_ed25519_keypair
from backend.crypto.audit import create_audit_entry

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "securevote.db")
SCHEMA_PATH = os.path.join(DB_DIR, "schema.sql")


def get_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Gets a SQLite connection bound to the current Flask context or a new one."""
    if hasattr(g, "db") and g.db is not None:
        return g.db
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    
    # Cache on flask g if inside request context
    try:
        g.db = conn
    except RuntimeError:
        pass
        
    return conn


def close_db(e=None):
    """Closes the current database connection if opened."""
    db = getattr(g, "db", None)
    if db is not None:
        db.close()
        g.db = None


def init_db(db_path: str = DB_PATH):
    """Initializes schema on the database."""
    conn = sqlite3.connect(db_path)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def seed_initial_data(db_path: str = DB_PATH):
    """Seeds the database with test users and a demo election if empty."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check if users already exist
    cursor.execute("SELECT COUNT(*) as count FROM users")
    if cursor.fetchone()["count"] > 0:
        conn.close()
        return
    
    print("[DB] Seeding initial cryptographic users and sample election...")
    
    # 1. Create Default Users (with Argon2id hashed passwords)
    default_users = [
        ("admin", "Admin@Secure2026!", "Системный Администратор (Admin)", "admin"),
        ("auditor", "Auditor@Audit2026!", "Независимый Аудитор (Auditor)", "auditor"),
        ("voter1", "Voter1@Pass!", "Алихан Сеитов (Избиратель 1)", "voter"),
        ("voter2", "Voter2@Pass!", "Динара Нурланова (Избиратель 2)", "voter"),
        ("voter3", "Voter3@Pass!", "Бауыржан Кенжебаев (Избиратель 3)", "voter"),
    ]
    
    for username, password, full_name, role in default_users:
        pass_hash = hash_password(password)
        voter_salt = secrets.token_hex(16)
        cursor.execute(
            "INSERT INTO users (username, password_hash, full_name, role, voter_salt) VALUES (?, ?, ?, ?, ?)",
            (username, pass_hash, full_name, role, voter_salt)
        )
    
    # 2. Create Sample Active Election
    election_key = generate_election_key()
    priv_pem, pub_pem = generate_ed25519_keypair()
    
    cursor.execute(
        """
        INSERT INTO elections (title, description, status, election_key, authority_privkey, authority_pubkey)
        VALUES (?, ?, 'ACTIVE', ?, ?, ?)
        """,
        (
            "Выборы Председателя Альянса Кибербезопасности 2026",
            "Пилотное электронное голосование, защищенное криптографическими протоколами AES-256-GCM, Ed25519, SHA-256 и Argon2id.",
            key_to_hex(election_key),
            priv_pem,
            pub_pem
        )
    )
    election_id = cursor.lastrowid
    
    # 3. Add Candidates
    candidates = [
        (election_id, "Д-р Аскар Сатпаев", "Лаборатория квантовой безопасности", "Внедрение постквантовой криптографии и совершенствование национальных стандартов шифрования.", "#2563eb"),
        (election_id, "Айсулу Берикова", "Zero-Trust & Privacy", "Полная гарантия анонимности данных избирателей и безопасность в недоверенных средах.", "#059669"),
        (election_id, "Ержан Темирханов", "Открытый аудит и блокчейн", "Перевод всех электоральных процессов на неизменяемые криптографические цепочки аудита.", "#d97706")
    ]
    for c in candidates:
        cursor.execute(
            "INSERT INTO candidates (election_id, name, party, manifesto, avatar_color) VALUES (?, ?, ?, ?, ?)",
            c
        )
    
    # 4. Create Genesis Audit Block
    genesis_block = create_audit_entry(
        index_num=0,
        timestamp="2026-10-19T09:00:00Z",
        prev_hash="0" * 64,
        action="GENESIS_ELECTION_INITIALIZED",
        payload={
            "election_id": election_id,
            "title": "Қазақстан Киберқауіпсіздік Альянсы 2026: Төраға сайлауы",
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
            genesis_block["index_num"],
            genesis_block["timestamp"],
            genesis_block["prev_hash"],
            genesis_block["action"],
            genesis_block["payload_hash"],
            genesis_block["current_hash"],
            genesis_block["signature"],
            genesis_block["details"]
        )
    )
    
    conn.commit()
    conn.close()
    print("[DB] Initial database successfully initialized and seeded.")
