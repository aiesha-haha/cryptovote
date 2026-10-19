-- =======================================================
-- SecureVote Database Schema
-- Multi-role cryptographic e-voting prototype
-- =======================================================

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'voter' CHECK(role IN ('admin', 'voter', 'auditor')),
    voter_salt TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS elections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('DRAFT', 'ACTIVE', 'CLOSED', 'TALLIED')),
    election_key TEXT NOT NULL,
    authority_privkey TEXT NOT NULL,
    authority_pubkey TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    party TEXT,
    manifesto TEXT,
    avatar_color TEXT DEFAULT '#4f46e5',
    FOREIGN KEY(election_id) REFERENCES elections(id) ON DELETE CASCADE
);

-- Anonymity Barrier: Records that a user voted, but has NO link to the ballot contents or vote row!
CREATE TABLE IF NOT EXISTS voter_participation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(election_id, user_id),
    FOREIGN KEY(election_id) REFERENCES elections(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Encrypted Ballot Box: Completely decoupled from voter identity
CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL,
    nullifier TEXT UNIQUE NOT NULL,
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    auth_tag TEXT NOT NULL,
    receipt_hash TEXT UNIQUE NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(election_id) REFERENCES elections(id) ON DELETE CASCADE
);

-- Tamper-Evident SHA-256 & Ed25519 Audit Chain
CREATE TABLE IF NOT EXISTS audit_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER NOT NULL,
    index_num INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    current_hash TEXT UNIQUE NOT NULL,
    signature TEXT NOT NULL,
    details TEXT,
    FOREIGN KEY(election_id) REFERENCES elections(id) ON DELETE CASCADE
);

-- Final Cryptographic Tally Record with Authority Signature
CREATE TABLE IF NOT EXISTS tallies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id INTEGER UNIQUE NOT NULL,
    total_votes INTEGER NOT NULL,
    valid_votes INTEGER NOT NULL,
    invalid_votes INTEGER NOT NULL,
    results_json TEXT NOT NULL,
    tally_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    tallied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(election_id) REFERENCES elections(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_audit_election ON audit_ledger(election_id, index_num);
CREATE INDEX IF NOT EXISTS idx_votes_receipt ON votes(receipt_hash);
