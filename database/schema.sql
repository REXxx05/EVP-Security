-- Database schema for the Electronic Voting Platform

-- Stores all registered voters
CREATE TABLE IF NOT EXISTS voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name_encrypted TEXT NOT NULL,
    email_encrypted TEXT NOT NULL,
    division TEXT NOT NULL,
    has_voted INTEGER DEFAULT 0,
    is_enrolled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Stores candidates for each division
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    party TEXT NOT NULL,
    division TEXT NOT NULL,
    ballot_position INTEGER NOT NULL
);

-- Stores submitted ballots
-- Voter id is not stored here to protect anonymity (SR-16)
CREATE TABLE IF NOT EXISTS ballots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_pseudonym TEXT NOT NULL,
    preferences_encrypted TEXT NOT NULL,
    division TEXT NOT NULL,
    receipt_token TEXT UNIQUE NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Stores ballot hashes separately so we can detect tampering (SR-04)
CREATE TABLE IF NOT EXISTS ballot_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_token TEXT UNIQUE NOT NULL,
    sha256_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Stores admin accounts
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    totp_secret TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Stores audit logs with hash chaining to detect tampering (SR-12, SR-13)
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_pseudonym TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);