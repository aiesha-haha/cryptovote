"""
Authentication and Voter Authorization module using Argon2id.
"""

import sqlite3
import secrets
from backend.database.db import get_db
from backend.crypto.passwords import hash_password, verify_password


class AuthError(Exception):
    pass


def register_user(username: str, password: str, full_name: str, role: str = "voter") -> int:
    """
    Registers a new user with Argon2id hashed password and a unique voter salt.
    """
    username = username.strip().lower()
    full_name = full_name.strip()
    
    if not username or len(username) < 3:
        raise AuthError("Имя пользователя должно содержать не менее 3 символов.")
    if not password or len(password) < 6:
        raise AuthError("Пароль должен содержать не менее 6 символов.")
    if role not in ("admin", "voter", "auditor"):
        raise AuthError("Указана недопустимая роль.")
    
    pass_hash = hash_password(password)
    voter_salt = secrets.token_hex(16)
    
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, full_name, role, voter_salt) VALUES (?, ?, ?, ?, ?)",
            (username, pass_hash, full_name, role, voter_salt)
        )
        db.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        raise AuthError(f"Пользователь с именем '{username}' уже зарегистрирован в системе.")


def authenticate_user(username: str, password: str) -> dict:
    """
    Validates user credentials using Argon2id.
    """
    username = username.strip().lower()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        raise AuthError("Неверное имя пользователя или пароль.")
    
    if not verify_password(user["password_hash"], password):
        raise AuthError("Неверное имя пользователя или пароль.")
    
    return dict(user)


def get_user_by_id(user_id: int) -> dict | None:
    """Retrieves user dictionary by ID."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, full_name, role, voter_salt, created_at FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return dict(user) if user else None


def get_all_users() -> list[dict]:
    """Retrieves all registered users without password hashes."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, full_name, role, created_at FROM users ORDER BY id ASC")
    return [dict(r) for r in cursor.fetchall()]
