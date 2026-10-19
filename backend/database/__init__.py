"""Database module for SecureVote."""
from backend.database.db import get_db, init_db, seed_initial_data, DB_PATH

__all__ = ["get_db", "init_db", "seed_initial_data", "DB_PATH"]
