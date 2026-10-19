"""
Configuration settings for SecureVote application.
"""

import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

FRONTEND_TEMPLATES = os.path.join(PROJECT_ROOT, "frontend", "templates")
FRONTEND_STATIC = os.path.join(PROJECT_ROOT, "frontend", "static")
DATABASE_FILE = os.path.join(BASE_DIR, "database", "securevote.db")


class Config:
    SECRET_KEY = os.environ.get("SECUREVOTE_SECRET", secrets.token_hex(32))
    DATABASE = DATABASE_FILE
    TEMPLATES_FOLDER = FRONTEND_TEMPLATES
    STATIC_FOLDER = FRONTEND_STATIC
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    JSON_SORT_KEYS = False
