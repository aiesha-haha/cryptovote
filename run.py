"""
SecureVote Root Entry Point.
Run this script to launch the full-stack cryptographic e-voting application.
Usage:
    py run.py
    # or
    python run.py
"""

import os
import sys

# Ensure backend and frontend are in Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.app import app

if __name__ == "__main__":
    print("=" * 65)
    print("  🔒 SecureVote — Криптографиялық электронды дауыс беру жүйесі")
    print("  🔗 Сервер іске қосылуда: http://127.0.0.1:5000")
    print("  🧪 Алгоритмдер: Argon2id, AES-256-GCM, Ed25519, SHA-256")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=True)
