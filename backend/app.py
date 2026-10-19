"""
SecureVote Application Server (Flask).
Binds cryptographic backend services to REST APIs and frontend templates.
"""

from functools import wraps
from datetime import datetime, timezone
import json
import sqlite3
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, g
)

from backend.config import Config
from backend.database.db import get_db, close_db, init_db, seed_initial_data
from backend.crypto.passwords import hash_password, verify_password
from backend.crypto.audit import verify_audit_chain, sha256_hash
from backend.crypto.signatures import verify_signature
from backend.voting.authentication import authenticate_user, register_user, get_user_by_id, get_all_users, AuthError
from backend.voting.election import get_election, get_all_elections, set_election_status, create_election
from backend.voting.ballot import cast_ballot, has_user_voted, lookup_receipt, BallotError, DoubleVotingError, ElectionClosedError
from backend.voting.tally import compute_election_tally, get_tally

app = Flask(
    __name__,
    template_folder=Config.TEMPLATES_FOLDER,
    static_folder=Config.STATIC_FOLDER
)
app.config.from_object(Config)
app.teardown_appcontext(close_db)


# =======================================================
# Authentication Decorators & Helpers
# =======================================================

def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)


@app.context_processor
def inject_globals():
    """Injects user and current election into all templates."""
    user = get_current_user()
    active_election = get_election()
    return {
        "current_user": user,
        "active_election": active_election,
        "now": datetime.now(timezone.utc)
    }


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Необходима авторизация в системе.", "warning")
            return redirect(url_for("login_view", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user or user["role"] not in roles:
                flash("Недостаточно прав для доступа к этому разделу.", "danger")
                return redirect(url_for("dashboard_view"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# =======================================================
# Page Views
# =======================================================

@app.route("/")
def index_view():
    election = get_election()
    tally = get_tally(election["id"]) if election and election["status"] == "TALLIED" else None
    return render_template("index.html", election=election, tally=tally)


@app.route("/login", methods=["GET", "POST"])
def login_view():
    if session.get("user_id"):
        return redirect(url_for("dashboard_view"))
        
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        try:
            user = authenticate_user(username, password)
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Добро пожаловать, {user['full_name']}! (Роль: {user['role']})", "success")
            
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard_view"))
        except AuthError as e:
            flash(str(e), "danger")
            
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register_view():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "voter")
        
        if role not in ("voter", "auditor"):
            role = "voter"
            
        try:
            register_user(username, password, full_name, role)
            flash("Регистрация успешно завершена! Теперь вы можете войти.", "success")
            return redirect(url_for("login_view"))
        except AuthError as e:
            flash(str(e), "danger")
            
    return render_template("register.html")


@app.route("/logout")
def logout_view():
    session.clear()
    flash("Вы успешно вышли из системы.", "info")
    return redirect(url_for("index_view"))


@app.route("/dashboard")
@login_required
def dashboard_view():
    user = get_current_user()
    election = get_election()
    has_voted = False
    user_receipt = None
    
    if election and user:
        has_voted = has_user_voted(user["id"], election["id"])
    
    users_list = []
    if user["role"] == "admin":
        users_list = get_all_users()
        
    tally = None
    if election and election["status"] == "TALLIED":
        tally = get_tally(election["id"])
        
    all_elections = get_all_elections()
    
    return render_template(
        "dashboard.html",
        user=user,
        election=election,
        has_voted=has_voted,
        users_list=users_list,
        tally=tally,
        all_elections=all_elections
    )


@app.route("/vote", methods=["GET", "POST"])
@login_required
def vote_view():
    user = get_current_user()
    election = get_election()
    
    if not election:
        flash("В данный момент нет активных выборов.", "warning")
        return redirect(url_for("dashboard_view"))
        
    has_voted = has_user_voted(user["id"], election["id"])
    if has_voted:
        flash("Вы уже проголосовали в этих выборах. Принцип «1 избиратель — 1 голос» строго соблюден!", "info")
        return redirect(url_for("dashboard_view"))
        
    if election["status"] != "ACTIVE":
        flash("Выборы в данный момент не принимают голоса (статус: " + election["status"] + ").", "warning")
        return redirect(url_for("dashboard_view"))
        
    if request.method == "POST":
        candidate_id = request.form.get("candidate_id")
        if not candidate_id:
            flash("Пожалуйста, выберите кандидата.", "danger")
            return redirect(url_for("vote_view"))
            
        try:
            receipt = cast_ballot(user["id"], election["id"], int(candidate_id))
            flash("Ваш голос успешно зашифрован AES-256-GCM и внесен в электронную урну!", "success")
            return render_template("vote.html", election=election, receipt=receipt, voted_now=True)
        except (BallotError, DoubleVotingError, ElectionClosedError) as e:
            flash(str(e), "danger")
            return redirect(url_for("vote_view"))
            
    return render_template("vote.html", election=election, receipt=None, voted_now=False)


@app.route("/results")
def results_view():
    election = get_election()
    if not election:
        return render_template("results.html", election=None, tally=None)
        
    tally = get_tally(election["id"])
    return render_template("results.html", election=election, tally=tally)


@app.route("/audit")
def audit_view():
    election = get_election()
    ledger_entries = []
    verification_res = None
    
    if election:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "SELECT * FROM audit_ledger WHERE election_id = ? ORDER BY index_num ASC",
            (election["id"],)
        )
        ledger_entries = [dict(r) for r in cursor.fetchall()]
        verification_res = verify_audit_chain(ledger_entries, election["authority_pubkey"])
        
    return render_template(
        "audit.html",
        election=election,
        ledger=ledger_entries,
        verification=verification_res
    )


# =======================================================
# REST APIs for Interactivity & Live Verification
# =======================================================

@app.route("/api/audit/verify", methods=["GET"])
def api_verify_audit():
    """Runs live cryptographic verification on the SHA-256 and Ed25519 audit chain."""
    election = get_election()
    if not election:
        return jsonify({"valid": False, "error": "Активные выборы не найдены."})
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT * FROM audit_ledger WHERE election_id = ? ORDER BY index_num ASC",
        (election["id"],)
    )
    chain = [dict(r) for r in cursor.fetchall()]
    res = verify_audit_chain(chain, election["authority_pubkey"])
    return jsonify(res)


@app.route("/api/audit/tamper_test", methods=["POST"])
@login_required
def api_tamper_test():
    """
    Demonstrates tamper-evidence by altering a block payload in the database.
    This enables the instructor or student to prove that the hash chain breaks instantly.
    """
    data = request.get_json() or {}
    block_index = int(data.get("block_index", 0))
    
    election = get_election()
    if not election:
        return jsonify({"success": False, "error": "Выборы не найдены."})
        
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT * FROM audit_ledger WHERE election_id = ? AND index_num = ?",
        (election["id"], block_index)
    )
    block = cursor.fetchone()
    if not block:
        return jsonify({"success": False, "error": f"Блок #{block_index} не найден."})
        
    # Inject deliberate alteration
    tampered_details = block["details"] + " [ДАННЫЕ_БЫЛИ_ПОДДЕЛАНЫ_TAMPERED]"
    cursor.execute(
        "UPDATE audit_ledger SET details = ? WHERE id = ?",
        (tampered_details, block["id"])
    )
    db.commit()
    
    return jsonify({
        "success": True,
        "message": f"Блок #{block_index} был намеренно модифицирован! Проверьте целостность цепи в панели аудита."
    })


@app.route("/api/audit/restore", methods=["POST"])
@login_required
def api_restore_audit():
    """Recomputes and restores canonical hashes in the database."""
    election = get_election()
    if not election:
        return jsonify({"success": False, "error": "Выборы не найдены."})
        
    # Re-initialize clean genesis and state if requested
    init_db()
    seed_initial_data()
    return jsonify({"success": True, "message": "База данных и цепочка аудита успешно восстановлены в эталонное состояние."})


@app.route("/api/receipt/<receipt_hash>", methods=["GET"])
def api_lookup_receipt(receipt_hash):
    """Public API for receipt verification on bulletin board."""
    receipt = lookup_receipt(receipt_hash)
    if not receipt:
        return jsonify({"found": False, "error": "Указанный хэш квитанции не найден в реестре аудита."}), 404
    return jsonify({"found": True, "receipt": receipt})


@app.route("/api/admin/election/status", methods=["POST"])
@login_required
@roles_required("admin")
def api_update_election_status():
    data = request.get_json() or {}
    election_id = int(data.get("election_id", 0))
    status = data.get("status")
    
    try:
        set_election_status(election_id, status)
        return jsonify({"success": True, "status": status})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/admin/election/tally", methods=["POST"])
@login_required
@roles_required("admin", "auditor")
def api_trigger_tally():
    data = request.get_json() or {}
    election_id = int(data.get("election_id", 0))
    
    try:
        tally = compute_election_tally(election_id)
        return jsonify({"success": True, "tally": tally})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/admin/election/create", methods=["POST"])
@login_required
@roles_required("admin")
def api_create_election():
    data = request.get_json() or {}
    title = data.get("title", "").strip()
    description = data.get("description", "").strip()
    candidates = data.get("candidates", [])
    
    if not title or len(candidates) < 2:
        return jsonify({"success": False, "error": "Необходимо указать название и как минимум 2 кандидатов."}), 400
        
    try:
        new_id = create_election(title, description, candidates)
        return jsonify({"success": True, "election_id": new_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# =======================================================
# Initialize DB on Startup
# =======================================================

with app.app_context():
    init_db()
    seed_initial_data()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
