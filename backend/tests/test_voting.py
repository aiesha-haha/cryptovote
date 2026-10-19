"""
Automated tests for voting business logic:
- 1-voter-1-vote enforcement
- Double-voting prevention
- Closed election vote rejection
- End-to-end tallying and signature verification
"""

import os
import tempfile
import pytest
from backend.database.db import init_db, seed_initial_data, get_db
from backend.voting.ballot import cast_ballot, has_user_voted, DoubleVotingError, ElectionClosedError
from backend.voting.election import get_election, set_election_status
from backend.voting.tally import compute_election_tally, get_tally


@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    seed_initial_data(path)
    
    # Override flask g / default path for test
    from flask import Flask
    app = Flask(__name__)
    with app.app_context():
        conn = get_db(path)
        try:
            yield path, conn
        finally:
            conn.close()
            
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def test_first_vote_succeeds_and_prevents_double_voting(test_db):
    path, conn = test_db
    election = get_election(1)
    assert election is not None
    assert election["status"] == "ACTIVE"
    candidates = election["candidates"]
    candidate_id = candidates[0]["id"]
    
    # Voter 1 casts vote
    voter1_id = 3  # Ali Khan (voter1)
    assert has_user_voted(voter1_id, 1) is False
    
    receipt = cast_ballot(user_id=voter1_id, election_id=1, candidate_id=candidate_id)
    assert receipt["success"] is True
    assert "receipt_hash" in receipt
    assert "receipt_signature" in receipt
    assert has_user_voted(voter1_id, 1) is True
    
    # Voter 1 tries to cast a second vote: MUST FAIL
    with pytest.raises(DoubleVotingError):
        cast_ballot(user_id=voter1_id, election_id=1, candidate_id=candidate_id)


def test_cannot_vote_in_closed_election(test_db):
    path, conn = test_db
    # Close election 1
    set_election_status(1, "CLOSED")
    
    election = get_election(1)
    assert election["status"] == "CLOSED"
    
    candidate_id = election["candidates"][0]["id"]
    voter2_id = 4  # Dinara (voter2)
    
    with pytest.raises(ElectionClosedError):
        cast_ballot(user_id=voter2_id, election_id=1, candidate_id=candidate_id)


def test_full_tally_and_verification(test_db):
    path, conn = test_db
    election = get_election(1)
    c1_id = election["candidates"][0]["id"]
    c2_id = election["candidates"][1]["id"]
    
    # Cast 2 votes: voter1 for c1, voter2 for c2
    cast_ballot(user_id=3, election_id=1, candidate_id=c1_id)
    cast_ballot(user_id=4, election_id=1, candidate_id=c2_id)
    
    # Close and tally
    set_election_status(1, "CLOSED")
    tally = compute_election_tally(1)
    
    assert tally["total_votes"] == 2
    assert tally["valid_votes"] == 2
    assert tally["invalid_votes"] == 0
    assert len(tally["signature"]) == 128
    
    # Check candidates count
    counts = {c["id"]: c["votes"] for c in tally["candidates"]}
    assert counts[c1_id] == 1
    assert counts[c2_id] == 1
    
    # Verify saved tally proof
    saved = get_tally(1)
    assert saved is not None
    assert saved["signature_valid"] is True
