import secrets
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from middleware.authenticate import token_required
from utils.crypto import encrypt_data, hash_ballot, pseudonymise_voter

# Ballot routes handle everything related to casting and verifying votes
ballot_bp = Blueprint('ballot', __name__)


def validate_preferences(preferences, num_candidates):
    # Checks that the voter has filled in their preferences correctly
    # SR-04: Ballot must pass validation before we accept and hash it

    # Must have a preference for every candidate
    if len(preferences) != num_candidates:
        return False, f'You must number all {num_candidates} candidates'

    # All values must be whole numbers
    for key, value in preferences.items():
        if not isinstance(value, int):
            return False, 'Preferences must be whole numbers only'

    # Numbers must go from 1 to the total number of candidates with no gaps or duplicates
    values = list(preferences.values())
    expected = list(range(1, num_candidates + 1))

    if sorted(values) != expected:
        return False, f'Preferences must be numbered 1 to {num_candidates} with no repeats or gaps'

    return True, 'Valid'


@ballot_bp.route('/cast', methods=['POST'])
@token_required
def cast_ballot():
    # Lets an eligible voter submit their ballot
    # SR-04: Validates and hashes the ballot
    # SR-07: Checks voter has not already voted
    # SR-16: Separates voter identity from their vote
    # SR-15: Issues a signed receipt to the voter

    from app import db
    from models.voter import Voter
    from models.ballot import Ballot, BallotHash
    from models.candidate import Candidate

    # Get the logged in voter from the session token
    user = request.current_user
    voter_id = user.get('voter_id')

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No ballot data was provided'}), 400

    # Look up the voter in the database
    voter = Voter.query.filter_by(voter_id=voter_id).first()
    if not voter:
        return jsonify({'error': 'Voter not found'}), 404

    # SR-07: Check voter has not already voted
    if voter.has_voted:
        return jsonify({'error': 'You have already submitted a ballot'}), 403

    # SR-07: Check voter is still enrolled
    if not voter.is_enrolled:
        return jsonify({'error': 'You are not enrolled to vote'}), 403

    # Get the preferences from the request
    preferences = data.get('preferences', {})

    # Count how many candidates are in this voter's division
    num_candidates = Candidate.query.filter_by(division=voter.division).count()

    # SR-04: Validate the ballot before accepting it
    is_valid, message = validate_preferences(preferences, num_candidates)
    if not is_valid:
        return jsonify({'error': message}), 400

    # SR-16: Create a pseudonym for the voter so their identity is not stored with their ballot
    voter_pseudonym = pseudonymise_voter(voter_id)

    # SR-02: Encrypt the ballot preferences before storing in database
    preferences_encrypted = encrypt_data(json.dumps(preferences))

    # Generate a unique receipt token for this ballot (SR-15)
    receipt_token = secrets.token_urlsafe(32)

    # SR-04: Hash the ballot data so we can detect tampering later
    ballot_data = {
        'voter_pseudonym': voter_pseudonym,
        'preferences': preferences,
        'division': voter.division,
        'receipt_token': receipt_token
    }
    ballot_hash = hash_ballot(ballot_data)

    # Save the ballot to the database
    new_ballot = Ballot(
        voter_pseudonym=voter_pseudonym,
        preferences_encrypted=preferences_encrypted,
        division=voter.division,
        receipt_token=receipt_token
    )
    db.session.add(new_ballot)

    # SR-04: Save the hash separately so we can verify integrity later
    new_hash = BallotHash(
        receipt_token=receipt_token,
        sha256_hash=ballot_hash
    )
    db.session.add(new_hash)

    # Mark voter as having voted to prevent double voting (SR-07)
    voter.has_voted = True
    db.session.commit()

    # SR-15: Return receipt to voter as proof their ballot was received
    return jsonify({
        'message': 'Your ballot has been submitted successfully',
        'receipt_token': receipt_token,
        'ballot_hash': ballot_hash,
        'submitted_at': datetime.now(timezone.utc).isoformat()
    }), 201


@ballot_bp.route('/verify/<receipt_token>', methods=['GET'])
def verify_ballot(receipt_token):
    # Lets a voter check that their ballot was recorded (SR-15)

    from models.ballot import BallotHash

    ballot_hash = BallotHash.query.filter_by(receipt_token=receipt_token).first()

    if not ballot_hash:
        return jsonify({'error': 'No ballot found with that receipt token'}), 404

    return jsonify({
        'message': 'Your ballot was found in the system',
        'receipt_token': receipt_token,
        'ballot_hash': ballot_hash.sha256_hash,
        'recorded_at': ballot_hash.created_at.isoformat()
    }), 200


@ballot_bp.route('/tally/<division>', methods=['GET'])
@token_required
def get_tally(division):
    # Returns the vote tally for a division (SR-06)
    # Also verifies that ballot count matches hash count

    from app import db
    from models.ballot import Ballot, BallotHash

    # Count total ballots submitted
    total_ballots = Ballot.query.filter_by(division=division).count()

    # Count total hashes stored
    total_hashes = BallotHash.query.count()

    # SR-06: Check if counts match
    if total_ballots != total_hashes:
        return jsonify({
            'warning': 'Ballot count does not match hash count. Please alert AEC auditors.',
            'total_ballots': total_ballots,
            'total_hashes': total_hashes
        }), 200

    return jsonify({
        'division': division,
        'total_votes': total_ballots,
        'integrity_check': 'passed'
    }), 200