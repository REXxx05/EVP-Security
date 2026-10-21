from utils.crypto import hash_ballot, pseudonymise_voter, hash_log_entry

# Tests for SHA-256 hashing and HMAC pseudonymisation
# SR-04: Verifies ballot hashing works correctly
# SR-18: Verifies voter PII is properly pseudonymised

def test_hash_ballot_returns_string():
    # hash_ballot should return a string
    ballot = {'1': 1, '2': 2, '3': 3}
    result = hash_ballot(ballot)
    assert isinstance(result, str)

def test_hash_ballot_is_consistent():
    # The same ballot data should always produce the same hash
    ballot = {'1': 1, '2': 2}
    hash1 = hash_ballot(ballot)
    hash2 = hash_ballot(ballot)
    assert hash1 == hash2

def test_hash_ballot_changes_when_data_changes():
    # Different ballot data should produce a different hash
    ballot1 = {'1': 1, '2': 2}
    ballot2 = {'1': 2, '2': 1}
    assert hash_ballot(ballot1) != hash_ballot(ballot2)

def test_hash_ballot_length():
    # SHA-256 always produces a 64 character hex string
    ballot = {'1': 1}
    result = hash_ballot(ballot)
    assert len(result) == 64

def test_pseudonymise_voter_hides_real_id():
    # The pseudonym should not contain the real voter id
    voter_id = 'VOTER123'
    result = pseudonymise_voter(voter_id)
    assert voter_id not in result

def test_pseudonymise_voter_is_consistent():
    # The same voter id should always produce the same pseudonym
    voter_id = 'VOTER123'
    result1 = pseudonymise_voter(voter_id)
    result2 = pseudonymise_voter(voter_id)
    assert result1 == result2

def test_different_voters_get_different_pseudonyms():
    # Different voter ids should produce different pseudonyms
    result1 = pseudonymise_voter('VOTER001')
    result2 = pseudonymise_voter('VOTER002')
    assert result1 != result2

def test_hash_log_entry_returns_string():
    # Log entry hashing should return a string
    entry = 'user:admin action:login resource:system'
    result = hash_log_entry(entry)
    assert isinstance(result, str)
    assert len(result) == 64