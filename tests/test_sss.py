import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.sss import secret_to_shards, shards_to_secret

def test_sss_reconstruction_success():
    secret = "TopSecretEdTech123"
    # Split into 3 shards, need 2 to reconstruct
    shards = secret_to_shards(secret, min_shares=2, total_shares=3)
    assert len(shards) == 3
    
    # Try with all 3
    reconstructed = shards_to_secret(shards)
    assert reconstructed == secret
    
    # Try with exactly 2
    reconstructed_min = shards_to_secret(shards[:2])
    assert reconstructed_min == secret

def test_sss_reconstruction_failure():
    secret = "TopSecretEdTech123"
    shards = secret_to_shards(secret, min_shares=3, total_shares=5)
    
    # Only providing 2 shards (insufficient)
    # This may result in a UnicodeDecodeError or a wrong string.
    try:
        wrong_reconstruction = shards_to_secret(shards[:2])
        assert wrong_reconstruction != secret
    except UnicodeDecodeError:
        # This is expected behavior for Shamir's when bits don't align to UTF-8
        pass

def test_sss_invalid_params():
    secret = "test"
    with pytest.raises(ValueError):
        secret_to_shards(secret, min_shares=5, total_shares=3)
