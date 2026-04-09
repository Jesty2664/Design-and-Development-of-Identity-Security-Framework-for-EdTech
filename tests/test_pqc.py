import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.lattice_crypto import generate_keypair, sign_audit_entry, verify_pqc_signature

def test_pqc_keypair_generation():
    kp = generate_keypair()
    assert "public" in kp
    assert "private" in kp
    assert len(kp["private"]) == 64
    
    seed, t = kp["public"]
    assert len(seed) == 32
    assert len(t) == 64

def test_pqc_signature_and_verification():
    kp = generate_keypair()
    entry = "USER_LOGIN: user@example.com at 2026-04-15"
    
    signature = sign_audit_entry(entry, kp["private"])
    assert len(signature) == 64
    
    # Verify (Mock logic)
    is_valid = verify_pqc_signature(entry, signature, kp["public"])
    assert is_valid is True

def test_pqc_signature_uniqueness():
    kp = generate_keypair()
    entry1 = "Entry 1"
    entry2 = "Entry 2"
    
    sig1 = sign_audit_entry(entry1, kp["private"])
    sig2 = sign_audit_entry(entry2, kp["private"])
    
    # Even if they are deterministic in this PoC, 
    # different messages should yield different sigs
    assert sig1 != sig2
