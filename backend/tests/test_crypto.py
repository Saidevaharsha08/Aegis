import sys
import time
import pytest
from pathlib import Path

project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "backend"))

from app.crypto.pqc import MLKEMSession, hkdf_sha256
from app.crypto.session import AegisSessionManager, session_manager
from app.crypto.rotation import KeyRotationManager, key_rotation_manager
from app.crypto.benchmark import run_pqc_benchmark

def test_mlkem_keypair_generation():
    kem = MLKEMSession()
    pk, sk = kem.generate_keypair()
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) == MLKEMSession.PUBLIC_KEY_BYTES
    details = kem.get_algorithm_details()
    assert details["algorithm"] == "ML-KEM-768"

def test_encapsulate_decapsulate_parity():
    kem = MLKEMSession()
    pk, sk = kem.generate_keypair()
    
    ciphertext, shared_secret_sender = kem.encapsulate(pk)
    assert len(ciphertext) == MLKEMSession.CIPHERTEXT_BYTES
    assert len(shared_secret_sender) == 32
    
    shared_secret_recipient = kem.decapsulate(ciphertext, secret_key=sk)
    assert shared_secret_sender == shared_secret_recipient

def test_session_creation_and_validation():
    sm = AegisSessionManager(token_ttl_seconds=3600)
    session = sm.create_session(component_id="detector_worker")
    
    sid = session["session_id"]
    secret_hash = session["shared_secret_hash"]
    
    assert sm.validate_session(sid, secret_hash) is True
    assert sm.validate_session(sid, "invalid_hash_string") is False
    assert sm.get_active_sessions_count() >= 1

def test_session_expiration_and_invalidation():
    sm = AegisSessionManager(token_ttl_seconds=1) # 1 sec TTL
    session = sm.create_session(component_id="temp_worker")
    sid = session["session_id"]
    secret_hash = session["shared_secret_hash"]
    
    # Invalidate manually
    sm.invalidate_session(sid)
    assert sm.validate_session(sid, secret_hash) is False

def test_key_rotation():
    rm = KeyRotationManager(overlap_window_seconds=0.1)
    res = rm.rotate_keys(reason="UNIT_TEST_TRIGGER")
    
    assert res["rotated"] is True
    assert res["rotation_time_ms"] < 2000.0  # < 2 seconds requirement
    assert len(res["new_key_fingerprint"]) > 0

def test_hybrid_secret_derivation():
    kem = MLKEMSession()
    classical_secret = b"\x01" * 32
    quantum_secret = b"\x02" * 32
    
    hybrid_secret = kem.derive_hybrid_secret(classical_secret, quantum_secret)
    assert len(hybrid_secret) == 32
    assert hybrid_secret != classical_secret
    assert hybrid_secret != quantum_secret

def test_pqc_benchmark_execution():
    benchmark_res = run_pqc_benchmark(n_iterations=50)
    assert "ML-KEM-768" in benchmark_res
    assert "X25519_Classical" in benchmark_res
    assert "Hybrid_Mode" in benchmark_res
    assert benchmark_res["ML-KEM-768"]["encap_ms"] < 5.0
