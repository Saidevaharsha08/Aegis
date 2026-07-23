from fastapi import APIRouter, status
from app.config import settings
from app.crypto.session import session_manager
from app.crypto.rotation import key_rotation_manager
from app.crypto.benchmark import run_pqc_benchmark

router = APIRouter()

@router.get("/crypto/status", status_code=status.HTTP_200_OK)
def get_crypto_status():
    """GET /crypto/status endpoint: Reports PQC algorithm status and active session stats."""
    details = session_manager.pqc_engine.get_algorithm_details()
    details.update({
        "active_sessions": session_manager.get_active_sessions_count(),
        "last_rotation_time": key_rotation_manager.last_rotation_time,
        "last_rotation_reason": key_rotation_manager.last_rotation_reason,
        "total_rotations": key_rotation_manager.total_rotations,
        "public_key_fingerprint": session_manager.public_key.hex()[:16]
    })
    return details

@router.get("/crypto/rotate", status_code=status.HTTP_200_OK)
def trigger_manual_key_rotation():
    """GET /crypto/rotate endpoint: Triggers manual ML-KEM key rotation."""
    return key_rotation_manager.rotate_keys(reason="MANUAL_ADMIN_ROTATION")

@router.get("/crypto/benchmark", status_code=status.HTTP_200_OK)
def get_pqc_benchmark():
    """GET /crypto/benchmark endpoint: Returns performance metrics across encryption modes."""
    return run_pqc_benchmark(n_iterations=50)
