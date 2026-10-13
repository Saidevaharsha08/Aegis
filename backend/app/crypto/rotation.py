import time
import threading
from typing import Dict, Any
from app.crypto.pqc import MLKEMSession
from app.crypto.session import session_manager, AegisSessionManager

class KeyRotationManager:
    """
    Automated Key Rotation Engine for Aegis.
    Supports emergency key rotation triggered by threat events or 24h periodic timer.
    Enforces a 30-second overlap window before invalidating legacy key sessions.
    """
    
    def __init__(self, overlap_window_seconds: float = 30.0):
        self.overlap_window_seconds = overlap_window_seconds
        self.last_rotation_time: float = time.time()
        self.last_rotation_reason: str = "SYSTEM_INITIALIZATION"
        self.total_rotations: int = 0

    def rotate_keys(self, reason: str = "THREAT_DETECTION_TRIGGER") -> Dict[str, Any]:
        """
        Executes ML-KEM key rotation.
        Generates new keypair, updates session manager, and schedules legacy token invalidation.
        Returns rotation performance stats (time-to-rotation < 2 seconds).
        """
        t0 = time.perf_counter()
        
        # 1. Instantiate new ML-KEM session engine & generate new keypair
        new_engine = MLKEMSession()
        new_pk, new_sk = new_engine.generate_keypair()
        
        # 2. Update active public key on session manager
        old_pk_fingerprint = session_manager.public_key.hex()[:16]
        session_manager.pqc_engine = new_engine
        session_manager.public_key = new_pk
        session_manager._secret_key = new_sk
        
        # 3. Schedule overlap window invalidation of old sessions in background thread
        def deferred_invalidation():
            time.sleep(self.overlap_window_seconds)
            session_manager.invalidate_all_sessions()
            
        t_thread = threading.Thread(target=deferred_invalidation, daemon=True)
        t_thread.start()
        
        t1 = time.perf_counter()
        rotation_time_ms = (t1 - t0) * 1000.0
        
        self.last_rotation_time = time.time()
        self.last_rotation_reason = reason
        self.total_rotations += 1
        
        result = {
            "rotated": True,
            "reason": reason,
            "rotation_time_ms": round(rotation_time_ms, 3),
            "old_key_fingerprint": old_pk_fingerprint,
            "new_key_fingerprint": new_pk.hex()[:16],
            "overlap_window_seconds": self.overlap_window_seconds,
            "timestamp": self.last_rotation_time,
            "target_met": rotation_time_ms < 2000.0
        }
        
        print(f"[+] Key Rotation Completed ({reason}): {rotation_time_ms:.2f} ms")
        return result

# Global key rotation manager instance
key_rotation_manager = KeyRotationManager()
