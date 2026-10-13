import time
import uuid
import hashlib
import hmac
from typing import Dict, Any, Optional
from app.crypto.pqc import MLKEMSession

class AegisSessionManager:
    """
    Manages post-quantum ML-KEM session keys, encapsulation tokens,
    and token authorization for internal microservice communication.
    """
    
    def __init__(self, token_ttl_seconds: int = 3600):
        self.token_ttl_seconds = token_ttl_seconds
        self.pqc_engine = MLKEMSession()
        self.public_key, self._secret_key = self.pqc_engine.generate_keypair()
        
        # Session table: session_id -> {shared_secret, created_at, expires_at, component_id, valid}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        
    def create_session(self, component_id: str = "backend_worker") -> Dict[str, Any]:
        """
        Creates a new PQC session by encapsulating a shared secret with system's ML-KEM public key.
        """
        ciphertext, shared_secret = self.pqc_engine.encapsulate(self.public_key)
        session_id = str(uuid.uuid4())
        
        now = time.time()
        expires_at = now + self.token_ttl_seconds
        
        # Hash of shared secret for fast verification header checks
        secret_hash = hashlib.sha256(shared_secret).hexdigest()
        
        session_data = {
            "session_id": session_id,
            "ciphertext_hex": ciphertext.hex(),
            "shared_secret_hash": secret_hash,
            "shared_secret": shared_secret,
            "component_id": component_id,
            "created_at": now,
            "expires_at": expires_at,
            "valid": True
        }
        
        self._sessions[session_id] = session_data
        return session_data

    def validate_session(self, session_id: str, secret_hash: str) -> bool:
        """
        Validates whether a session token is active, unexpired, and matches shared secret hash.
        """
        session = self._sessions.get(session_id)
        if not session:
            return False
            
        if not session.get("valid", False):
            return False
            
        if time.time() > session["expires_at"]:
            session["valid"] = False
            return False
            
        return hmac.compare_digest(session["shared_secret_hash"], secret_hash)

    def invalidate_session(self, session_id: str):
        """Invalidates a specific session."""
        if session_id in self._sessions:
            self._sessions[session_id]["valid"] = False

    def invalidate_all_sessions(self):
        """Invalidates all current sessions (triggered during key rotation)."""
        for sid in self._sessions:
            self._sessions[sid]["valid"] = False

    def get_active_sessions_count(self) -> int:
        """Returns total count of valid, non-expired sessions."""
        now = time.time()
        return sum(1 for s in self._sessions.values() if s.get("valid") and s["expires_at"] > now)

# Global session manager instance
session_manager = AegisSessionManager()
