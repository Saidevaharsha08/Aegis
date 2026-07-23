from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import time
import uuid

@dataclass
class AegisLedgerEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = "THREAT_DETECTED"  # THREAT_DETECTED | RULE_APPLIED | KEY_ROTATED | NODE_ISOLATED | GENESIS
    threat_id: Optional[str] = None
    source_ip: str = "127.0.0.1"
    attack_type: str = "BENIGN"
    threat_score: float = 0.0
    actions_taken: List[str] = field(default_factory=list)
    rules_applied: List[Dict[str, Any]] = field(default_factory=list)
    crypto_mode: str = "ML-KEM-768"
    model_version: str = "aegis-ids/v1.0.0"
    operator_id: str = "system_auto_response"
    prev_hash: str = "0" * 64
    row_hash: str = ""
