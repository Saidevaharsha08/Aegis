from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import time
import uuid

@dataclass
class ThreatRecord:
    threat_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    source_ip: str = "192.168.1.105"
    attack_type: str = "DoS"
    threat_score: float = 0.95
    confidence: str = "HIGH"
    affected_node: str = "10.0.0.14"
    status: str = "DETECTED"
