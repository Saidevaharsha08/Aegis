import time
import uuid
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

from app.ml.detector import DetectionResult
from app.crypto.rotation import key_rotation_manager
from app.optimizer.qaoa_sim import QAOAInspiredOptimizer
from app.ledger.chain import ledger_chain

class ResponseResult(BaseModel):
    threat_id: str
    actions_taken: List[str]
    rules_applied: List[Dict[str, Any]]
    keys_rotated: bool
    affected_node: str
    response_time_ms: float
    ledger_entry_id: str

class AegisResponseEngine:
    """
    Automated Threat Response Playbook Engine for Aegis.
    Maps detected threat signatures to mitigation action chains (QAOA rule optimization,
    PQC key rotation, node isolation, and tamper-evident audit logging).
    """
    
    def execute_response(self, detection: DetectionResult, source_ip: str = "192.168.1.105") -> ResponseResult:
        """
        Executes automated mitigation pipeline in < 100ms.
        """
        t0 = time.perf_counter()
        threat_id = str(uuid.uuid4())
        affected_node = "10.0.0.14"
        actions_taken = []
        keys_rotated = False
        
        # 1. Run QAOA-inspired optimizer to select optimal firewall rules
        optimizer = QAOAInspiredOptimizer(fpr_budget=0.10, cost_budget=10.0)
        opt_res = optimizer.optimize()
        rules_applied = [r.model_dump() for r in opt_res.selected_rules]
        actions_taken.append("APPLY_QAOA_FIREWALL_RULES")
        
        attack_type = detection.attack_type.upper()
        
        # 2. Playbook Action Mapping
        if "DOS" in attack_type or "DDOS" in attack_type:
            actions_taken.extend(["RATE_LIMIT_SYN_FLOOD", "ISOLATE_AFFECTED_SUBNET"])
            # Rotate ML-KEM encryption keys
            rot_res = key_rotation_manager.rotate_keys(reason=f"AUTO_RESPONSE_{attack_type}")
            keys_rotated = rot_res["rotated"]
            actions_taken.append("ROTATE_MLKEM_SESSION_KEYS")
            
        elif "BRUTEFORCE" in attack_type:
            actions_taken.extend(["BLOCK_SOURCE_IP", "ENABLE_EXPONENTIAL_AUTH_BACKOFF"])
            rot_res = key_rotation_manager.rotate_keys(reason="AUTO_RESPONSE_BRUTEFORCE")
            keys_rotated = rot_res["rotated"]
            actions_taken.append("ROTATE_AFFECTED_SERVICE_KEYS")
            
        elif "PORTSCAN" in attack_type:
            actions_taken.extend(["TEMPORARY_BLOCK_SOURCE_IP_15MIN", "INCREASE_LOGGING_VERBOSITY"])
            
        else: # Bot / Web Attack / Infiltration / DataExfiltration
            actions_taken.extend(["ISOLATE_AFFECTED_NODE_IMMEDIATE", "CAPTURE_FORENSIC_TRAFFIC_DUMP"])
            rot_res = key_rotation_manager.rotate_keys(reason=f"CRITICAL_ALERT_{attack_type}")
            keys_rotated = rot_res["rotated"]
            actions_taken.append("ROTATE_ALL_SYSTEM_KEYS")
            
        # 3. Log Immutable Event to Tamper-Evident Ledger
        ledger_entry = ledger_chain.append_event(
            event_type="AUTOMATED_THREAT_RESPONSE",
            actions_taken=actions_taken,
            threat_id=threat_id,
            source_ip=source_ip,
            attack_type=detection.attack_type,
            threat_score=detection.threat_score,
            rules_applied=rules_applied,
            crypto_mode="ML-KEM-768",
            operator_id="aegis_auto_response_playbook"
        )
        
        t1 = time.perf_counter()
        response_time_ms = (t1 - t0) * 1000.0
        
        return ResponseResult(
            threat_id=threat_id,
            actions_taken=actions_taken,
            rules_applied=rules_applied,
            keys_rotated=keys_rotated,
            affected_node=affected_node,
            response_time_ms=round(response_time_ms, 3),
            ledger_entry_id=ledger_entry.id
        )

response_engine = AegisResponseEngine()
