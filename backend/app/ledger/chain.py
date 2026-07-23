import json
import hashlib
import time
import uuid
from typing import List, Dict, Any, Optional
from app.models.ledger import AegisLedgerEntry

def compute_entry_hash(entry: AegisLedgerEntry, prev_hash: str) -> str:
    """
    Computes immutable SHA256 hash for a ledger entry concatenated with previous hash pointer.
    """
    actions_str = ",".join(sorted(entry.actions_taken))
    rules_str = json.dumps(entry.rules_applied, sort_keys=True)
    
    raw_payload = (
        f"{entry.id}|{entry.timestamp:.4f}|{entry.event_type}|{entry.threat_id or ''}|"
        f"{entry.source_ip}|{entry.attack_type}|{entry.threat_score:.4f}|{actions_str}|"
        f"{rules_str}|{entry.crypto_mode}|{entry.model_version}|{entry.operator_id}|{prev_hash}"
    )
    return hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

class AegisLedgerChain:
    """
    Tamper-Evident SHA256 Cryptographic Hash-Chained Audit Ledger.
    Ensures O(1) append complexity and O(N) verification complexity for NIS2 / SOC2 compliance.
    """
    
    GENESIS_HASH = "0" * 64
    
    def __init__(self):
        self._chain: List[AegisLedgerEntry] = []
        self._initialize_genesis_block()
        
    def _initialize_genesis_block(self):
        """Appends Genesis block if chain is empty."""
        if not self._chain:
            genesis = AegisLedgerEntry(
                id="00000000-0000-0000-0000-000000000000",
                timestamp=1700000000.0,
                event_type="SYSTEM_START",
                source_ip="127.0.0.1",
                attack_type="BENIGN",
                threat_score=0.0,
                actions_taken=["INITIALIZE_AEGIS_LEDGER_CHAIN"],
                prev_hash=self.GENESIS_HASH,
                operator_id="system_genesis"
            )
            genesis.row_hash = compute_entry_hash(genesis, self.GENESIS_HASH)
            self._chain.append(genesis)

    def get_latest_entry(self) -> AegisLedgerEntry:
        """Returns the most recent block entry in the ledger."""
        return self._chain[-1]

    def append_event(
        self,
        event_type: str,
        actions_taken: List[str],
        threat_id: Optional[str] = None,
        source_ip: str = "192.168.1.100",
        attack_type: str = "BENIGN",
        threat_score: float = 0.0,
        rules_applied: Optional[List[Dict[str, Any]]] = None,
        crypto_mode: str = "ML-KEM-768",
        operator_id: str = "auto_response_engine"
    ) -> AegisLedgerEntry:
        """
        Appends a new event block to the tamper-evident hash chain.
        """
        prev_hash = self.get_latest_entry().row_hash
        
        entry = AegisLedgerEntry(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            event_type=event_type,
            threat_id=threat_id,
            source_ip=source_ip,
            attack_type=attack_type,
            threat_score=threat_score,
            actions_taken=actions_taken,
            rules_applied=rules_applied or [],
            crypto_mode=crypto_mode,
            operator_id=operator_id,
            prev_hash=prev_hash
        )
        
        entry.row_hash = compute_entry_hash(entry, prev_hash)
        self._chain.append(entry)
        return entry

    def get_all_entries(self, limit: int = 50, offset: int = 0) -> List[AegisLedgerEntry]:
        """Returns paginated ledger entries in reverse chronological order."""
        reversed_chain = list(reversed(self._chain))
        return reversed_chain[offset : offset + limit]

    def get_chain_length(self) -> int:
        return len(self._chain)

# Global ledger chain instance
ledger_chain = AegisLedgerChain()
