import sys
import pytest
from pathlib import Path

project_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "backend"))

from app.ledger.chain import AegisLedgerChain, compute_entry_hash
from app.ledger.verify import verify_chain_integrity

def test_ledger_genesis_block():
    chain = AegisLedgerChain()
    assert chain.get_chain_length() >= 1
    genesis = chain._chain[0]
    assert genesis.event_type == "SYSTEM_START"
    assert genesis.prev_hash == AegisLedgerChain.GENESIS_HASH

def test_ledger_append_and_verify():
    chain = AegisLedgerChain()
    entry1 = chain.append_event("RULE_APPLIED", actions_taken=["BLOCK_IP"], attack_type="DoS")
    entry2 = chain.append_event("KEY_ROTATED", actions_taken=["ROTATE_PQC_KEYS"], attack_type="DoS")
    
    assert entry2.prev_hash == entry1.row_hash
    
    verification = verify_chain_integrity(chain)
    assert verification["valid"] is True
    assert verification["broken_at"] is None

def test_ledger_tamper_detection():
    chain = AegisLedgerChain()
    chain.append_event("RULE_APPLIED", actions_taken=["BLOCK_IP"], attack_type="PortScan")
    chain.append_event("NODE_ISOLATED", actions_taken=["ISOLATE_NODE"], attack_type="Infiltration")
    
    # Verify chain is valid initially
    assert verify_chain_integrity(chain)["valid"] is True
    
    # Tamper with an existing block content in history
    chain._chain[1].attack_type = "TAMPERED_ATTACK_NAME"
    
    # Re-verify: integrity check must catch tampering!
    verification = verify_chain_integrity(chain)
    assert verification["valid"] is False
    assert verification["broken_at"] == chain._chain[1].id
