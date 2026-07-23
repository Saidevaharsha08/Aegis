from typing import Dict, Any, Optional
from app.ledger.chain import ledger_chain, compute_entry_hash, AegisLedgerChain

def verify_chain_integrity(chain_instance: Optional[AegisLedgerChain] = None) -> Dict[str, Any]:
    """
    Verifies full hash-chain integrity from Genesis block to latest block.
    Detects any tampering or block modification.
    Returns: {valid: bool, chain_length: int, first_entry: float, last_entry: float, broken_at: Optional[str]}
    """
    chain = (chain_instance or ledger_chain)._chain
    
    if not chain:
        return {"valid": False, "chain_length": 0, "reason": "EMPTY_CHAIN", "broken_at": None}

    # 1. Genesis block verification
    expected_prev = AegisLedgerChain.GENESIS_HASH
    
    for i, entry in enumerate(chain):
        # Verify previous hash pointer matches previous block's row_hash
        if entry.prev_hash != expected_prev:
            return {
                "valid": False,
                "chain_length": len(chain),
                "first_entry": chain[0].timestamp,
                "last_entry": chain[-1].timestamp,
                "broken_at": entry.id,
                "reason": f"PREV_HASH_MISMATCH_AT_INDEX_{i}"
            }
            
        # Re-compute row_hash and verify cryptographic match
        computed_hash = compute_entry_hash(entry, expected_prev)
        if computed_hash != entry.row_hash:
            return {
                "valid": False,
                "chain_length": len(chain),
                "first_entry": chain[0].timestamp,
                "last_entry": chain[-1].timestamp,
                "broken_at": entry.id,
                "reason": f"TAMPERED_CONTENT_AT_INDEX_{i}"
            }
            
        expected_prev = entry.row_hash

    return {
        "valid": True,
        "chain_length": len(chain),
        "first_entry": chain[0].timestamp,
        "last_entry": chain[-1].timestamp,
        "broken_at": None
    }
