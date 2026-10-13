"""Tamper-detection tests for the hash-chained ledger.

The mesh relies on the ledger for audit-log guarantees:
countermeasures, bounty awards, MODEL_SWAP events all append here.
If a single entry's content is modified in memory or on disk,
``verify_chain_integrity`` must report ``valid=False`` and identify
which entry broke the chain.

These tests run against the in-memory ``ledger_chain`` singleton.
They DO NOT touch disk — so they exercise the contract that
``verify_chain_integrity`` walks every entry and re-computes its
hash from the stored content.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("REDIS_URL", "")
os.environ.setdefault("AEGIS_REDTEAM_BOOT", "0")


def _fresh_chain():
    """Return a fresh in-memory ledger for isolation."""
    from app.ledger.chain import AegisLedgerChain
    return AegisLedgerChain()


def test_genesis_block_verifies():
    chain = _fresh_chain()
    from app.ledger.verify import verify_chain_integrity
    res = verify_chain_integrity(chain_instance=chain)
    assert res["valid"] is True, res
    assert res["chain_length"] == 1
    print("[OK] genesis block verifies")


def test_append_then_still():
    chain = _fresh_chain()
    for i in range(5):
        chain.append_event(
            event_type="TEST_EVENT",
            actions_taken=[f"step={i}"],
            threat_id=f"t-{i}",
            source_ip="10.0.0.1",
            attack_type="BENIGN",
            threat_score=0.1,
        )
    from app.ledger.verify import verify_chain_integrity
    res = verify_chain_integrity(chain_instance=chain)
    assert res["valid"] is True
    assert res["chain_length"] == 6  # 1 genesis + 5 appended
    print("[OK] 5 appended events verify")


def test_content_mutation_detected():
    chain = _fresh_chain()
    for i in range(5):
        chain.append_event(
            event_type="TEST_EVENT",
            actions_taken=[f"step={i}"],
            threat_id=f"t-{i}",
        )
    # Mutate entry index 3 (the 4th non-genesis entry) in place.
    target = chain._chain[3]
    original_actions = list(target.actions_taken)
    target.actions_taken = ["INJECTED_BY_ATTACKER"]
    from app.ledger.verify import verify_chain_integrity
    res = verify_chain_integrity(chain_instance=chain)
    assert res["valid"] is False, "tamper must be detected"
    assert res["broken_at"] == target.id
    assert "TAMPERED_CONTENT" in res["reason"], res
    # Restore so the next test sees a clean chain if these run together.
    target.actions_taken = original_actions
    print(f"[OK] content mutation detected at {res['reason']}")


def test_deletion_detected():
    chain = _fresh_chain()
    for i in range(5):
        chain.append_event(event_type="TEST_EVENT", actions_taken=[f"s={i}"])
    # Delete entry index 2. prev_hash of entry 3 will no longer match.
    removed = chain._chain.pop(2)
    from app.ledger.verify import verify_chain_integrity
    res = verify_chain_integrity(chain_instance=chain)
    assert res["valid"] is False
    assert "PREV_HASH_MISMATCH" in res["reason"], res
    # The broken_at should point at the entry that lost its prev pointer
    # (the one that USED to follow the deleted block).
    assert res["broken_at"] is not None
    # Re-insert to keep the chain usable.
    chain._chain.insert(2, removed)
    print("[OK] deletion detected via PREV_HASH_MISMATCH")


def test_insertion_detected():
    chain = _fresh_chain()
    for i in range(3):
        chain.append_event(event_type="TEST_EVENT", actions_taken=[f"s={i}"])
    from app.models.ledger import AegisLedgerEntry
    # Forge an entry that points at genesis — only valid as entry 1.
    forged = AegisLedgerEntry(
        id="forged-entry-id",
        timestamp=1234567890.0,
        event_type="FORGED",
        threat_id=None,
        source_ip="0.0.0.0",
        attack_type="BENIGN",
        threat_score=0.0,
        actions_taken=["FORGED_ACTION"],
        prev_hash="0" * 64,
        operator_id="forger",
    )
    from app.ledger.chain import compute_entry_hash
    forged.row_hash = compute_entry_hash(forged, "0" * 64)
    chain._chain.insert(1, forged)  # inserted right after genesis
    from app.ledger.verify import verify_chain_integrity
    res = verify_chain_integrity(chain_instance=chain)
    assert res["valid"] is False
    # Either the forged entry's prev mismatch (it points to genesis,
    # but genesis was followed by some other entry) OR a content
    # mismatch downstream should fire.
    assert res["reason"] in (
        "PREV_HASH_MISMATCH_AT_INDEX_1",
        "PREV_HASH_MISMATCH_AT_INDEX_2",
    ) or "TAMPERED_CONTENT" in res["reason"], res
    print(f"[OK] insertion detected via {res['reason']}")


if __name__ == "__main__":
    test_genesis_block_verifies()
    test_append_then_still()
    test_content_mutation_detected()
    test_deletion_detected()
    test_insertion_detected()
    print("\nAll ledger tamper-detection checks passed.")