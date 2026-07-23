from fastapi import APIRouter, Query, status
from app.ledger.chain import ledger_chain
from app.ledger.verify import verify_chain_integrity

router = APIRouter()

@router.get("/ledger/verify", status_code=status.HTTP_200_OK)
def verify_ledger():
    """GET /ledger/verify endpoint: Verifies hash-chain cryptographic integrity."""
    return verify_chain_integrity()

@router.get("/ledger/entries", status_code=status.HTTP_200_OK)
def get_ledger_entries(limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    """GET /ledger/entries endpoint: Returns paginated audit log entries."""
    entries = ledger_chain.get_all_entries(limit=limit, offset=offset)
    return {
        "total_entries": ledger_chain.get_chain_length(),
        "limit": limit,
        "offset": offset,
        "entries": [e.__dict__ for e in entries]
    }
