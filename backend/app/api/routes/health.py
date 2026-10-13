from fastapi import APIRouter, Depends
from app.config import settings
from app.api.deps import get_detector, AegisIDSDetector

router = APIRouter()

@router.get("/health")
def health_check(detector: AegisIDSDetector = Depends(get_detector)):
    """Health check endpoint for system readiness."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "model_version": settings.MODEL_VERSION,
        "model_loaded": detector.is_loaded,
        "pqc_algorithm": settings.PQC_ALGORITHM,
        "environment": settings.ENVIRONMENT
    }
