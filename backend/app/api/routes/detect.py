from fastapi import APIRouter, Depends, HTTPException, status
from app.ml.detector import TrafficFeatures, DetectionResult, AegisIDSDetector
from app.api.deps import get_detector

router = APIRouter()

@router.post("/detect", response_model=DetectionResult, status_code=status.HTTP_200_OK)
def detect_threat(
    traffic: TrafficFeatures,
    detector: AegisIDSDetector = Depends(get_detector)
) -> DetectionResult:
    """
    POST /detect endpoint: Analyzes live network traffic flow features and detects potential intrusions.
    Returns threat score, attack type classification, confidence level, and top 5 SHAP feature explanations.
    """
    try:
        result = detector.predict(traffic)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )
