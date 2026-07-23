from fastapi import APIRouter, Depends, HTTPException, status
from app.ml.detector import DetectionResult
from app.response.actions import response_engine, ResponseResult

router = APIRouter()

@router.post("/respond", response_model=ResponseResult, status_code=status.HTTP_200_OK)
def trigger_automated_response(detection: DetectionResult) -> ResponseResult:
    """
    POST /respond endpoint: Triggers automated mitigation playbook for detected threat.
    Executes QAOA rule optimization, PQC key rotation, node isolation, and tamper-evident logging.
    """
    try:
        result = response_engine.execute_response(detection)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Response execution failed: {str(e)}"
        )
