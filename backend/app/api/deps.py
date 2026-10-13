from app.ml.detector import detector_engine, AegisIDSDetector

def get_detector() -> AegisIDSDetector:
    """Dependency provider for Aegis IDS Engine."""
    if not detector_engine.is_loaded:
        detector_engine.load_model()
    return detector_engine
