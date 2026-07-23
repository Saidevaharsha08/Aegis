from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.routes import health, detect, response, optimize, crypto, ledger
from app.ml.detector import detector_engine

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Aegis — Quantum-Safe AI Threat Detection System REST API Engine",
    version="1.0.0"
)

# CORS middleware for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register complete API router surface
app.include_router(health.router, tags=["Health"])
app.include_router(detect.router, tags=["Detection"])
app.include_router(response.router, tags=["Response Engine"])
app.include_router(optimize.router, tags=["QAOA Optimizer"])
app.include_router(crypto.router, tags=["Post-Quantum Crypto"])
app.include_router(ledger.router, tags=["Audit Ledger"])

@app.on_event("startup")
def startup_event():
    print(f"[*] Starting {settings.PROJECT_NAME} Backend Engine...")
    detector_engine.load_model()
    print("[+] Model preloaded & SHAP explainer warmed up successfully.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )
