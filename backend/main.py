import asyncio
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.routes import health, detect, response, optimize, crypto, ledger, monitor, ingest, generator, stream as stream_routes, mesh as mesh_routes
from app.ml.detector import detector_engine

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Aegis — Quantum-Safe AI Threat Detection System REST API Engine",
    version="1.0.0"
)

# CORS middleware for Next.js frontend.
# Default to the local dev origin only — opening CORS to "*" is
# unsafe once the mesh is publicly reachable (the share-link page
# loads from any origin). In development we keep "*" for tooling
# convenience; production deployments MUST pin origins.
_cors_origins = ["http://localhost:3000"]
if settings.ENVIRONMENT == "development":
    _cors_origins.append("*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
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
app.include_router(monitor.router, tags=["Monitor"])
app.include_router(ingest.router, tags=["Ingest"])
app.include_router(generator.router, tags=["Attack Generator Studio"])
app.include_router(stream_routes.router, tags=["Stream"])
app.include_router(mesh_routes.router, tags=["Mesh"])


@app.on_event("startup")
def startup_event():
    print(f"[*] Starting {settings.PROJECT_NAME} Backend Engine...")
    detector_engine.load_model()
    print("[+] Model preloaded & SHAP explainer warmed up successfully.")
    # Schedule the online detector consumer in the running event loop.
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            from app.online_detector import start_background_consumer
            task = start_background_consumer()
            # Keep a reference so the task is not GC'd and the
            # coroutine is properly tracked (avoids the
            # "coroutine was never awaited" warning under TestClient).
            app.state.online_detector_task = task
            print("[+] Online detector consumer scheduled.")
    except RuntimeError:
        # Some test harnesses don't expose a running loop here.
        pass

    # Boot the red-team driver so the mesh is alive even without
    # external peers. Disabled under TestClient — the smoke test
    # drives the mesh explicitly.
    if os.getenv("AEGIS_REDTEAM_BOOT", "1") == "1":
        try:
            from app.mesh.redteam import redteam
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(redteam.start(), name="redteam-boot")
        except Exception:
            pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )
