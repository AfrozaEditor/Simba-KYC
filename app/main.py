"""Application FastAPI principale pour Simba KYC."""

import logging
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
from app.api.v1.endpoints import health, ready, analyze_llm

# Configuration du logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Middleware d'authentification par clé API
class APIKeyMiddleware(BaseHTTPMiddleware):
    """Middleware pour valider la clé API"""
    
    async def dispatch(self, request: Request, call_next):
        # Les endpoints de santé (health, ready) ne requièrent pas la clé API
        if request.url.path in ["/health", "/ready"]:
            return await call_next(request)
        
        # Les endpoints racinaires ne requièrent pas la clé API
        if request.url.path == "/":
            return await call_next(request)
        
        # Les endpoints docs ne requièrent pas la clé API quand ils sont exposés.
        if settings.EXPOSE_API_DOCS and (
            request.url.path.startswith("/docs")
            or request.url.path.startswith("/redoc")
            or request.url.path.startswith("/openapi")
        ):
            return await call_next(request)
        
        # Si mode anonyme enabled et qu'on a pas de clé → OK
        if settings.ALLOW_ANONYMOUS:
            return await call_next(request)
        
        # Sinon, requiert une clé API valide
        api_key = request.headers.get("X-API-Key")
        if not api_key or api_key != settings.API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API Key manquante ou invalide"
            )
        
        return await call_next(request)

# Création de l'application FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Service KYC autonome: OCR, QR, MRZ, liveness AWS et anti-fraude.",
    docs_url="/docs" if settings.EXPOSE_API_DOCS else None,
    redoc_url="/redoc" if settings.EXPOSE_API_DOCS else None,
    openapi_url="/openapi.json" if settings.EXPOSE_API_DOCS else None,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key middleware
app.add_middleware(APIKeyMiddleware)

# Routes de santé (racine)
@app.get("/health", tags=["Health"])
async def root_health():
    """Health check racine"""
    return await health.health_check()

@app.get("/ready", tags=["Health"])
async def root_ready():
    """Readiness check racine"""
    return await ready.readiness_check()

# Routes API v1
app.include_router(
    health.router,
    prefix="/api/v1",
    tags=["Health"]
)

app.include_router(
    ready.router,
    prefix="/api/v1",
    tags=["Health"]
)

app.include_router(
    analyze_llm.router,
    prefix="/api/v1",
    tags=["KYC"]
)

# Routes de test/info
@app.get("/", tags=["Info"])
async def root():
    """Info du service"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs" if settings.EXPOSE_API_DOCS else None,
        "health": "/health",
        "ready": "/ready"
    }

@app.on_event("startup")
async def startup_event():
    """Événement de démarrage"""
    logger.info(f" {settings.APP_NAME} v{settings.APP_VERSION} démarré")
    logger.info(
        f"Providers configurés: OCR_pref={settings.LLM_PREFER_PROVIDER}, Liveness={settings.LIVENESS_PROVIDER}"
    )

@app.on_event("shutdown")
async def shutdown_event():
    """Événement d'arrêt"""
    logger.info(f" {settings.APP_NAME} arrêté")

# Entry point
if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL.lower()
    )
