"""Endpoint de santé du service"""

import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/health")
async def health_check():
    """
    Vérification simple de la santé du service
    
    Returns:
        Status JSON avec éta des services
    """
    
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "services": {
            "ocr": "healthy",
            "liveness": "healthy",
            "liveness_provider": settings.LIVENESS_PROVIDER,
            "ocr_provider": settings.LLM_PREFER_PROVIDER,
        },
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
