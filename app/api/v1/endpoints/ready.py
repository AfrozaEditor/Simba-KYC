"""Endpoint de readiness pour Kubernetes."""

import logging
from fastapi import APIRouter
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/ready")
async def readiness_check():
    """
    Vérifie la disponibilité du service pour recevoir du trafic (Kubernetes)
    
    Returns:
        Status de readiness avec dépendances
    """
    
    dependencies_status = {}
    all_ready = True
    
    # 1. Vérifier Groq API (OCR)
    groq_available = False
    if settings.GROQ_API_KEY:
        try:
            import aiohttp
            import asyncio
            
            async def check_groq():
                
                headers = {"Authorization": f"Bearer {settings.GROQ_API_KEY}"}
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{settings.GROQ_API_BASE}/models",
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        return resp.status
            
            # Vérifier Groq
            groq_status = await check_groq()
            groq_available = groq_status == 200
            dependencies_status["groq_api"] = "connected" if groq_available else f"http_{groq_status}"
            if not groq_available:
                all_ready = False
        except Exception as e:
            dependencies_status["groq_api"] = f"disconnected: {str(e)}"
            all_ready = False
    else:
        dependencies_status["groq_api"] = "not_configured"
        all_ready = False
    
    # 2. Vérifier que les credentials AWS sont résolubles localement.
    try:
        import boto3

        session = boto3.Session(
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            aws_session_token=settings.AWS_SESSION_TOKEN,
            region_name=settings.AWS_REGION,
        )
        credentials = session.get_credentials()
        dependencies_status["aws_rekognition"] = (
            "configured" if credentials is not None else "credentials_not_found"
        )
        if credentials is None:
            all_ready = False
    except Exception as e:
        dependencies_status["aws_rekognition"] = f"error: {str(e)}"
        all_ready = False

    dependencies_status["liveness_mode"] = "aws_rekognition"
    dependencies_status["ocr_mode"] = "real (groq)" if settings.GROQ_API_KEY else "real (not_configured)"
    
    return {
        "ready": all_ready,
        "dependencies": dependencies_status
    }
