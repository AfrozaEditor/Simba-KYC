"""Factory pour créer instances LLM avec configuration"""

import logging
from typing import List, Optional
from app.infrastructure.external.llm_multimodal_interface import LLMMultimodalInterface
from app.infrastructure.external.groq_model import GroqModel
from app.infrastructure.external.llm_router import LLMRouter
from app.core.config import settings

logger = logging.getLogger(__name__)


def create_llm_models() -> List[LLMMultimodalInterface]:
    """Créer les instances de modèles disponibles"""
    configured_chain = [str(item).strip().lower() for item in settings.LLM_FALLBACK_CHAIN if str(item).strip()]
    if not configured_chain:
        configured_chain = ["groq"]

    unsupported = [provider for provider in configured_chain if provider != "groq"]
    if unsupported:
        logger.warning(
            "Providers LLM non supportés dans ce microservice KYC: %s. Groq reste le provider actif.",
            unsupported,
        )

    models: List[LLMMultimodalInterface] = []
    
    # Groq
    groq = GroqModel(
        api_key=settings.GROQ_API_KEY,
        api_base=settings.GROQ_API_BASE,
        model=settings.GROQ_MODEL,
        timeout=settings.GROQ_TIMEOUT,
    )
    models.append(groq)
    logger.info(f"  Groq disponible: {groq.is_available}")

    return models


def create_llm_router() -> LLMRouter:
    """Créer le router avec fallback automatique"""
    models = create_llm_models()
    
    router = LLMRouter(
        providers=models,
        prefer_provider=settings.LLM_PREFER_PROVIDER
    )
    
    logger.info(f" LLMRouter créé - Chaîne: {settings.LLM_FALLBACK_CHAIN}")
    
    return router


# Instance globale (singleton)
_llm_router: Optional[LLMRouter] = None


def get_llm_router() -> LLMRouter:
    """Obtenir l'instance globale du router"""
    global _llm_router
    if _llm_router is None:
        _llm_router = create_llm_router()
    return _llm_router
