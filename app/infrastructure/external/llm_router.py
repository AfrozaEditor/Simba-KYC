"""Router LLM avec fallback automatique — ordonnance prioritaire"""

import logging
from typing import Dict, Any, List, Optional
from app.infrastructure.external.llm_multimodal_interface import LLMMultimodalInterface

logger = logging.getLogger(__name__)


class LLMRouter:
    """
    Router intelligent avec fallback automatique.
    
    Stratégie:
    1. Essayer le provider préféré (par config)
    2. Si échoue/indisponible → fallback automatique
    3. Logger tous les essais et résultats
    4. Retourner meilleur résultat disponible
        """
    
    def __init__(self, providers: List[LLMMultimodalInterface],
                 prefer_provider: Optional[str] = None):
        """
        Args:
            providers: Liste des providers disponibles
            prefer_provider: Provider prioritaire (sinon premier de la liste)
        """
        self.providers: Dict[str, LLMMultimodalInterface] = {
            p.name: p for p in providers
        }
        
        # Ordonner les providers
        if prefer_provider and prefer_provider in self.providers:
            self.fallback_chain = [
                prefer_provider,
                *[p.name for p in providers if p.name != prefer_provider]
            ]
        else:
            self.fallback_chain = [p.name for p in providers]
        
        logger.info(f"🔗 LLMRouter initialisé - Chaîne: {self.fallback_chain}")

    async def extract_from_image(self, image_base64: str,
                                  document_type: str = "CNI_CAMEROON",
                                  document_side: Optional[str] = None,
                                  use_all: bool = False) -> Dict[str, Any]:
        """
        Extraire avec fallback automatique.
        
        Args:
            image_base64: Image en base64
            document_type: Type de document
            document_side: Face du document si connue ("front" ou "back")
            use_all: Si True, essayer TOUS les providers et retourner le meilleur
        
        Returns:
            Résultat du meilleur provider + logs de tous les essais
        """
        results = {}
        
        logger.info(
            "   Extraction multi-LLM debute - document_type=%s - side=%s",
            document_type,
            document_side or "unknown",
        )
        
        if use_all:
            # Essayer tous les providers
            for provider_name in self.fallback_chain:
                provider = self.providers[provider_name]
                if not provider.is_available:
                    logger.debug(f"⏭️ {provider_name.upper()} indisponible - skipped")
                    continue

                logger.info(f"🔄 Essai {provider_name.upper()}...")
                try:
                    result = await provider.extract_from_image(
                        image_base64,
                        document_type,
                        document_side=document_side,
                    )
                    results[provider_name] = result
                    logger.info(f"  {provider_name.upper()} succès - Confiance: {result.get('confidence', 0):.2f}")
                except Exception as e:
                    logger.warning(f"  {provider_name.upper()} erreur: {e}")
                    results[provider_name] = {"success": False, "error": str(e)}
        else:
            # Chaîne fallback: essayer les providers dans l'ordre até succès
            for provider_name in self.fallback_chain:
                provider = self.providers[provider_name]
                
                if not provider.is_available:
                    logger.warning(f"⏭️ {provider_name.upper()} indisponible - skipped")
                    continue
                
                logger.info(f"🔄 Essai {provider_name.upper()}...")
                try:
                    result = await provider.extract_from_image(
                        image_base64,
                        document_type,
                        document_side=document_side,
                    )
                    
                    if result.get("success"):
                        logger.info(f"  {provider_name.upper()} succès - Confiance: {result.get('confidence', 0):.2f}")
                        result["all_attempts"] = results
                        return result
                    else:
                        logger.warning(f"   {provider_name.upper()} échoué: {result.get('error', 'Unknown error')}")
                        results[provider_name] = result
                
                except Exception as e:
                    logger.error(f"  {provider_name.upper()} exception: {e}")
                    results[provider_name] = {"success": False, "error": str(e)}
            
            # Tous ont échoué
            logger.error("  TOUS les providers ont échoué")
            return {
                "success": False,
                "provider": "router",
                "confidence": 0.0,
                "detected_fields": {},
                "confidence_scores": {},
                "warnings": ["all_providers_failed"],
                "all_attempts": results
            }
        
        # Mode use_all: retourner le meilleur
        if not results:
            return {
                "success": False,
                "provider": "router",
                "confidence": 0.0,
                "detected_fields": {},
                "confidence_scores": {},
                "warnings": ["no_results"],
                "all_attempts": results
            }
        
        # Trouver le meilleur (highest confidence)
        best_name = max(
            results.keys(),
            key=lambda k: results[k].get("confidence", 0)
        )
        best_result = results[best_name]
        
        logger.info(f"🏆 Meilleur résultat: {best_name.upper()} (confiance: {best_result.get('confidence', 0):.2f})")
        
        best_result["all_attempts"] = {
            k: {"confidence": v.get("confidence", 0), "success": v.get("success", False)}
            for k, v in results.items()
        }
        
        return best_result

    async def analyze_document_integrity(self, image_base64: str) -> Dict[str, Any]:
        """Analyser l'intégrité avec fallback"""
        for provider_name in self.fallback_chain:
            provider = self.providers[provider_name]
            
            if not provider.is_available:
                continue
            
            try:
                logger.info(f"Intégrité check via {provider_name}")
                result = await provider.analyze_document_integrity(image_base64)
                result["provider"] = provider_name
                return result
            except Exception as e:
                logger.warning(f"{provider_name} integrity check échoué: {e}")
        
        logger.error("Integrity check échoué sur tous les providers")
        return {
            "integrity_score": 0.0,
            "is_tampered": False,
            "is_fake": False,
            "warnings": ["integrity_check_failed"],
            "provider": "router"
        }

    def get_available_providers(self) -> List[str]:
        """Lister les providers disponibles"""
        available = [
            name for name in self.fallback_chain
            if self.providers[name].is_available
        ]
        logger.info(f"Providers disponibles: {available}")
        return available

    def get_provider_status(self) -> Dict[str, bool]:
        """Status de tous les providers"""
        return {
            name: provider.is_available
            for name, provider in self.providers.items()
        }
