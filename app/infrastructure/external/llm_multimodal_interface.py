"""Interface generique pour LLM multimodaux - extraction documentaire"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class LLMMultimodalInterface(ABC):
    """
    Interface abstraite pour LLM multimodaux.
    Tous les providers doivent implementer cette interface pour:
    - Extraction de champs structurés (JSON)
    - Analyse d'integrite/tamper detection
    - Support async
    """

    @abstractmethod
    async def extract_from_image(
        self,
        image_base64: str,
        document_type: str = "CNI_CAMEROON",
        document_side: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Extraire les champs structures d'un document.
        
        Args:
            image_base64: Image en base64
            document_type: Type de document (CNI_CAMEROON, PASSPORT, CONTRACT, etc.)
            document_side: Precision optionnelle sur la face du document
                ("front", "back" ou None)
        
        Returns:
            {
                "success": bool,
                "provider": "groq" | etc.,
                "confidence": float (0-1),
                "detected_fields": {
                    "national_id": "AB05011462",
                    "full_name": "Jean Dupont",
                    "date_of_birth": "1990-05-15",
                    "gender": "M",
                    "address": "Yaoundé, Cameroun",
                    ...
                },
                "confidence_scores": {"field": score, ...},
                "warnings": [list of warnings],
                "raw_response": originalLLMOutput
            }
        """
        pass

    @abstractmethod
    async def analyze_document_integrity(self, image_base64: str) -> Dict[str, Any]:
        """
        Détecter les altérations/tampering.
        
        Returns:
            {
                "integrity_score": float (0-1),
                "is_tampered": bool,
                "is_fake": bool,
                "warnings": [list of warnings]
            }
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Nom du provider (groq, etc.)"""
        pass

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """Vérifier si le provider est disponible/configuré"""
        pass
