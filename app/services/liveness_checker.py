"""Service de vérification de vivacité — couche orchestration."""

import logging
from typing import Any, Dict, Optional

from app.core.models.kyc_result import LivenessCheck
from app.infrastructure.external.aws_liveness import LivenessInterface

logger = logging.getLogger(__name__)


class LivenessChecker:
    """Orchestre et normalise les résultats du provider livenesfs actif.

    Ce service est le seul point de contact entre l'orchestrateur KYC
    et l'implémentation AWSLiveness.
    """

    def __init__(self, liveness_service: Optional[LivenessInterface] = None):
        """
        Args:
            liveness_service: Provider liveness (doit implémenter LivenessInterface).
        """
        self.service: Optional[LivenessInterface] = liveness_service
        self.min_confidence = 0.85

    # ─────────────────────────────────────────────────────────────────────────
    # check_liveness
    # ─────────────────────────────────────────────────────────────────────────

    async def check_liveness(self, selfie_base64: str) -> LivenessCheck:
        """Vérifie la vivacité du selfie et retourne un LivenessCheck enrichi."""
        if self.service is None:
            logger.error("check_liveness: service indisponible")
            return LivenessCheck(
                passed=False,
                confidence=0.0,
                method="unavailable",
                spoof_score=1.0,
                quality_score=0.0,
                flags=["service_unavailable"],
                face_count=0,
            )

        try:
            result: Dict[str, Any] = await self.service.check_liveness(selfie_base64)

            return LivenessCheck(
                passed=result.get("is_live", False),
                confidence=result.get("confidence", 0.0),
                method=result.get("method", "unknown"),
                spoof_score=result.get("spoof_score"),
                quality_score=result.get("quality_score"),
                flags=result.get("flags") or [],
                face_count=result.get("face_count"),
            )

        except Exception as exc:
            logger.error(f"check_liveness erreur: {exc}", exc_info=True)
            return LivenessCheck(
                passed=False,
                confidence=0.0,
                method="error",
                spoof_score=1.0,
                quality_score=0.0,
                flags=["service_error"],
                face_count=0,
            )

    # ─────────────────────────────────────────────────────────────────────────
    # compare_faces
    # ─────────────────────────────────────────────────────────────────────────

    async def compare_faces(
        self, selfie_base64: str, document_face_base64: str
    ) -> Dict[str, Any]:
        """Compare le visage du selfie avec celui du document."""
        if self.service is None:
            logger.error("compare_faces: service indisponible")
            return {
                "match": False,
                "confidence": 0.0,
                "similarity_score": 0.0,
                "method": "unavailable",
                "error": "liveness_service_unavailable"
            }

        try:
            result: Dict[str, Any] = await self.service.compare_faces(
                selfie_base64, document_face_base64
            )
            
            error = result.get("error")
            if error:
                logger.warning(f"compare_faces: error={error}")

            logger.info(
                f"compare_faces: similarité={result.get('confidence', 0):.3f}, "
                f"match={result.get('match', False)}"
            )
            
            return result

        except Exception as exc:
            logger.error(f"compare_faces erreur: {exc}", exc_info=True)
            return {
                "match": False,
                "confidence": 0.0,
                "similarity_score": 0.0,
                "method": "error",
                "error": str(exc)
            }

    # ── get_face_match_score - Version simplifiée ─────────────────────────────

    async def get_face_match_score(
        self, selfie_base64: str, document_face_base64: str
    ) -> float:
        """Version simplifiée qui retourne uniquement le score de similarité."""
        result = await self.compare_faces(selfie_base64, document_face_base64)
        return float(result.get("confidence", result.get("similarity_score", 0.0)))

    # ─────────────────────────────────────────────────────────────────────────
    # detect_spoof_attempts
    # ─────────────────────────────────────────────────────────────────────────

    async def detect_spoof_attempts(
        self, selfie_base64: str
    ) -> Dict[str, Any]:
        """Détecte les tentatives de spoofing."""
        if self.service is None:
            logger.error("detect_spoof_attempts: service indisponible")
            return {
                "is_spoofed": True,
                "spoof_confidence": 1.0,
                "spoof_type": "service_unavailable",
                "flags": ["service_unavailable"],
                "method": "unavailable",
                "details": {},
            }

        try:
            result: Dict[str, Any] = await self.service.detect_spoof_attempts(selfie_base64)
            return result
            
        except Exception as exc:
            logger.error(f"detect_spoof_attempts erreur: {exc}", exc_info=True)
            return {
                "is_spoofed": True,
                "spoof_confidence": 1.0,
                "spoof_type": "service_error",
                "flags": ["check_failed"],
                "method": "error",
                "details": {"error": str(exc)}
            }
