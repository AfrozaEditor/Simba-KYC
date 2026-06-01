"""Service de detection de fraude."""

from typing import Any, Dict, List, Optional

from app.core.models.fraud_indicators import (
    FraudCriterionLevel,
    FraudIndicators,
)
from app.services.fraud_criteria_engine import FraudCriteriaEngine


class FraudDetector:
    """Detecte et evalue les indicateurs de fraude."""

    DOCUMENT_HARD_REJECT_THRESHOLD = 0.10
    DOCUMENT_SUSPECT_THRESHOLD = 0.60
    SPOOF_HARD_CONFIDENCE = 0.95
    
    def __init__(self, ocr_service=None, liveness_service=None, criteria_engine: Optional[FraudCriteriaEngine] = None):
        """
        Initialise le detecteur de fraude
        
        Args:
            ocr_service: Service OCR pour analyser les documents
            liveness_service: Service de liveness check
            criteria_engine: Moteur de criteres AF-xxx
        """
        self.ocr = ocr_service
        self.liveness = liveness_service
        self.criteria_engine = criteria_engine or FraudCriteriaEngine()
    
    async def analyze_fraud_indicators(
        self,
        document_front_base64: str,
        selfie_base64: str,
        document_back_base64: str = "",
        liveness_confidence: float = 0.95,
        face_match_score: float = 0.92,
        metadata: Optional[Any] = None,
        liveness_quality_score: Optional[float] = None,
        liveness_flags: Optional[List[str]] = None,
        liveness_face_count: Optional[int] = None,
        kyc_data: Optional[Any] = None,
        qr_analysis: Optional[dict] = None,
        mrz_analysis: Optional[dict] = None,
    ) -> FraudIndicators:
        """
        Analyse les indicateurs de fraude
        
        Returns:
            FraudIndicators avec les résultats d'analyse
        """
        
        # Analyse l'intégrité du document
        document_integrity_result = await self._assess_document_integrity(document_front_base64)
        document_integrity = float(document_integrity_result.get("integrity_score", 0.85))
        
        # Détecte les drapeaux de fraude
        fraud_flags = await self._detect_fraud_flags(
            document_front_base64,
            selfie_base64,
            liveness_confidence,
            face_match_score,
            document_integrity_result,
        )

        if liveness_flags:
            fraud_flags = self._merge_liveness_flags(fraud_flags, liveness_flags)

        criteria_results = self.criteria_engine.evaluate(
            document_front_base64=document_front_base64,
            selfie_base64=selfie_base64,
            liveness_confidence=liveness_confidence,
            face_match_score=face_match_score,
            document_integrity=document_integrity,
            fraud_flags=fraud_flags,
            metadata=metadata,
            liveness_quality_score=liveness_quality_score,
            liveness_flags=liveness_flags,
            liveness_face_count=liveness_face_count,
            kyc_data=kyc_data,
            qr_analysis=qr_analysis,
            mrz_analysis=mrz_analysis,
        )

        hard_reject_criteria = sorted(
            [
                criterion.criterion_id
                for criterion in criteria_results
                if criterion.level == FraudCriterionLevel.HARD_REJECT
            ]
        )
        manual_review_criteria = sorted(
            [
                criterion.criterion_id
                for criterion in criteria_results
                if criterion.level == FraudCriterionLevel.MANUAL_REVIEW
            ]
        )

        if not hard_reject_criteria and not manual_review_criteria:
            ambiguous_document_flags = {"document_fake_suspected", "document_tampered_suspected"}
            if fraud_flags and set(fraud_flags).issubset(ambiguous_document_flags):
                fraud_flags = [flag for flag in fraud_flags if flag not in ambiguous_document_flags]

        if hard_reject_criteria:
            fraud_flags.append("hard_reject_criteria_detected")
        if manual_review_criteria:
            fraud_flags.append("manual_review_criteria_detected")

        fraud_flags = sorted(set(fraud_flags))
        
        is_suspicious = (
            len(fraud_flags) > 0
            or len(criteria_results) > 0
            or document_integrity < 0.75
            or face_match_score < 0.8
        )
        
        return FraudIndicators(
            document_integrity=document_integrity,
            face_match_score=face_match_score,
            is_suspicious=is_suspicious,
            flags=fraud_flags,
            criteria_results=criteria_results,
            hard_reject_criteria=hard_reject_criteria,
            manual_review_criteria=manual_review_criteria,
        )
    
    async def _assess_document_integrity(self, document_base64: str) -> Dict[str, Any]:
        """Évalue l'intégrité d'un document"""
        
        if self.ocr is None:
            return {
                "integrity_score": 0.90,
                "is_tampered": False,
                "is_fake": False,
            }
        
        try:
            result = await self.ocr.analyze_document_integrity(document_base64)
            return {
                "integrity_score": float(result.get("integrity_score", 0.90)),
                "is_tampered": bool(result.get("is_tampered", False)),
                "is_fake": bool(result.get("is_fake", False)),
                "warnings": result.get("warnings", []),
            }
        except Exception:
            return {
                "integrity_score": 0.85,
                "is_tampered": False,
                "is_fake": False,
            }
    
    async def _detect_fraud_flags(
        self,
        document_base64: str,
        selfie_base64: str,
        liveness_confidence: float,
        face_match_score: float,
        document_integrity_result: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """Détecte les drapeaux de fraude potentiels"""
        
        flags = []
        
        # Vérifications basées sur les scores
        if face_match_score < 0.8:
            flags.append("low_face_match")
        
        if liveness_confidence < 0.85:
            flags.append("liveness_suspicious")
        
        if face_match_score < 0.5:
            flags.append("no_face_match")
        
        if liveness_confidence < 0.5:
            flags.append("spoofing_attempt")
        
        # Vérifications OCR/integrite documentaire (gating anti faux positifs)
        integrity = document_integrity_result or {}
        integrity_score = float(integrity.get("integrity_score", 0.90))
        is_tampered = bool(integrity.get("is_tampered", False))
        is_fake = bool(integrity.get("is_fake", False))
        has_critical_pair_signal = is_tampered and is_fake and integrity_score <= 0.20

        if is_tampered:
            if has_critical_pair_signal and integrity_score <= self.DOCUMENT_HARD_REJECT_THRESHOLD:
                flags.append("document_tampered")
            elif integrity_score <= self.DOCUMENT_SUSPECT_THRESHOLD:
                flags.append("document_tampered_suspected")

        if is_fake:
            if has_critical_pair_signal and integrity_score <= self.DOCUMENT_HARD_REJECT_THRESHOLD:
                flags.append("document_fake")
            elif integrity_score <= self.DOCUMENT_SUSPECT_THRESHOLD:
                flags.append("document_fake_suspected")
        
        # Vérifications liveness
        if self.liveness:
            try:
                spoof_result = await self.liveness.detect_spoof_attempts(selfie_base64)
                spoof_flags = [str(flag).lower() for flag in spoof_result.get("flags", [])]
                if spoof_result.get("is_spoofed"):
                    spoof_conf = float(spoof_result.get("spoof_confidence", 0.0) or 0.0)
                    spoof_type = str(spoof_result.get("spoof_type") or "").lower()
                    is_critical_spoof = (
                        spoof_conf >= self.SPOOF_HARD_CONFIDENCE
                        and any(token in spoof_type for token in ("screen", "monitor", "display", "tv", "television"))
                    )

                    if is_critical_spoof:
                        flags.append("spoofing_attempt")
                    else:
                        flags.append("liveness_suspicious")
                elif any(flag.startswith("suspicious_") for flag in spoof_flags):
                    suspicious_screen_tokens = (
                        "screen",
                        "monitor",
                        "display",
                        "television",
                        "tv",
                    )
                    has_screen_like_warning = any(
                        any(token in flag for token in suspicious_screen_tokens)
                        for flag in spoof_flags
                        if flag.startswith("suspicious_")
                    )
                    if has_screen_like_warning:
                        flags.append("liveness_suspicious")
            except Exception:
                pass
        
        return sorted(set(flags))

    @staticmethod
    def _merge_liveness_flags(flags: List[str], liveness_flags: List[str]) -> List[str]:
        """Mappe des flags liveness detaillees vers les flags fraude existants."""

        merged = list(flags)
        detailed_flags = set(liveness_flags)

        if detailed_flags.intersection(
            {
                "screen_pattern_detected",
                "printed_photo_suspected",
                "flat_depth_mask_suspected",
            }
        ):
            merged.append("liveness_suspicious")

        if detailed_flags.intersection({"eyes_closed", "strong_reflection", "poor_lighting"}):
            merged.append("liveness_suspicious")

        return sorted(set(merged))
    
    def get_fraud_severity(self, fraud_indicators: FraudIndicators) -> str:
        """Évalue la sévérité des fraudes"""
        
        if not fraud_indicators.flags:
            return "low"
        
        high_severity_flags = {
            "document_tampered", "document_fake", "spoofing_attempt", "no_face_match"
        }
        
        has_high = any(flag in high_severity_flags for flag in fraud_indicators.flags)
        
        if has_high:
            return "high"
        elif len(fraud_indicators.flags) >= 2:
            return "medium"
        else:
            return "low"
