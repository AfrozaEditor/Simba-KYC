"""Règles pour la analyse KYC"""

from typing import Optional, Sequence

from app.core.models.fraud_indicators import FraudCriterionResult


class KYCRules:
    """Règles et logique pour l'analyse KYC"""
    
    # Seuils de confiance
    MIN_LIVENESS_CONFIDENCE = 0.85
    MIN_FACE_MATCH = 0.80
    MIN_DOCUMENT_INTEGRITY = 0.75
    
    # Seuils de score
    EXCELLENT_SCORE = 850
    GOOD_SCORE = 700
    ACCEPTABLE_SCORE = 500
    POOR_SCORE = 300
    
    @staticmethod
    def determine_kyc_status(
        valid: bool,
        liveness_passed: bool,
        liveness_confidence: float,
        face_match_score: float,
        document_integrity: float,
        fraud_flags: list,
        kyc_score: Optional[int] = None,
        simba_score: Optional[int] = None,
        hard_reject_criteria: Optional[list] = None,
        manual_review_criteria: Optional[list] = None,
    ) -> tuple[str, str]:
        """
        Détermine le statut KYC et la recommandation
        
        Returns:
            (status, recommendation) - status: APPROVED/REJECTED/MANUAL_REVIEW
                                     recommendation: AUTO_APPROVE/MANUAL_REVIEW/AUTO_REJECT
        """

        hard_reject_criteria = hard_reject_criteria or []
        manual_review_criteria = manual_review_criteria or []
        effective_score = kyc_score if kyc_score is not None else int(simba_score or 0)

        # Priorite absolue: criteres hard reject explicites
        if hard_reject_criteria:
            return ("REJECTED", "AUTO_REJECT")
        
        # Critères d'approbation automatique (stricte)
        if (valid and 
            liveness_passed and 
            liveness_confidence >= KYCRules.MIN_LIVENESS_CONFIDENCE and
            face_match_score >= KYCRules.MIN_FACE_MATCH and
            document_integrity >= KYCRules.MIN_DOCUMENT_INTEGRITY and
            len(fraud_flags) == 0 and
            len(manual_review_criteria) == 0 and
            effective_score >= KYCRules.GOOD_SCORE):
            
            return ("APPROVED", "AUTO_APPROVE")

        # Auto-approbation robuste: biometrie tres forte et absence de signaux
        # hard/manual explicites, meme si l'integrite visuelle est moderement basse.
        fraud_severity = KYCRules._assess_fraud_severity(fraud_flags)
        if (
            valid
            and liveness_passed
            and liveness_confidence >= 0.90
            and face_match_score >= 0.90
            and document_integrity >= 0.35
            and len(hard_reject_criteria) == 0
            and len(manual_review_criteria) == 0
            and fraud_severity == "low"
            and effective_score >= KYCRules.GOOD_SCORE
        ):
            return ("APPROVED", "AUTO_APPROVE")
        
        # Critères de rejet automatique
        if (not valid or
            not liveness_passed or
            liveness_confidence < 0.5 or
            face_match_score < 0.5 or
            document_integrity < 0.5):
            
            fraud_severity = KYCRules._assess_fraud_severity(fraud_flags)
            
            if fraud_severity == "high" or effective_score < KYCRules.POOR_SCORE:
                return ("REJECTED", "AUTO_REJECT")

        # Criteres explicites de revue humaine
        if manual_review_criteria:
            return ("MANUAL_REVIEW", "MANUAL_REVIEW")
        
        # Sinon: révision manuelle
        return ("MANUAL_REVIEW", "MANUAL_REVIEW")
    
    @staticmethod
    def _assess_fraud_severity(fraud_flags: list) -> str:
        """Évalue la sévérité des indicateurs de fraude"""
        
        high_severity_flags = [
            "document_tampered",
            "document_fake",
            "spoofing_attempt",
            "face_swap",
            "deep_fake"
        ]
        
        medium_severity_flags = [
            "low_face_match",
            "document_blurry",
            "poor_lighting",
            "liveness_suspicious"
        ]
        
        high_count = sum(1 for flag in fraud_flags if flag in high_severity_flags)
        medium_count = sum(1 for flag in fraud_flags if flag in medium_severity_flags)
        
        if high_count > 0:
            return "high"
        elif medium_count >= 2:
            return "medium"
        else:
            return "low"
    
    @staticmethod
    def generate_kyc_score(
        liveness_confidence: float,
        face_match_score: float,
        document_integrity: float,
        fraud_flags: list,
        criteria_results: Optional[Sequence[FraudCriterionResult]] = None,
        account_age_days: int = 0,
        document_consistency_bonus: int = 0,
    ) -> int:
        """Génère un score KYC (0-1000)"""
        
        # Score de base sur les vérifications
        liveness_score = int(liveness_confidence * 300)  # 0-300
        face_score = int(face_match_score * 350)  # 0-350
        document_score = int(document_integrity * 350)  # 0-350
        
        base_score = liveness_score + face_score + document_score
        
        # Pénalité pour fraude
        fraud_penalty = 0
        fraud_severity = KYCRules._assess_fraud_severity(fraud_flags)
        
        if fraud_severity == "high":
            fraud_penalty = -200
        elif fraud_severity == "medium":
            fraud_penalty = -100
        
        # Bonus pour ancienneté compte (contexte)
        age_bonus = 0
        if account_age_days > 365:
            age_bonus = 100
        elif account_age_days > 180:
            age_bonus = 50

        criteria_penalty = 0
        if criteria_results:
            criteria_penalty = sum(
                result.score_impact
                for result in criteria_results
                if result.score_impact < 0
            )
        
        final_score = base_score + fraud_penalty + age_bonus + criteria_penalty + document_consistency_bonus
        
        return max(min(final_score, 1000), 0)
