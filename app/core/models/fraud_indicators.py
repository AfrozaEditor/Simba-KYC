from enum import Enum
from pydantic import BaseModel, Field, ConfigDict
from typing import Any, Dict, List


class FraudCriterionStatus(str, Enum):
    """Etat d'execution d'un critere anti-fraude."""

    PASS = "PASS"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


class FraudCriterionLevel(str, Enum):
    """Niveau de severite d'un critere anti-fraude."""

    INFO = "INFO"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    HARD_REJECT = "HARD_REJECT"


class FraudCriterionResult(BaseModel):
    """Resultat d'un critere individuel du catalogue AF-xxx."""

    criterion_id: str = Field(..., description="Identifiant du critere (ex: AF-040)")
    status: FraudCriterionStatus = Field(..., description="Etat du critere")
    level: FraudCriterionLevel = Field(..., description="Niveau de severite")
    score_impact: int = Field(
        default=0,
        description="Impact sur le score KYC (souvent negatif en cas d'echec)",
    )
    reason: str = Field(..., description="Raison lisible expliquant le declenchement")
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Elements de preuve utiles pour audit et revue humaine",
    )


class FraudIndicators(BaseModel):
    """Indicateurs de fraude détectés lors de l'analyse KYC"""
    
    document_integrity: float = Field(
        ..., 
        ge=0.0, 
        le=1.0,
        description="Score d'intégrité du document (0-1)"
    )
    face_match_score: float = Field(
        ..., 
        ge=0.0, 
        le=1.0,
        description="Score de correspondance visage (0-1)"
    )
    is_suspicious: bool = Field(
        ..., 
        description="Indicateur si le document est suspect"
    )
    flags: List[str] = Field(
        default_factory=list,
        description="Liste des drapeaux de fraude détectés"
    )
    criteria_results: List[FraudCriterionResult] = Field(
        default_factory=list,
        description="Criteres AF-xxx declenches pendant l'analyse",
    )
    hard_reject_criteria: List[str] = Field(
        default_factory=list,
        description="Sous-ensemble des criteres qui imposent un rejet automatique",
    )
    manual_review_criteria: List[str] = Field(
        default_factory=list,
        description="Sous-ensemble des criteres qui imposent une revue manuelle",
    )
    
    model_config = ConfigDict(json_schema_extra = {
        "example": {
            "document_integrity": 0.98,
            "face_match_score": 0.92,
            "is_suspicious": False,
            "flags": [],
            "criteria_results": [],
            "hard_reject_criteria": [],
            "manual_review_criteria": []
        }
    })
