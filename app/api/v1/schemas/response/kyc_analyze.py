from pydantic import BaseModel, Field, ConfigDict
from typing import Optional

from app.core.models.kyc_result import KYCResult


class KYCAnalyzeResponse(BaseModel):
    """Réponse KYC de Simba KYC."""
    
    success: bool = Field(..., description="Succès de l'opération")
    request_id: Optional[str] = Field(None, description="Identifiant dashboard temps reel de la demande KYC")
    data: Optional[KYCResult] = Field(None, description="Résultat du KYC")
    error: Optional[str] = Field(None, description="Message d'erreur si applicable")
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "success": True,
            "data": {
                "valid": True,
                "status": "APPROVED",
                "kyc_data": {
                    "full_name": "AQIL BELL",
                    "first_name": "AQIL",
                    "last_name": "BELL",
                    "date_of_birth": "2005-08-03",
                    "national_id": "AB05011462",
                    "document_type": "CNI_CAMEROON",
                    "expiry_date": "2036-04-09",
                    "country": "CM",
                    "address": None,
                    "gender": "M"
                },
                "liveness": {
                    "passed": True,
                    "confidence": 0.95,
                    "method": "aws_rekognition"
                },
                "fraud_indicators": {
                    "document_integrity": 0.98,
                    "face_match_score": 0.92,
                    "is_suspicious": False,
                    "flags": [],
                    "criteria_results": [],
                    "hard_reject_criteria": [],
                    "manual_review_criteria": []
                },
                "qr_confidence": 0.95,
                "mrz_confidence": 0.92,
                "document_consistency": 0.94,
                "kyc_score": 750,
                "recommendation": "AUTO_APPROVE"
            }
        }
    })
