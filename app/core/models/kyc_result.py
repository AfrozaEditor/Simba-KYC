from pydantic import AliasChoices, BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from datetime import date
from enum import Enum

from .fraud_indicators import FraudIndicators


class KYCStatus(str, Enum):
    """Statut de la vérification KYC"""
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class DocumentType(str, Enum):
    """Types de documents supportés"""
    CNI_CAMEROON = "CNI_CAMEROON"
    PASSPORT = "PASSPORT"
    NATIONAL_ID = "NATIONAL_ID"


class KYCData(BaseModel):
    """Données extraites du document KYC"""

    full_name: str = Field(..., description="Nom complet du titulaire")
    first_name: str = Field(..., description="Prénom")
    last_name: str = Field(..., description="Nom de famille")
    date_of_birth: date = Field(..., description="Date de naissance (YYYY-MM-DD)")
    national_id: str = Field(..., description="Numéro d'identification national")
    document_type: DocumentType = Field(..., description="Type de document")
    expiry_date: Optional[date] = Field(None, description="Date d'expiration")
    country: str = Field(..., description="Code pays (ex: CM, GA, CG)")
    address: Optional[str] = Field(None, description="Adresse")
    gender: Optional[str] = Field(None, description="Genre (M/F)")


class LivenessCheck(BaseModel):
    """Résultat de la vérification de vivacité.

    Les champs obligatoires (passed, confidence, method) assurent la
    rétrocompatibilité avec les mocks et l'interface AWS.

    Les champs optionnels propagent les métriques riches du provider actif.
    """

    # ── Champs obligatoires (existants — backward compatible) ──────────────
    passed: bool = Field(..., description="Vérification réussie")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Niveau de confiance global")
    method: str = Field(..., description="Méthode utilisée (aws_rekognition)")

    # ── Champs enrichis (P2 — optionnels pour rester compatibles) ──────────
    spoof_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Score de spoofing détecté (0=réel, 1=spoofé)."
    )
    quality_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Score de qualité image (sharpness + brightness + contrast)."
    )
    flags: Optional[List[str]] = Field(
        None,
        description="Flags d'anomalie détectés (screen_pattern_detected, eyes_closed…)"
    )
    face_count: Optional[int] = Field(
        None, ge=0,
        description="Nombre de visages détectés dans le selfie."
    )


class KYCResult(BaseModel):
    """Résultat complet de l'analyse KYC"""

    model_config = ConfigDict(populate_by_name=True)

    valid: bool = Field(..., description="Le KYC est valide")
    status: KYCStatus = Field(..., description="Statut du KYC")
    reason: Optional[str] = Field(None, description="Raison du rejet/demande de révision")
    kyc_data: Optional[KYCData] = Field(None, description="Données KYC extraites")
    liveness: Optional[LivenessCheck] = Field(None, description="Résultat liveness check")
    fraud_indicators: Optional[FraudIndicators] = Field(None, description="Indicateurs de fraude")
    qr_confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Confiance QR documentaire (0-1)"
    )
    mrz_confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Confiance MRZ documentaire (0-1)"
    )
    document_consistency: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Coherence QR/MRZ globale (0-1)"
    )
    source_checks: Optional[Dict[str, Any]] = Field(
        None, description="Comparaisons OCR vs QR/MRZ pour l'UI"
    )
    qr_data: Optional[Dict[str, Any]] = Field(
        None, description="Identite extraite du QR (pour backend APS)"
    )
    mrz_data: Optional[Dict[str, Any]] = Field(
        None, description="Identite extraite de la MRZ (pour backend APS)"
    )
    kyc_score: int = Field(
        ...,
        ge=0,
        le=1000,
        validation_alias=AliasChoices("kyc_score", "simba_score"),
        description="Score KYC explicable (0-1000)",
    )
    recommendation: str = Field(..., description="Recommandation (AUTO_APPROVE/MANUAL_REVIEW/AUTO_REJECT)")
