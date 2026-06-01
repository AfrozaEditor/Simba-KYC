"""Document consistency scoring for QR/MRZ sources."""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from app.core.models.fraud_indicators import FraudCriterionResult, FraudCriterionStatus

QR_WEIGHTS = {
    "prefix_valid": 0.10,
    "base32_valid": 0.20,
    "decompression_valid": 0.25,
    "required_fields_present": 0.35,
    "signature_present": 0.10,
}

MRZ_CHECK_WEIGHTS = {
    "document_number": 0.20,
    "date_of_birth": 0.20,
    "expiry_date": 0.20,
    "composite": 0.20,
}

MAJOR_CONSISTENCY_CRITERIA = {
    "AF-054",
    "AF-055",
    "AF-056",
    "AF-057",
    "AF-058",
    "AF-059",
    "AF-060",
    "AF-061",
    "AF-062",
    "AF-063",
    "AF-065",
    "AF-066",
    "AF-068",
    "AF-069",
    "AF-070",
}


def calculate_qr_confidence(qr_analysis: Optional[Dict[str, Any]]) -> float:
    """Calculate a QR confidence score in [0,1]."""

    if not qr_analysis or not qr_analysis.get("detected"):
        return 0.0

    score = 0.0
    for key, weight in QR_WEIGHTS.items():
        value = qr_analysis.get(key)
        if value is True:
            score += weight
        elif value is None:
            score += weight * 0.5

    return round(min(max(score, 0.0), 1.0), 2)


def calculate_mrz_confidence(mrz_analysis: Optional[Dict[str, Any]]) -> float:
    """Calculate a MRZ confidence score in [0,1]."""

    if not mrz_analysis or not mrz_analysis.get("detected"):
        return 0.0

    if not mrz_analysis.get("parseable"):
        return 0.25

    checks = mrz_analysis.get("checksums") or {}

    score = 0.20
    for key, weight in MRZ_CHECK_WEIGHTS.items():
        check = checks.get(key) or {}
        available = check.get("available") is True
        valid = check.get("valid") is True

        if available:
            score += weight if valid else 0.0
        else:
            score += weight * 0.5

    return round(min(max(score, 0.0), 1.0), 2)


def compute_document_consistency(
    *,
    qr_analysis: Optional[Dict[str, Any]] = None,
    mrz_analysis: Optional[Dict[str, Any]] = None,
    criteria_results: Optional[Sequence[FraudCriterionResult]] = None,
    bonus_cap: int = 100,
) -> Dict[str, float]:
    """Compute QR/MRZ consistency confidence and bonus."""

    qr_confidence = calculate_qr_confidence(qr_analysis)
    mrz_confidence = calculate_mrz_confidence(mrz_analysis)

    qr_available = bool(qr_analysis and qr_analysis.get("detected"))
    mrz_available = bool(mrz_analysis and mrz_analysis.get("detected") and mrz_analysis.get("parseable"))

    document_consistency = 0.0
    bonus_ratio = 0.0

    if qr_available and mrz_available:
        document_consistency = round((qr_confidence + mrz_confidence) / 2, 2)
        bonus_ratio = document_consistency
    elif qr_available:
        document_consistency = round(qr_confidence, 2)
        bonus_ratio = document_consistency * 0.5
    elif mrz_available:
        document_consistency = round(mrz_confidence, 2)
        bonus_ratio = document_consistency * 0.5

    bonus = int(round(bonus_cap * bonus_ratio))
    if _has_major_consistency_failure(criteria_results):
        bonus = 0

    return {
        "qr_confidence": qr_confidence,
        "mrz_confidence": mrz_confidence,
        "document_consistency": document_consistency,
        "consistency_bonus": bonus,
    }


def _has_major_consistency_failure(
    criteria_results: Optional[Sequence[FraudCriterionResult]],
) -> bool:
    if not criteria_results:
        return False

    for result in criteria_results:
        if result.criterion_id in MAJOR_CONSISTENCY_CRITERIA:
            if result.status == FraudCriterionStatus.FAIL:
                return True
    return False
