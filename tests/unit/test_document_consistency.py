import pytest

from app.core.models.fraud_indicators import (
    FraudCriterionLevel,
    FraudCriterionResult,
    FraudCriterionStatus,
)
from app.services.document_consistency import (
    calculate_mrz_confidence,
    calculate_qr_confidence,
    compute_document_consistency,
)


@pytest.mark.unit
def test_qr_confidence_full_when_all_checks_pass() -> None:
    qr_analysis = {
        "detected": True,
        "prefix_valid": True,
        "base32_valid": True,
        "decompression_valid": True,
        "required_fields_present": True,
        "signature_present": True,
    }

    assert calculate_qr_confidence(qr_analysis) == 1.0


@pytest.mark.unit
def test_mrz_confidence_full_when_all_checks_pass() -> None:
    mrz_analysis = {
        "detected": True,
        "parseable": True,
        "checksums": {
            "document_number": {"available": True, "valid": True},
            "date_of_birth": {"available": True, "valid": True},
            "expiry_date": {"available": True, "valid": True},
            "composite": {"available": True, "valid": True},
        },
    }

    assert calculate_mrz_confidence(mrz_analysis) == 1.0


@pytest.mark.unit
def test_consistency_bonus_blocked_on_major_criteria() -> None:
    qr_analysis = {
        "detected": True,
        "prefix_valid": True,
        "base32_valid": True,
        "decompression_valid": True,
        "required_fields_present": True,
        "signature_present": True,
    }
    mrz_analysis = {
        "detected": True,
        "parseable": True,
        "checksums": {
            "document_number": {"available": True, "valid": True},
            "date_of_birth": {"available": True, "valid": True},
            "expiry_date": {"available": True, "valid": True},
            "composite": {"available": True, "valid": True},
        },
    }
    criteria_results = [
        FraudCriterionResult(
            criterion_id="AF-069",
            status=FraudCriterionStatus.FAIL,
            level=FraudCriterionLevel.HARD_REJECT,
            score_impact=-240,
            reason="mismatch",
            evidence={},
        )
    ]

    consistency = compute_document_consistency(
        qr_analysis=qr_analysis,
        mrz_analysis=mrz_analysis,
        criteria_results=criteria_results,
        bonus_cap=100,
    )

    assert consistency["document_consistency"] > 0.0
    assert consistency["consistency_bonus"] == 0
