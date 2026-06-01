import asyncio
from datetime import date
from typing import Any, Dict, Optional

import pytest

from app.services.fraud_detector import FraudDetector


BASE_METADATA = {
    "device_id": "device-1",
    "ip_address": "192.168.0.10",
    "timestamp": "2026-04-24T12:00:00+00:00",
    "app_version": "1.0.0",
}

BASE_KYC_DATA = {
    "document_type": "CNI_CAMEROON",
    "full_name": "MAMADOU DIALLO",
    "first_name": "MAMADOU",
    "last_name": "DIALLO",
    "national_id": "CM987654321",
    "date_of_birth": date(1992, 3, 15),
}

BASE_QR_VALID = {
    "detected": True,
    "prefix_valid": True,
    "base32_valid": True,
    "decompression_valid": True,
    "required_fields_present": True,
    "parsed_fields": {
        "full_name": "MAMADOU DIALLO",
        "national_id": "CM987654321",
        "date_of_birth": "1992-03-15",
    },
}


def _run_indicators(
    *,
    metadata: Optional[Dict[str, Any]] = None,
    kyc_data: Optional[Dict[str, Any]] = None,
    qr_analysis: Optional[Dict[str, Any]] = None,
):
    detector = FraudDetector()
    payload_metadata = metadata or dict(BASE_METADATA)
    payload_kyc_data = kyc_data or dict(BASE_KYC_DATA)
    payload_qr_analysis = qr_analysis or dict(BASE_QR_VALID)

    return asyncio.run(
        detector.analyze_fraud_indicators(
            document_front_base64="A" * 1200,
            selfie_base64="B" * 1200,
            liveness_confidence=0.95,
            face_match_score=0.92,
            metadata=payload_metadata,
            liveness_quality_score=0.95,
            liveness_flags=[],
            liveness_face_count=1,
            kyc_data=payload_kyc_data,
            qr_analysis=payload_qr_analysis,
        )
    )


def _criteria_ids(indicators) -> set[str]:
    return {criterion.criterion_id for criterion in indicators.criteria_results}


@pytest.mark.unit
def test_af063_triggered_when_qr_missing_for_cni() -> None:
    indicators = _run_indicators(
        qr_analysis={"detected": False, "error": "not_found", "back_provided": True}
    )

    assert "AF-063" in indicators.manual_review_criteria
    assert "AF-069" not in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af069_triggered_on_qr_ocr_identity_mismatch() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "prefix_valid": True,
            "base32_valid": True,
            "decompression_valid": True,
            "required_fields_present": True,
            "parsed_fields": {
                "full_name": "MAMADOU DIALLO",
                "national_id": "CM000000000",
                "date_of_birth": "1992-03-15",
            },
        }
    )

    assert "AF-069" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_qr_coherent_identity_does_not_trigger_af069() -> None:
    indicators = _run_indicators(qr_analysis=BASE_QR_VALID)

    assert "AF-069" not in indicators.hard_reject_criteria
    assert "AF-063" not in indicators.manual_review_criteria


@pytest.mark.unit
def test_af063_not_triggered_for_passport_without_qr() -> None:
    indicators = _run_indicators(
        kyc_data={
            "document_type": "PASSPORT",
            "national_id": "P1234567",
            "date_of_birth": date(1992, 3, 15),
        },
        qr_analysis={"detected": False, "error": "not_found"},
    )

    assert "AF-063" not in indicators.manual_review_criteria


@pytest.mark.unit
def test_af064_info_criterion_on_invalid_prefix() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "prefix_valid": False,
            "base32_valid": True,
            "decompression_valid": True,
            "required_fields_present": True,
            "parsed_fields": dict(BASE_QR_VALID["parsed_fields"]),
        }
    )

    assert "AF-064" in _criteria_ids(indicators)
    assert "AF-064" not in indicators.manual_review_criteria
    assert "AF-064" not in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af065_triggered_when_base32_invalid() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "prefix_valid": True,
            "base32_valid": False,
            "decompression_valid": True,
            "required_fields_present": True,
            "parsed_fields": dict(BASE_QR_VALID["parsed_fields"]),
        }
    )

    assert "AF-065" in indicators.manual_review_criteria


@pytest.mark.unit
def test_af066_triggered_when_decompression_invalid() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "prefix_valid": True,
            "base32_valid": True,
            "decompression_valid": False,
            "required_fields_present": True,
            "parsed_fields": dict(BASE_QR_VALID["parsed_fields"]),
        }
    )

    assert "AF-066" in indicators.manual_review_criteria


@pytest.mark.unit
def test_af068_triggered_when_required_fields_missing() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "prefix_valid": True,
            "base32_valid": True,
            "decompression_valid": True,
            "required_fields_present": False,
            "parsed_fields": {"full_name": "MAMADOU DIALLO"},
        }
    )

    assert "AF-068" in indicators.manual_review_criteria


@pytest.mark.unit
def test_af069_triggered_on_qr_ocr_date_of_birth_mismatch() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "prefix_valid": True,
            "base32_valid": True,
            "decompression_valid": True,
            "required_fields_present": True,
            "parsed_fields": {
                "full_name": "MAMADOU DIALLO",
                "national_id": "CM987654321",
                "date_of_birth": "1991-03-15",
            },
        }
    )

    assert "AF-069" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af069_triggered_on_qr_ocr_full_name_mismatch() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "prefix_valid": True,
            "base32_valid": True,
            "decompression_valid": True,
            "required_fields_present": True,
            "parsed_fields": {
                "full_name": "JEAN DUPONT",
                "national_id": "CM987654321",
                "date_of_birth": "1992-03-15",
            },
        }
    )

    assert "AF-069" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af069_not_triggered_when_name_tokens_match_with_different_order() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "prefix_valid": True,
            "base32_valid": True,
            "decompression_valid": True,
            "required_fields_present": True,
            "parsed_fields": {
                "full_name": "DIALLO MAMADOU",
                "national_id": "CM987654321",
                "date_of_birth": "1992-03-15",
            },
        }
    )

    assert "AF-069" not in indicators.hard_reject_criteria
