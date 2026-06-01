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
    "document_type": "PASSPORT",
    "full_name": "ANNA MARIA ERIKSSON",
    "first_name": "ANNA MARIA",
    "last_name": "ERIKSSON",
    "national_id": "L898902C3",
    "date_of_birth": date(1974, 8, 12),
    "expiry_date": date(2012, 4, 15),
}

BASE_MRZ_VALID = {
    "expected": True,
    "detected": True,
    "parseable": True,
    "format": "TD3",
    "parsed_fields": {
        "document_number": "L898902C3",
        "date_of_birth": "1974-08-12",
        "expiry_date": "2012-04-15",
        "full_name": "ANNA MARIA ERIKSSON",
    },
    "checksums": {
        "document_number": {"available": True, "valid": True, "expected": "6", "computed": "6"},
        "date_of_birth": {"available": True, "valid": True, "expected": "2", "computed": "2"},
        "expiry_date": {"available": True, "valid": True, "expected": "9", "computed": "9"},
        "composite": {"available": True, "valid": True, "expected": "0", "computed": "0"},
    },
}


def _run_indicators(
    *,
    metadata: Optional[Dict[str, Any]] = None,
    kyc_data: Optional[Dict[str, Any]] = None,
    mrz_analysis: Optional[Dict[str, Any]] = None,
    qr_analysis: Optional[Dict[str, Any]] = None,
):
    detector = FraudDetector()
    payload_metadata = metadata or dict(BASE_METADATA)
    payload_kyc_data = kyc_data or dict(BASE_KYC_DATA)
    payload_mrz_analysis = mrz_analysis or dict(BASE_MRZ_VALID)
    payload_qr_analysis = qr_analysis or {"detected": False}

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
            mrz_analysis=payload_mrz_analysis,
        )
    )


def _criteria_ids(indicators) -> set[str]:
    return {criterion.criterion_id for criterion in indicators.criteria_results}


@pytest.mark.unit
def test_af054_info_triggered_when_mrz_expected_but_missing() -> None:
    indicators = _run_indicators(
        mrz_analysis={
            "expected": True,
            "detected": False,
            "parseable": False,
            "error": "mrz_not_detected",
            "checksums": {},
            "parsed_fields": {},
        }
    )

    assert "AF-054" in _criteria_ids(indicators)


@pytest.mark.unit
def test_af055_manual_review_when_mrz_detected_but_not_parseable() -> None:
    indicators = _run_indicators(
        mrz_analysis={
            "expected": True,
            "detected": True,
            "parseable": False,
            "raw_lines": ["P<INVALID"],
            "error": "mrz_not_parseable",
            "checksums": {},
            "parsed_fields": {},
        }
    )

    assert "AF-055" in indicators.manual_review_criteria


@pytest.mark.unit
def test_af056_triggered_when_document_number_checksum_invalid() -> None:
    mrz = dict(BASE_MRZ_VALID)
    mrz["checksums"] = dict(BASE_MRZ_VALID["checksums"])
    mrz["checksums"]["document_number"] = {"available": True, "valid": False, "expected": "6", "computed": "0"}

    indicators = _run_indicators(mrz_analysis=mrz)

    assert "AF-056" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af057_triggered_when_birth_checksum_invalid() -> None:
    mrz = dict(BASE_MRZ_VALID)
    mrz["checksums"] = dict(BASE_MRZ_VALID["checksums"])
    mrz["checksums"]["date_of_birth"] = {"available": True, "valid": False, "expected": "2", "computed": "7"}

    indicators = _run_indicators(mrz_analysis=mrz)

    assert "AF-057" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af058_triggered_when_expiry_checksum_invalid() -> None:
    mrz = dict(BASE_MRZ_VALID)
    mrz["checksums"] = dict(BASE_MRZ_VALID["checksums"])
    mrz["checksums"]["expiry_date"] = {"available": True, "valid": False, "expected": "9", "computed": "3"}

    indicators = _run_indicators(mrz_analysis=mrz)

    assert "AF-058" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af059_triggered_when_composite_checksum_invalid() -> None:
    mrz = dict(BASE_MRZ_VALID)
    mrz["checksums"] = dict(BASE_MRZ_VALID["checksums"])
    mrz["checksums"]["composite"] = {"available": True, "valid": False, "expected": "0", "computed": "8"}

    indicators = _run_indicators(mrz_analysis=mrz)

    assert "AF-059" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af061_triggered_when_mrz_document_number_mismatch_ocr() -> None:
    indicators = _run_indicators(
        kyc_data={
            **BASE_KYC_DATA,
            "national_id": "X00000000",
        }
    )

    assert "AF-061" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af062_triggered_when_mrz_dates_mismatch_ocr() -> None:
    indicators = _run_indicators(
        kyc_data={
            **BASE_KYC_DATA,
            "date_of_birth": date(1975, 8, 12),
        }
    )

    assert "AF-062" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af060_triggered_when_mrz_name_mismatch_ocr() -> None:
    indicators = _run_indicators(
        kyc_data={
            **BASE_KYC_DATA,
            "full_name": "JOHN DOE",
            "first_name": "JOHN",
            "last_name": "DOE",
        }
    )

    assert "AF-060" in indicators.manual_review_criteria


@pytest.mark.unit
def test_af070_triggered_when_qr_mrz_identity_mismatch() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "parsed_fields": {
                "full_name": "ANNA MARIA ERIKSSON",
                "national_id": "X12345678",
                "date_of_birth": "1974-08-12",
            },
        }
    )

    assert "AF-070" in indicators.hard_reject_criteria


@pytest.mark.unit
def test_af070_not_triggered_when_qr_mrz_are_coherent() -> None:
    indicators = _run_indicators(
        qr_analysis={
            "detected": True,
            "parsed_fields": {
                "full_name": "ANNA MARIA ERIKSSON",
                "national_id": "L898902C3",
                "date_of_birth": "1974-08-12",
            },
        }
    )

    assert "AF-070" not in indicators.hard_reject_criteria


@pytest.mark.unit
def test_mrz_coherent_does_not_trigger_af056_to_af062() -> None:
    indicators = _run_indicators()

    assert "AF-056" not in indicators.hard_reject_criteria
    assert "AF-057" not in indicators.hard_reject_criteria
    assert "AF-058" not in indicators.hard_reject_criteria
    assert "AF-059" not in indicators.hard_reject_criteria
    assert "AF-061" not in indicators.hard_reject_criteria
    assert "AF-062" not in indicators.hard_reject_criteria


@pytest.mark.unit
def test_cni_with_incompatible_mrz_format_avoids_hard_reject_mrz_checks() -> None:
    indicators = _run_indicators(
        kyc_data={
            "document_type": "CNI_CAMEROON",
            "full_name": "AQIL BELL",
            "first_name": "AQIL",
            "last_name": "BELL",
            "national_id": "AB05011462",
            "date_of_birth": date(2005, 8, 3),
            "expiry_date": date(2036, 4, 9),
        },
        qr_analysis={
            "detected": True,
            "parsed_fields": {
                "full_name": "AQIL BELL",
                "national_id": "AB05011462",
                "date_of_birth": "2005-08-03",
            },
        },
        mrz_analysis={
            "expected": True,
            "detected": True,
            "parseable": True,
            "format": "TD3",
            "parsed_fields": {
                "document_number": "0508034M3",
                "date_of_birth": None,
                "expiry_date": None,
                "full_name": "1019127762AB05011462",
            },
            "checksums": {
                "document_number": {"available": True, "valid": False, "expected": "6", "computed": "1"},
                "date_of_birth": {"available": False, "valid": None, "expected": "<", "computed": None},
                "expiry_date": {"available": False, "valid": None, "expected": "<", "computed": None},
                "composite": {"available": False, "valid": None, "expected": "<", "computed": None},
            },
        },
    )

    assert "AF-056" not in indicators.hard_reject_criteria
    assert "AF-061" not in indicators.hard_reject_criteria
    assert "AF-070" not in indicators.hard_reject_criteria
    assert "AF-055" in indicators.manual_review_criteria


@pytest.mark.unit
def test_cni_with_unexpected_detected_mrz_keeps_mrz_advisory() -> None:
    indicators = _run_indicators(
        kyc_data={
            "document_type": "CNI_CAMEROON",
            "full_name": "JEDIDIA KAMDEM SOUOP",
            "first_name": "JEDIDIA",
            "last_name": "KAMDEM SOUOP",
            "national_id": "AB02485921",
            "date_of_birth": date(2007, 5, 27),
            "expiry_date": date(2036, 4, 9),
        },
        qr_analysis={
            "detected": True,
            "parsed_fields": {
                "full_name": "JEDIDIA KAMDEM SOUOP",
                "national_id": "AB02485921",
                "date_of_birth": "2007-05-27",
            },
        },
        mrz_analysis={
            "expected": False,
            "detected": True,
            "parseable": True,
            "format": "TD1",
            "parsed_fields": {
                "document_number": "WRONG123",
                "date_of_birth": "2007-05-27",
                "full_name": "JEDIDIA KAMDEM SOUOP",
            },
            "checksums": {
                "document_number": {"available": True, "valid": False, "expected": "6", "computed": "1"},
                "date_of_birth": {"available": True, "valid": False, "expected": "2", "computed": "7"},
                "expiry_date": {"available": False, "valid": None},
                "composite": {"available": False, "valid": None},
            },
        },
    )

    assert "AF-056" not in indicators.hard_reject_criteria
    assert "AF-057" not in indicators.hard_reject_criteria
    assert "AF-061" not in indicators.hard_reject_criteria
    assert "AF-070" not in indicators.hard_reject_criteria
