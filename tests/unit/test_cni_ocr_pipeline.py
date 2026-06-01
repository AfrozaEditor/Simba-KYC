import asyncio
from datetime import date

import pytest

from app.services.cni_ocr_runtime import extract_document_ocr
from app.services.cni_ocr_postprocessor import merge_cni_ocr_fields, sanitize_cni_ocr_fields
from app.services.kyc_orchestrator import KYCOrchestrator


class _FakeCniOcr:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    async def extract_from_image(
        self,
        image_base64: str,
        document_type: str = "CNI_CAMEROON",
        document_side: str | None = None,
    ) -> dict:
        assert image_base64
        self.calls.append((document_type, document_side))

        if document_type != "CNI_CAMEROON":
            return {
                "success": True,
                "provider": "fake-ocr",
                "confidence": 0.61,
                "detected_fields": {
                    "document_number": "P1234567",
                    "full_name": "ALICE DOE",
                },
                "warnings": [],
                "raw_response": '{"document_number":"P1234567"}',
            }

        if document_side == "front":
            return {
                "success": True,
                "provider": "fake-ocr",
                "confidence": 0.72,
                "detected_fields": {
                    "document_type": "CNI_CAMEROON",
                    "country": "CM",
                    "document_side": "front",
                    "full_name": "BELLE AQIL",
                    "first_name": "AQIL",
                    "last_name": "BELL",
                    "date_of_birth": "03.08.2005",
                    "gender": "M",
                    "expiry_date": "09.04.2036",
                    "national_id": "1019127762",
                },
                "warnings": [],
                "raw_response": '{"document_side":"front"}',
            }

        if document_side == "back":
            return {
                "success": True,
                "provider": "fake-ocr",
                "confidence": 0.84,
                "detected_fields": {
                    "document_type": "CNI_CAMEROON",
                    "country": "CM",
                    "document_side": "back",
                    "national_id": "AB05011462",
                    "father_name": "MBOUGAM ALI",
                    "mother_name": "PENZIE AMINATOU",
                    "place_of_birth": "FOUMBAN",
                    "profession": "ETUDIANT-E-",
                    "issue_date": "09.04.2026",
                    "height": "1.7 m",
                },
                "warnings": [],
                "raw_response": '{"document_side":"back"}',
            }

        raise AssertionError(f"unexpected side: {document_side}")


@pytest.mark.unit
def test_sanitize_cni_front_ignores_serial_number_near_photo() -> None:
    cleaned, warnings = sanitize_cni_ocr_fields(
        {
            "document_side": "front",
            "national_id": "1019127762",
            "full_name": "BELLE AQIL",
            "first_name": "AQIL",
            "last_name": "BELL",
            "date_of_birth": "03.08.2005",
            "expiry_date": "09.04.2036",
            "gender": "M",
        },
        document_side="front",
    )

    assert cleaned["national_id"] == ""
    assert cleaned["full_name"] == "AQIL BELL"
    assert cleaned["date_of_birth"] == "2005-08-03"
    assert cleaned["expiry_date"] == "2036-04-09"
    assert "front_serial_not_national_id_ignored" in warnings


@pytest.mark.unit
def test_sanitize_cni_back_does_not_confuse_parent_name_with_holder_name() -> None:
    cleaned, warnings = sanitize_cni_ocr_fields(
        {
            "document_side": "back",
            "full_name": "MBOUGAM ALI",
            "father_name": "MBOUGAM ALI",
            "mother_name": "PENZIE AMINATOU",
            "national_id": "AB05011462",
        },
        document_side="back",
    )

    assert cleaned["full_name"] == ""
    assert cleaned["national_id"] == "AB05011462"
    assert "back_parent_name_not_holder_name" in warnings


@pytest.mark.unit
def test_merge_cni_ocr_fields_prefers_recto_identity_and_verso_national_id() -> None:
    merged, warnings = merge_cni_ocr_fields(
        {
            "document_side": "front",
            "full_name": "BELLE AQIL",
            "first_name": "AQIL",
            "last_name": "BELL",
            "date_of_birth": "03.08.2005",
            "gender": "M",
            "expiry_date": "09.04.2036",
            "national_id": "1019127762",
        },
        {
            "document_side": "back",
            "national_id": "AB05011462",
            "father_name": "MBOUGAM ALI",
            "mother_name": "PENZIE AMINATOU",
            "place_of_birth": "FOUMBAN",
            "profession": "ETUDIANT-E-",
            "issue_date": "09.04.2026",
            "height": "1.7 m",
        },
    )

    assert merged["full_name"] == "AQIL BELL"
    assert merged["first_name"] == "AQIL"
    assert merged["last_name"] == "BELL"
    assert merged["national_id"] == "AB05011462"
    assert merged["father_name"] == "MBOUGAM ALI"
    assert merged["mother_name"] == "PENZIE AMINATOU"
    assert "front_serial_not_national_id_ignored" in warnings


@pytest.mark.unit
def test_extract_document_ocr_front_only_sanitizes_recto_fields() -> None:
    ocr = _FakeCniOcr()

    result = asyncio.run(
        extract_document_ocr(
            ocr,
            image_base64="front-image",
            document_type="CNI_CAMEROON",
            document_side="front",
        )
    )

    assert result["success"] is True
    assert result["detected_fields"]["national_id"] == ""
    assert result["detected_fields"]["full_name"] == "AQIL BELL"
    assert result["warnings"] == ["front_serial_not_national_id_ignored"]
    assert result["confidence"] >= 0.9
    assert ocr.calls == [("CNI_CAMEROON", "front")]


@pytest.mark.unit
def test_extract_document_ocr_merges_front_and_back_for_cni() -> None:
    ocr = _FakeCniOcr()

    result = asyncio.run(
        extract_document_ocr(
            ocr,
            image_base64="front-image",
            image_back_base64="back-image",
            document_type="CNI_CAMEROON",
        )
    )

    assert result["success"] is True
    assert result["detected_fields"]["full_name"] == "AQIL BELL"
    assert result["detected_fields"]["national_id"] == "AB05011462"
    assert result["detected_fields"]["father_name"] == "MBOUGAM ALI"
    assert result["warnings"] == ["front_serial_not_national_id_ignored"]
    assert result["confidence"] >= 0.9
    assert ocr.calls == [("CNI_CAMEROON", "front"), ("CNI_CAMEROON", "back")]


@pytest.mark.unit
def test_extract_document_ocr_back_only_uses_back_side_fields() -> None:
    ocr = _FakeCniOcr()

    result = asyncio.run(
        extract_document_ocr(
            ocr,
            image_base64="back-image",
            document_type="CNI_CAMEROON",
            document_side="back",
        )
    )

    assert result["success"] is True
    assert result["detected_fields"]["national_id"] == "AB05011462"
    assert result["detected_fields"]["father_name"] == "MBOUGAM ALI"
    assert result["detected_fields"].get("full_name", "") == ""
    assert result["confidence"] >= 0.9
    assert ocr.calls == [("CNI_CAMEROON", "back")]


@pytest.mark.unit
def test_extract_document_ocr_keeps_non_cni_passthrough() -> None:
    ocr = _FakeCniOcr()

    result = asyncio.run(
        extract_document_ocr(
            ocr,
            image_base64="passport-image",
            document_type="PASSPORT",
        )
    )

    assert result["success"] is True
    assert result["detected_fields"]["document_number"] == "P1234567"
    assert result["detected_fields"]["full_name"] == "ALICE DOE"
    assert ocr.calls == [("PASSPORT", None)]


@pytest.mark.unit
def test_orchestrator_extracts_cni_data_from_front_and_back() -> None:
    orchestrator = KYCOrchestrator(ocr_service=_FakeCniOcr(), liveness_service=None)

    kyc_data = asyncio.run(orchestrator._extract_kyc_data("front-image", "back-image"))

    assert kyc_data is not None
    assert kyc_data.full_name == "AQIL BELL"
    assert kyc_data.first_name == "AQIL"
    assert kyc_data.last_name == "BELL"
    assert kyc_data.national_id == "AB05011462"
    assert kyc_data.date_of_birth == date(2005, 8, 3)
    assert kyc_data.expiry_date == date(2036, 4, 9)
    assert orchestrator._last_ocr_result is not None
    assert orchestrator._last_ocr_result["detected_fields"]["father_name"] == "MBOUGAM ALI"
    assert orchestrator._last_ocr_result["detected_fields"]["mother_name"] == "PENZIE AMINATOU"
