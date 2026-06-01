import asyncio
from datetime import date, datetime, timezone

import pytest

from app.core.rules.kyc_rules import KYCRules
from app.services.fraud_criteria_engine import FraudCriteriaEngine
from app.services.fraud_detector import FraudDetector


@pytest.mark.unit
def test_af063_not_triggered_when_back_not_provided() -> None:
    engine = FraudCriteriaEngine()

    results = engine.evaluate(
        document_front_base64="A" * 2000,
        selfie_base64="B" * 2000,
        liveness_confidence=0.95,
        face_match_score=0.95,
        document_integrity=0.90,
        fraud_flags=[],
        metadata={
            "device_id": "device-1",
            "ip_address": "127.0.0.1",
            "timestamp": "2026-04-25T12:00:00+00:00",
            "app_version": "1.0.0",
        },
        liveness_quality_score=0.95,
        liveness_flags=[],
        liveness_face_count=1,
        kyc_data={
            "document_type": "CNI_CAMEROON",
            "national_id": "CM123456789",
            "date_of_birth": date(1990, 1, 1),
            "full_name": "MAMADOU DIALLO",
        },
        qr_analysis={"detected": False, "error": "not_found", "back_provided": False},
        mrz_analysis={"expected": False, "detected": False},
    )

    criteria_ids = {criterion.criterion_id for criterion in results}
    assert "AF-063" not in criteria_ids


@pytest.mark.unit
def test_ambiguous_visual_flags_suppressed_with_strong_biometrics() -> None:
    engine = FraudCriteriaEngine()

    results = engine.evaluate(
        document_front_base64="A" * 2000,
        selfie_base64="B" * 2000,
        liveness_confidence=0.94,
        face_match_score=0.96,
        document_integrity=0.40,
        fraud_flags=["document_tampered_suspected", "document_fake_suspected"],
        metadata={
            "device_id": "device-1",
            "ip_address": "127.0.0.1",
            "timestamp": "2026-04-25T12:00:00+00:00",
            "app_version": "1.0.0",
        },
        liveness_quality_score=0.95,
        liveness_flags=[],
        liveness_face_count=1,
        kyc_data={"document_type": "CNI_CAMEROON"},
        qr_analysis={"detected": False, "back_provided": False},
        mrz_analysis={"expected": False, "detected": False},
    )

    criteria_ids = {criterion.criterion_id for criterion in results}
    assert "AF-037" not in criteria_ids
    assert "AF-042" not in criteria_ids
    assert "AF-043" not in criteria_ids


@pytest.mark.unit
def test_detector_maps_generic_suspicious_labels_to_non_blocking() -> None:
    class _FakeLiveness:
        async def detect_spoof_attempts(self, _selfie: str):
            return {
                "is_spoofed": False,
                "spoof_confidence": 0.0,
                "spoof_type": None,
                "flags": ["suspicious_document", "suspicious_text"],
            }

    detector = FraudDetector(ocr_service=None, liveness_service=_FakeLiveness())

    flags = asyncio.run(
        detector._detect_fraud_flags(
            document_base64="A" * 2000,
            selfie_base64="B" * 2000,
            liveness_confidence=0.95,
            face_match_score=0.95,
            document_integrity_result={
                "integrity_score": 0.90,
                "is_tampered": False,
                "is_fake": False,
            },
        )
    )

    assert "liveness_suspicious" not in flags


@pytest.mark.unit
def test_detector_clears_ambiguous_document_flags_without_manual_criteria() -> None:
    class _FakeLiveness:
        async def detect_spoof_attempts(self, _selfie: str):
            return {
                "is_spoofed": False,
                "spoof_confidence": 0.0,
                "spoof_type": None,
                "flags": [],
            }

    class _FakeOcr:
        async def analyze_document_integrity(self, _document_base64: str):
            return {
                "integrity_score": 0.40,
                "is_tampered": True,
                "is_fake": True,
                "warnings": [],
            }

    detector = FraudDetector(ocr_service=_FakeOcr(), liveness_service=_FakeLiveness())

    indicators = asyncio.run(
        detector.analyze_fraud_indicators(
            document_front_base64="A" * 2000,
            selfie_base64="B" * 2000,
            liveness_confidence=0.94,
            face_match_score=0.96,
            metadata={
                "device_id": "device-1",
                "ip_address": "127.0.0.1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "app_version": "1.0.0",
            },
            liveness_quality_score=0.95,
            liveness_flags=[],
            liveness_face_count=1,
            kyc_data={"document_type": "CNI_CAMEROON"},
            qr_analysis={"detected": True, "back_provided": True, "prefix_valid": True},
            mrz_analysis={"expected": False, "detected": False},
        )
    )

    assert "document_fake_suspected" not in indicators.flags
    assert "document_tampered_suspected" not in indicators.flags


@pytest.mark.unit
def test_manual_review_reason_uses_human_readable_criterion_reason() -> None:
    from app.core.models.fraud_indicators import FraudCriterionLevel, FraudCriterionResult, FraudCriterionStatus, FraudIndicators
    from app.core.models.kyc_result import LivenessCheck
    from app.services.kyc_orchestrator import KYCOrchestrator

    fraud_indicators = FraudIndicators(
        document_integrity=0.40,
        face_match_score=0.96,
        is_suspicious=True,
        flags=["document_fake_suspected", "document_tampered_suspected", "manual_review_criteria_detected"],
        criteria_results=[
            FraudCriterionResult(
                criterion_id="AF-055",
                status=FraudCriterionStatus.FAIL,
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-110,
                reason="MRZ detectee mais non parseable.",
                evidence={"mrz_error": "invalid"},
            )
        ],
        hard_reject_criteria=[],
        manual_review_criteria=["AF-055"],
    )

    reason = KYCOrchestrator._derive_rejection_reason(
        status="MANUAL_REVIEW",
        liveness=LivenessCheck(passed=True, confidence=0.96, method="dummy", spoof_score=0.0, quality_score=1.0, flags=[], face_count=1),
        face_match_score=0.96,
        fraud_indicators=fraud_indicators,
    )

    assert reason == "Revue manuelle requise: MRZ detectee mais non parseable."


@pytest.mark.unit
def test_kyc_rules_auto_approve_strong_biometrics_on_moderate_integrity() -> None:
    status, recommendation = KYCRules.determine_kyc_status(
        valid=True,
        liveness_passed=True,
        liveness_confidence=0.93,
        face_match_score=0.95,
        document_integrity=0.40,
        fraud_flags=[],
        kyc_score=760,
        hard_reject_criteria=[],
        manual_review_criteria=[],
    )

    assert status == "APPROVED"
    assert recommendation == "AUTO_APPROVE"
