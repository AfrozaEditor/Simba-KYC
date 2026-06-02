from datetime import date

from app.core.models.kyc_result import DocumentType, KYCData
from app.services.kyc_orchestrator import KYCOrchestrator


def _kyc_data(full_name="AQIL BELL"):
    return KYCData(
        full_name=full_name,
        first_name="AQIL",
        last_name="BELL",
        date_of_birth=date(2005, 8, 3),
        national_id="AB05011462",
        document_type=DocumentType.CNI_CAMEROON,
        expiry_date=date(2036, 4, 9),
        country="CM",
    )


def test_source_checks_compare_ocr_name_with_mobile_money_identity():
    orchestrator = KYCOrchestrator()

    checks = orchestrator._build_source_checks(
        kyc_data=_kyc_data(),
        qr_analysis={},
        mrz_analysis={},
        mobile_money_identity={"mobile_money_full_name": "AQIL BELL"},
    )

    assert checks["ocr_vs_mobile_money"]["status"] == "matched"
    assert checks["ocr_vs_mobile_money"]["checked_fields"] == ["full_name"]


def test_source_checks_flag_mobile_money_name_mismatch():
    orchestrator = KYCOrchestrator()

    checks = orchestrator._build_source_checks(
        kyc_data=_kyc_data(),
        qr_analysis={},
        mrz_analysis={},
        mobile_money_identity={"mobile_money_full_name": "OTHER NAME"},
    )

    assert checks["ocr_vs_mobile_money"]["status"] == "mismatch"
    assert checks["ocr_vs_mobile_money"]["field_issues"][0]["field"] == "full_name"
