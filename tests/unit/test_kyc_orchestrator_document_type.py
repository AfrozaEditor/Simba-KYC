from datetime import date

import pytest

from app.core.models.kyc_result import DocumentType, KYCData
from app.services.kyc_orchestrator import KYCOrchestrator


def _kyc_data(document_type: DocumentType) -> KYCData:
    return KYCData(
        full_name="JEDIDIA KAMDEM SOUOP",
        first_name="JEDIDIA",
        last_name="KAMDEM SOUOP",
        date_of_birth=date(2007, 5, 27),
        national_id="AB02485821",
        document_type=document_type,
        country="CMR",
    )


@pytest.mark.unit
def test_cni_cameroon_does_not_require_external_mrz_face() -> None:
    assert KYCOrchestrator._expects_mrz_document(_kyc_data(DocumentType.CNI_CAMEROON)) is False


@pytest.mark.unit
def test_passport_requires_external_mrz_face() -> None:
    assert KYCOrchestrator._expects_mrz_document(_kyc_data(DocumentType.PASSPORT)) is True


@pytest.mark.unit
def test_raw_document_type_values_follow_same_rule() -> None:
    assert KYCOrchestrator._expects_mrz_document({"document_type": "CNI_CAMEROON"}) is False
    assert KYCOrchestrator._expects_mrz_document({"document_type": "DocumentType.CNI_CAMEROON"}) is False
    assert KYCOrchestrator._expects_mrz_document({"document_type": "PASSPORT"}) is True
    assert KYCOrchestrator._expects_mrz_document({"document_type": "DocumentType.PASSPORT"}) is True
