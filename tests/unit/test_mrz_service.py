import pytest

from app.services.mrz_service import MRZService


TD3_LINE_1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
TD3_LINE_2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"


def _replace_char(value: str, index: int, new_char: str) -> str:
    return f"{value[:index]}{new_char}{value[index + 1:]}"


@pytest.mark.unit
def test_analyze_td3_valid_passport_mrz() -> None:
    service = MRZService()

    analysis = service.analyze(mrz_lines=[TD3_LINE_1, TD3_LINE_2], expected=True)

    assert analysis["detected"] is True
    assert analysis["parseable"] is True
    assert analysis["format"] == "TD3"
    assert analysis["checksums"]["document_number"]["valid"] is True
    assert analysis["checksums"]["date_of_birth"]["valid"] is True
    assert analysis["checksums"]["expiry_date"]["valid"] is True
    assert analysis["checksums"]["composite"]["valid"] is True
    assert analysis["parsed_fields"]["document_number"] == "L898902C3"
    assert analysis["parsed_fields"]["date_of_birth"] == "1974-08-12"
    assert analysis["parsed_fields"]["expiry_date"] == "2012-04-15"


@pytest.mark.unit
def test_analyze_detects_invalid_document_number_checksum() -> None:
    service = MRZService()
    invalid_line_2 = _replace_char(TD3_LINE_2, 9, "0")

    analysis = service.analyze(mrz_lines=[TD3_LINE_1, invalid_line_2], expected=True)

    assert analysis["detected"] is True
    assert analysis["parseable"] is True
    assert analysis["checksums"]["document_number"]["available"] is True
    assert analysis["checksums"]["document_number"]["valid"] is False


@pytest.mark.unit
def test_analyze_returns_not_detected_when_expected_but_missing() -> None:
    service = MRZService()

    analysis = service.analyze(mrz_lines=[], raw_text="", expected=True)

    assert analysis["detected"] is False
    assert analysis["parseable"] is False
    assert analysis["error"] == "mrz_not_detected"


@pytest.mark.unit
def test_analyze_parses_mrz_from_raw_text_blob() -> None:
    service = MRZService()
    raw_text = "header line\n" + TD3_LINE_1 + "\n" + TD3_LINE_2 + "\nfooter line"

    analysis = service.analyze(raw_text=raw_text, expected=True)

    assert analysis["detected"] is True
    assert analysis["parseable"] is True
    assert analysis["format"] == "TD3"
    assert analysis["checksums"]["composite"]["valid"] is True


@pytest.mark.unit
def test_analyze_recovers_ocr_numeric_confusions_in_td3() -> None:
    service = MRZService()
    ocr_line_2 = list(TD3_LINE_2)

    # Simule des erreurs OCR courantes sur des champs numeriques
    ocr_line_2[17] = "I"  # 1
    ocr_line_2[25] = "I"  # 1

    analysis = service.analyze(mrz_lines=[TD3_LINE_1, "".join(ocr_line_2)], expected=True)

    assert analysis["detected"] is True
    assert analysis["parseable"] is True
    assert analysis["parsed_fields"]["document_number"] == "L898902C3"
    assert analysis["parsed_fields"]["date_of_birth"] == "1974-08-12"
    assert analysis["parsed_fields"]["expiry_date"] == "2012-04-15"
    assert analysis["checksums"]["document_number"]["valid"] is True
    assert analysis["checksums"]["date_of_birth"]["valid"] is True
    assert analysis["checksums"]["expiry_date"]["valid"] is True


@pytest.mark.unit
def test_analyze_accepts_truncated_td3_lines_from_ocr() -> None:
    service = MRZService()
    raw_text = TD3_LINE_1[:-1] + "\n" + TD3_LINE_2[:-1]

    analysis = service.analyze(raw_text=raw_text, expected=True)

    assert analysis["detected"] is True
    assert analysis["parseable"] is True
    assert analysis["format"] == "TD3"
    assert analysis["checksums"]["document_number"]["valid"] is True
    assert analysis["checksums"]["date_of_birth"]["valid"] is True
    assert analysis["checksums"]["expiry_date"]["valid"] is True
    assert analysis["checksums"]["composite"]["available"] is False


@pytest.mark.unit
def test_analyze_prefers_td1_for_cni_like_lines_with_extra_fillers() -> None:
    service = MRZService()
    cni_like_lines = [
        "I<CMR1019127762AB05011462<<<<<<",
        "0508034M3604096CMR<<<<<<<<<<<<8",
        "BELL<<AQIL<<<<<<<<<<<<<<<<<<<<<<",
    ]

    analysis = service.analyze(mrz_lines=cni_like_lines, expected=True)

    assert analysis["detected"] is True
    assert analysis["parseable"] is True
    assert analysis["format"] == "TD1"
    assert analysis["parsed_fields"]["country"] == "CMR"
    assert analysis["parsed_fields"]["first_name"] == "AQIL"
    assert analysis["parsed_fields"]["last_name"] == "BELL"


@pytest.mark.unit
def test_analyze_ignores_ocr_name_noise_without_mrz_signature() -> None:
    service = MRZService()

    analysis = service.analyze(
        raw_text="FULLNAMEAZABARANGAFRANCKMIGUEL",
        expected=False,
    )

    assert analysis["detected"] is False
    assert analysis["parseable"] is False
    assert analysis["error"] is None
