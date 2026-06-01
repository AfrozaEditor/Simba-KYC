import base64
import zlib

import pytest

from app.services.qr_cni_decoder import QRCNIDecoder


def _tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        length_bytes = bytes([length])
    elif length <= 0xFF:
        length_bytes = b"\x81" + bytes([length])
    else:
        length_bytes = b"\x82" + length.to_bytes(2, "big")
    return bytes([tag]) + length_bytes + value


def _build_cameroon_payload() -> str:
    raw = b"".join(
        [
            _tlv(0xA0, b"DIALLO"),
            _tlv(0xA1, b"MAMADOU"),
            _tlv(0xA3, b"1992-03-15"),
            _tlv(0xA5, b"2030-01-01"),
            _tlv(0xA6, b"CM987654321"),
            _tlv(0xB1, b"FATOU DIALLO"),
            _tlv(0xB2, b"AMADOU DIALLO"),
            _tlv(0xC1, bytes.fromhex("0123456789ABCDEF")),
            _tlv(0x7F, bytes.fromhex("A1B2C3D4")),
        ]
    )
    compressed = zlib.compress(raw)
    encoded = base64.b32encode(compressed).decode("ascii").rstrip("=")
    return f"IDB1D{encoded}"


def _build_unknown_schema_payload() -> str:
    raw = b"".join(
        [
            _tlv(0xAA, b"AURELIEN RICKY"),
            _tlv(0xAB, b"AA18926250"),
            _tlv(0xAC, b"14082007"),
            _tlv(0xAD, b"27112035"),
            _tlv(0x7F, bytes.fromhex("A1B2C3D4")),
        ]
    )
    compressed = zlib.compress(raw)
    encoded = base64.b32encode(compressed).decode("ascii").rstrip("=")
    return f"IDB1D{encoded}"


def _build_qr_image_base64(payload: str) -> str:
    cv2 = pytest.importorskip("cv2")

    if not hasattr(cv2, "QRCodeEncoder_create") or not hasattr(cv2, "QRCodeEncoder_Params"):
        pytest.skip("OpenCV QRCodeEncoder n'est pas disponible")

    params = cv2.QRCodeEncoder_Params()
    params.version = 8
    encoder = cv2.QRCodeEncoder_create(params)
    qr_img = encoder.encode(payload)

    if qr_img is None:
        pytest.skip("Generation QR OpenCV indisponible dans cet environnement")

    ok, buffer = cv2.imencode(".png", qr_img)
    assert ok
    return base64.b64encode(buffer.tobytes()).decode("ascii")


@pytest.mark.unit
def test_decode_cni_cameroon_full_robust_extracts_sections() -> None:
    decoder = QRCNIDecoder()
    payload = _build_cameroon_payload()

    decoded = decoder.decode_cni_cameroon_full_robust(payload)

    assert decoded["metadata"]["taille_totale_octets"] > 0
    assert decoded["identite_titulaire"]["nom"] == "DIALLO"
    assert decoded["identite_titulaire"]["prenom"] == "MAMADOU"
    assert decoded["identite_titulaire"]["numero_document"] == "CM987654321"
    assert decoded["filiation"]["nom_mere"] == "FATOU DIALLO"
    assert decoded["infrastructure_anti_fraude"]["signature_cryptographique"] == "a1b2c3d4"


@pytest.mark.unit
def test_analyze_payload_canonicalizes_for_ocr_comparison() -> None:
    decoder = QRCNIDecoder()
    payload = _build_cameroon_payload()

    analysis = decoder.analyze_payload(payload)

    assert analysis["detected"] is True
    assert analysis["prefix_valid"] is True
    assert analysis["base32_valid"] is True
    assert analysis["decompression_valid"] is True
    assert analysis["required_fields_present"] is True
    assert analysis["signature_present"] is True
    assert analysis["parsed_fields"]["full_name"] == "MAMADOU DIALLO"
    assert analysis["parsed_fields"]["national_id"] == "CM987654321"
    assert analysis["parsed_fields"]["date_of_birth"] == "1992-03-15"


@pytest.mark.unit
def test_analyze_from_photo_detects_qr_and_extracts_payload() -> None:
    decoder = QRCNIDecoder()
    payload = _build_cameroon_payload()
    image_b64 = _build_qr_image_base64(payload)

    analysis = decoder.analyze(document_front_base64=image_b64, document_back_base64="")

    assert analysis["detected"] is True
    assert analysis["raw_payload"].startswith("IDB1D")
    assert analysis["required_fields_present"] is True
    assert analysis["parsed_fields"]["national_id"] == "CM987654321"


@pytest.mark.unit
def test_decode_payload_returns_error_on_invalid_base32() -> None:
    decoder = QRCNIDecoder()

    decoded = decoder.decode_cni_cameroon_full_robust("IDB1D###NOT-BASE32###")

    assert "error" in decoded


@pytest.mark.unit
def test_analyze_payload_recovers_identity_when_schema_tags_are_unknown() -> None:
    decoder = QRCNIDecoder()
    payload = _build_unknown_schema_payload()

    analysis = decoder.analyze_payload(payload)

    assert analysis["detected"] is True
    assert analysis["required_fields_present"] is True
    assert analysis["parsed_fields"]["full_name"] == "AURELIEN RICKY"
    assert analysis["parsed_fields"]["national_id"] == "AA18926250"
    assert analysis["parsed_fields"]["date_of_birth"] == "2007-08-14"
