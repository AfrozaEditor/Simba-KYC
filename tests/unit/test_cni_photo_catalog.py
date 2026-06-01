from pathlib import Path

import pytest

from app.services.cni_photo_catalog import discover_cni_photo_sets, infer_document_side_from_name


@pytest.mark.unit
def test_infer_document_side_from_name_handles_known_variants() -> None:
    assert infer_document_side_from_name("recto.jpeg") == "front"
    assert infer_document_side_from_name("versau.jpeg") == "back"
    assert infer_document_side_from_name("page-1.recto.png") == "front"
    assert infer_document_side_from_name("page-2versau.png") == "back"
    assert infer_document_side_from_name("mystery-file.png") is None


@pytest.mark.unit
def test_discover_cni_photo_sets_pairs_variants_and_skips_pdf(tmp_path: Path) -> None:
    for filename in (
        "recto.jpeg",
        "versau.jpeg",
        "WhatsApp.recto.jpeg",
        "WhatsApp.versau.jpeg",
        "page-1.recto.png",
        "page-2versau.png",
        "isolated.verso.jpeg",
        "Scanned_20260303_210748.pdf",
    ):
        (tmp_path / filename).write_bytes(b"fixture")

    photo_sets, skipped_files = discover_cni_photo_sets(tmp_path)

    by_id = {photo_set.document_id: photo_set for photo_set in photo_sets}

    assert [path.name for path in skipped_files] == ["Scanned_20260303_210748.pdf"]

    assert by_id["default"].front_path and by_id["default"].front_path.name == "recto.jpeg"
    assert by_id["default"].back_path and by_id["default"].back_path.name == "versau.jpeg"
    assert by_id["default"].has_pair is True

    assert by_id["whatsapp"].front_path and by_id["whatsapp"].front_path.name == "WhatsApp.recto.jpeg"
    assert by_id["whatsapp"].back_path and by_id["whatsapp"].back_path.name == "WhatsApp.versau.jpeg"
    assert by_id["whatsapp"].has_pair is True

    assert by_id["page"].front_path and by_id["page"].front_path.name == "page-1.recto.png"
    assert by_id["page"].back_path and by_id["page"].back_path.name == "page-2versau.png"
    assert by_id["page"].has_pair is True

    assert by_id["isolated"].front_path is None
    assert by_id["isolated"].back_path and by_id["isolated"].back_path.name == "isolated.verso.jpeg"
    assert by_id["isolated"].has_pair is False
