"""Analyse documentaire reelle sur les photos CNI du dossier de test.

Ce script ne lance pas un faux KYC complet: le dossier cible contient des
documents, pas de vrais selfies. Il produit donc un rapport honnete base sur:
1) OCR reel via le router LLM configure
2) Decodage QR documentaire
3) Analyse MRZ si des lignes candidates remontent depuis l'OCR
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.services.cni_ocr_runtime import extract_document_ocr
from app.services.cni_photo_catalog import CNIDocumentPhotoSet, discover_cni_photo_sets, infer_document_side_from_name
from app.services.mrz_service import MRZService
from app.services.qr_cni_decoder import QRCNIDecoder


def _image_to_b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def _extract_mrz_inputs_from_ocr_result(result: Dict[str, Any]) -> Tuple[List[str], str]:
    lines: List[str] = []
    text_chunks: List[str] = []
    fields = result.get("detected_fields") if isinstance(result, dict) else {}
    fields = fields if isinstance(fields, dict) else {}

    def add_line_candidate(value: Any) -> None:
        if not value:
            return
        if isinstance(value, str):
            if "\n" in value:
                for piece in value.splitlines():
                    if piece.strip():
                        lines.append(piece.strip())
            elif value.strip():
                lines.append(value.strip())
            return
        if isinstance(value, list):
            for item in value:
                add_line_candidate(item)

    for key in ("mrz_lines", "mrz_line1", "mrz_line2", "mrz_line3", "mrz", "mrz_text"):
        add_line_candidate(fields.get(key))
        add_line_candidate(result.get(key))

    for key in ("text", "raw_text", "raw_response"):
        chunk = result.get(key)
        if isinstance(chunk, str) and chunk.strip():
            text_chunks.append(chunk)

    dedup_lines: List[str] = []
    seen = set()
    for line in lines:
        if line not in seen:
            seen.add(line)
            dedup_lines.append(line)

    return dedup_lines, "\n".join(text_chunks)


async def _analyze_document(
    photo_set: CNIDocumentPhotoSet,
    llm_router: Any,
    qr_decoder: QRCNIDecoder,
    mrz_service: MRZService,
) -> Dict[str, Any]:
    front_path = photo_set.front_path
    back_path = photo_set.back_path
    primary_path = front_path or back_path
    if primary_path is None:
        return {
            "document_id": photo_set.document_id,
            "error": "no_supported_image",
        }

    front_b64 = _image_to_b64(front_path) if front_path else ""
    back_b64 = _image_to_b64(back_path) if back_path else ""
    primary_b64 = front_b64 or back_b64
    primary_side = infer_document_side_from_name(primary_path)

    ocr_result = await extract_document_ocr(
        llm_router,
        image_base64=primary_b64,
        image_back_base64=back_b64 if front_b64 else "",
        document_type="CNI_CAMEROON",
        document_side=None if front_b64 and back_b64 else primary_side,
    )

    qr_analysis = qr_decoder.analyze(
        document_front_base64=front_b64 or (primary_b64 if primary_side != "back" else ""),
        document_back_base64=back_b64 or (primary_b64 if primary_side == "back" else ""),
    )

    mrz_lines, mrz_text = _extract_mrz_inputs_from_ocr_result(ocr_result)
    mrz_analysis = mrz_service.analyze(
        mrz_lines=mrz_lines,
        raw_text=mrz_text,
        expected=False,
    )

    return {
        "document_id": photo_set.document_id,
        "front": front_path.name if front_path else None,
        "back": back_path.name if back_path else None,
        "pair_complete": photo_set.has_pair,
        "primary_side": primary_side,
        "ocr_success": ocr_result.get("success", False),
        "ocr_provider": ocr_result.get("provider"),
        "ocr_confidence": ocr_result.get("confidence", 0.0),
        "ocr_fields": ocr_result.get("detected_fields", {}),
        "ocr_warnings": ocr_result.get("warnings", []),
        "ocr_error": ocr_result.get("error"),
        "qr_detected": qr_analysis.get("detected"),
        "qr_source": qr_analysis.get("source"),
        "qr_required_fields_present": qr_analysis.get("required_fields_present"),
        "qr_parsed_fields": qr_analysis.get("parsed_fields", {}),
        "qr_error": qr_analysis.get("error"),
        "mrz_detected": mrz_analysis.get("detected"),
        "mrz_parseable": mrz_analysis.get("parseable"),
        "mrz_format": mrz_analysis.get("format"),
        "mrz_fields": mrz_analysis.get("parsed_fields", {}),
        "mrz_error": mrz_analysis.get("error"),
    }


async def _run_document_analysis(photos_dir: str) -> Dict[str, Any]:
    llm_router = None
    llm_router_error: Optional[str] = None
    try:
        from app.infrastructure.external.llm_factory import get_llm_router
        llm_router = get_llm_router()
    except Exception as exc:
        llm_router_error = str(exc)

    qr_decoder = QRCNIDecoder()
    mrz_service = MRZService()

    photo_sets, skipped_files = discover_cni_photo_sets(photos_dir)
    if not photo_sets:
        raise FileNotFoundError(f"Aucune image .jpeg/.jpg/.png trouvee dans: {photos_dir}")

    rows: List[Dict[str, Any]] = []
    for photo_set in photo_sets:
        rows.append(await _analyze_document(photo_set, llm_router, qr_decoder, mrz_service))

    return {
        "photos_dir": str(Path(photos_dir)),
        "document_count": len(photo_sets),
        "ocr_router_error": llm_router_error,
        "skipped_files": [path.name for path in skipped_files],
        "documents": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse documentaire reelle sur les photos CNI du dossier de test")
    parser.add_argument("--photos-dir", default="tests/unit/cni_photos", help="Dossier contenant les images du document")
    parser.add_argument("--indent", type=int, default=2, help="Indentation JSON en sortie")
    args = parser.parse_args()

    report = asyncio.run(_run_document_analysis(photos_dir=args.photos_dir))
    print(json.dumps(report, indent=args.indent, ensure_ascii=False))


if __name__ == "__main__":
    main()
