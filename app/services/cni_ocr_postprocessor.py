"""Post-traitement OCR pour les CNI camerounaises."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.services.cni_ocr_confidence import calculate_cni_confidence, calculate_cni_field_scores


FRONT_PRIORITY_FIELDS = (
    "first_name",
    "last_name",
    "full_name",
    "date_of_birth",
    "gender",
    "expiry_date",
)

BACK_PRIORITY_FIELDS = (
    "national_id",
    "father_name",
    "mother_name",
    "place_of_birth",
    "profession",
    "issue_date",
    "height",
    "mrz_text",
)


def sanitize_cni_ocr_fields(
    fields: Optional[Dict[str, Any]],
    document_side: Optional[str] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """Nettoie les champs OCR pour une CNI camerounaise."""

    source = dict(fields or {})
    warnings: List[str] = []
    cleaned: Dict[str, Any] = {}

    side = _normalize_document_side(document_side or source.get("document_side") or source.get("side"))
    cleaned["document_type"] = "CNI_CAMEROON"
    cleaned["country"] = _clean_text(source.get("country")) or "CM"

    if side:
        cleaned["document_side"] = side

    for key, value in source.items():
        if key in {"document_type", "country", "document_side", "side", "warnings"}:
            continue

        if key in {"mrz_text", "mrz_lines", "mrz_line1", "mrz_line2", "mrz_line3", "mrz"}:
            if key == "mrz_lines":
                cleaned[key] = _normalize_mrz_lines(value)
            else:
                cleaned[key] = _normalize_mrz_text(value)
            continue

        if isinstance(value, str):
            value = _clean_text(value)

        if key in {"date_of_birth", "expiry_date", "issue_date"}:
            cleaned[key] = _normalize_date(value)
            continue

        if key == "gender":
            cleaned[key] = _normalize_gender(value)
            continue

        if key in {
            "full_name",
            "first_name",
            "last_name",
            "father_name",
            "mother_name",
            "place_of_birth",
            "profession",
        }:
            cleaned[key] = _normalize_name(value)
            continue

        if key == "national_id":
            cleaned[key] = _normalize_national_id(value)
            continue

        cleaned[key] = value

    if cleaned.get("first_name") and cleaned.get("last_name"):
        cleaned["full_name"] = _compose_holder_name(cleaned.get("first_name"), cleaned.get("last_name"))

    if side == "back":
        back_full_name = str(cleaned.get("full_name") or "")
        if back_full_name and _matches_parent_name(
            back_full_name,
            str(cleaned.get("father_name") or ""),
            str(cleaned.get("mother_name") or ""),
        ):
            warnings.append("back_parent_name_not_holder_name")
        elif cleaned.get("full_name") or cleaned.get("first_name") or cleaned.get("last_name"):
            warnings.append("back_holder_name_ignored")
        cleaned["full_name"] = ""
        cleaned["first_name"] = ""
        cleaned["last_name"] = ""

    national_id = str(cleaned.get("national_id") or "")
    if side == "front" and national_id:
        cleaned["national_id"] = ""
        warnings.append("front_serial_not_national_id_ignored")
    elif national_id and not _looks_like_cni_number(national_id):
        cleaned["national_id"] = ""
        warnings.append("national_id_format_suspect")

    return cleaned, warnings


def merge_cni_ocr_fields(
    front_fields: Optional[Dict[str, Any]],
    back_fields: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """Fusionne le recto et le verso en respectant la structure reelle du document."""

    front, front_warnings = sanitize_cni_ocr_fields(front_fields, document_side="front")
    back, back_warnings = sanitize_cni_ocr_fields(back_fields, document_side="back") if back_fields else ({}, [])

    merged: Dict[str, Any] = {
        "document_type": "CNI_CAMEROON",
        "country": front.get("country") or back.get("country") or "CM",
    }

    for key in FRONT_PRIORITY_FIELDS:
        merged[key] = front.get(key) or back.get(key) or ""

    for key in BACK_PRIORITY_FIELDS:
        merged[key] = back.get(key) or front.get(key) or ""

    for key in ("address",):
        merged[key] = front.get(key) or back.get(key) or ""

    if not merged.get("full_name") and (merged.get("first_name") or merged.get("last_name")):
        merged["full_name"] = _compose_holder_name(merged.get("first_name"), merged.get("last_name"))

    warnings = _dedupe(front_warnings + back_warnings)
    return merged, warnings


def normalize_cni_ocr_result(
    result: Optional[Dict[str, Any]],
    document_side: Optional[str] = None,
) -> Dict[str, Any]:
    """Nettoie une reponse OCR CNI simple en conservant sa structure."""

    normalized = dict(result or {})
    fields, warnings = sanitize_cni_ocr_fields(
        normalized.get("detected_fields"),
        document_side=document_side,
    )
    normalized["detected_fields"] = fields
    normalized["warnings"] = _dedupe(list(normalized.get("warnings") or []) + warnings)
    normalized["confidence_scores"] = calculate_cni_field_scores(fields, document_side=document_side)
    normalized["confidence"] = max(
        float(normalized.get("confidence") or 0.0),
        calculate_cni_confidence(fields, document_side=document_side),
    )
    return normalized


def merge_cni_ocr_results(
    front_result: Dict[str, Any],
    back_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Fusionne deux reponses OCR CNI en un resultat unique exploitable."""

    normalized_front = normalize_cni_ocr_result(front_result, document_side="front")
    normalized_back = normalize_cni_ocr_result(back_result, document_side="back") if back_result else None

    usable_back = normalized_back if normalized_back and normalized_back.get("success", True) else None
    merged_fields, merge_warnings = merge_cni_ocr_fields(
        normalized_front.get("detected_fields"),
        usable_back.get("detected_fields") if usable_back else None,
    )

    warnings = _dedupe(
        list(normalized_front.get("warnings") or [])
        + (list(normalized_back.get("warnings") or []) if normalized_back else [])
        + merge_warnings
    )

    raw_chunks = [str(normalized_front.get("raw_response") or "").strip()]
    if normalized_back:
        raw_chunks.append(str(normalized_back.get("raw_response") or "").strip())

    successful_results = [normalized_front]
    if usable_back:
        successful_results.append(usable_back)

    providers = [
        str(result.get("provider") or "").strip()
        for result in successful_results
        if str(result.get("provider") or "").strip()
    ]
    provider = "+".join(dict.fromkeys(providers)) or "ocr"

    confidence_values = [float(result.get("confidence") or 0.0) for result in successful_results]
    averaged_confidence = round(sum(confidence_values) / len(confidence_values), 2) if confidence_values else 0.0
    merged_confidence = calculate_cni_confidence(merged_fields, merged=True)
    confidence = max(averaged_confidence, merged_confidence)

    confidence_scores = _merge_confidence_scores(
        merged_fields=merged_fields,
        front_scores=normalized_front.get("confidence_scores"),
        back_scores=usable_back.get("confidence_scores") if usable_back else None,
    )

    error = None
    if not normalized_front.get("success", True):
        error = normalized_front.get("error")
    elif normalized_back and not normalized_back.get("success", True):
        error = normalized_back.get("error")

    return {
        "success": bool(normalized_front.get("success", False)),
        "provider": provider,
        "confidence": confidence,
        "detected_fields": merged_fields,
        "confidence_scores": confidence_scores,
        "warnings": warnings,
        "front_result": normalized_front,
        "back_result": normalized_back,
        "raw_response": "\n".join(chunk for chunk in raw_chunks if chunk),
        "error": error,
    }


def _normalize_document_side(value: Any) -> str:
    text = _clean_text(value).lower()
    if text in {"front", "recto"}:
        return "front"
    if text in {"back", "verso", "versau"}:
        return "back"
    return ""


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).replace("\u00a0", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _normalize_mrz_lines(value: Any) -> List[str]:
    lines: List[str] = []
    if value is None:
        return lines
    if isinstance(value, list):
        for item in value:
            lines.extend(_normalize_mrz_lines(item))
        return lines
    text = str(value).replace("\u00a0", " ")
    for piece in text.splitlines():
        piece = piece.strip()
        if piece:
            lines.append(piece)
    return lines


def _normalize_mrz_text(value: Any) -> str:
    lines = _normalize_mrz_lines(value)
    return "\n".join(lines)


def _normalize_name(value: Any) -> str:
    text = _clean_text(value)
    if not text:
        return ""
    text = re.sub(r"[^A-ZÀ-ÖØ-Ý0-9' -]", " ", text.upper())
    return re.sub(r"\s+", " ", text).strip()


def _normalize_gender(value: Any) -> str:
    text = _clean_text(value).upper()
    if text.startswith("M"):
        return "M"
    if text.startswith("F"):
        return "F"
    return ""


def _normalize_national_id(value: Any) -> str:
    text = _clean_text(value).upper()
    if not text:
        return ""
    text = re.sub(r"[^A-Z0-9]", "", text)
    return text


def _normalize_date(value: Any) -> str:
    text = _clean_text(value)
    if not text:
        return ""

    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y%m%d", "%d%m%Y"):
        try:
            return datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue

    return ""


def _compose_holder_name(first_name: Any, last_name: Any) -> str:
    first = _normalize_name(first_name)
    last = _normalize_name(last_name)
    return " ".join(part for part in (first, last) if part).strip()


def _looks_like_cni_number(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{1,4}[0-9]{5,12}", value)) and not value.startswith("CMR")


def _matches_parent_name(full_name: str, father_name: str, mother_name: str) -> bool:
    normalized_full = _normalize_name(full_name)
    candidates = {_normalize_name(father_name), _normalize_name(mother_name)}
    candidates.discard("")
    return normalized_full in candidates


def _dedupe(values: List[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _merge_confidence_scores(
    *,
    merged_fields: Dict[str, Any],
    front_scores: Any,
    back_scores: Any,
) -> Dict[str, float]:
    merged_scores: Dict[str, float] = dict(
        calculate_cni_field_scores(merged_fields, merged=True)
    )
    front_mapping = front_scores if isinstance(front_scores, dict) else {}
    back_mapping = back_scores if isinstance(back_scores, dict) else {}

    for key, value in merged_fields.items():
        if value in ("", None):
            continue

        preferred = back_mapping if key in BACK_PRIORITY_FIELDS else front_mapping
        fallback = front_mapping if preferred is back_mapping else back_mapping
        score = preferred.get(key, fallback.get(key))
        if isinstance(score, (int, float)):
            merged_scores[key] = max(float(score), float(merged_scores.get(key, 0.0)))

    return merged_scores
