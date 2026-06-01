"""Calibration de confiance OCR pour les CNI camerounaises."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional


FRONT_PRIMARY_GROUPS = (
    ("first_name", "full_name"),
    ("last_name", "full_name"),
    ("date_of_birth",),
)
FRONT_SUPPORT_FIELDS = ("gender", "expiry_date", "country")

BACK_PRIMARY_GROUPS = (
    ("national_id",),
    ("father_name",),
    ("mother_name",),
)
BACK_SUPPORT_FIELDS = ("place_of_birth", "profession", "issue_date", "height", "country")

MERGED_PRIMARY_GROUPS = (
    ("national_id",),
    ("first_name", "full_name"),
    ("last_name", "full_name"),
    ("date_of_birth",),
)
MERGED_SUPPORT_FIELDS = ("expiry_date", "gender", "father_name", "mother_name", "place_of_birth", "issue_date")

QUALITY_SCORES = {
    "high": 0.95,
    "medium": 0.80,
    "low": 0.55,
    "haute": 0.95,
    "moyenne": 0.80,
    "faible": 0.55,
}


def calculate_cni_confidence(
    fields: Dict[str, Any],
    *,
    document_side: Optional[str] = None,
    merged: bool = False,
) -> float:
    """Retourne une confiance plus realiste pour les CNI multi-faces."""

    if not fields:
        return 0.0

    normalized_side = _normalize_document_side(document_side or fields.get("document_side"))
    if merged or normalized_side not in {"front", "back"}:
        primary_groups = MERGED_PRIMARY_GROUPS
        support_fields = MERGED_SUPPORT_FIELDS
    elif normalized_side == "front":
        primary_groups = FRONT_PRIMARY_GROUPS
        support_fields = FRONT_SUPPORT_FIELDS
    else:
        primary_groups = BACK_PRIMARY_GROUPS
        support_fields = BACK_SUPPORT_FIELDS

    primary_ratio = _filled_group_ratio(fields, primary_groups)
    support_ratio = _filled_field_ratio(fields, support_fields)
    quality_score = _quality_score(fields.get("extraction_quality"))

    confidence = 0.55 * primary_ratio + 0.20 * support_ratio + 0.25 * quality_score
    return round(min(max(confidence, 0.0), 0.99), 2)


def calculate_cni_field_scores(
    fields: Dict[str, Any],
    *,
    document_side: Optional[str] = None,
    merged: bool = False,
) -> Dict[str, float]:
    """Scoring par champ base sur la face attendue."""

    if not fields:
        return {}

    normalized_side = _normalize_document_side(document_side or fields.get("document_side"))
    if merged or normalized_side not in {"front", "back"}:
        preferred_fields = {
            "national_id",
            "first_name",
            "last_name",
            "full_name",
            "date_of_birth",
            "expiry_date",
            "gender",
            "father_name",
            "mother_name",
            "place_of_birth",
            "issue_date",
        }
    elif normalized_side == "front":
        preferred_fields = {
            "first_name",
            "last_name",
            "full_name",
            "date_of_birth",
            "gender",
            "expiry_date",
            "country",
        }
    else:
        preferred_fields = {
            "national_id",
            "father_name",
            "mother_name",
            "place_of_birth",
            "profession",
            "issue_date",
            "height",
            "country",
        }

    preferred_score = max(calculate_cni_confidence(fields, document_side=normalized_side, merged=merged), 0.75)
    secondary_score = max(preferred_score - 0.15, 0.60)

    scores: Dict[str, float] = {}
    for key, value in fields.items():
        if key in {"warnings", "confidence_notes", "extraction_quality"}:
            continue
        if not _has_value(value):
            scores[key] = 0.0
        elif key in preferred_fields:
            scores[key] = preferred_score
        else:
            scores[key] = secondary_score

    return scores


def _filled_group_ratio(fields: Dict[str, Any], groups: Iterable[Iterable[str]]) -> float:
    groups_list = list(groups)
    if not groups_list:
        return 0.0
    filled = 0
    for group in groups_list:
        if any(_has_value(fields.get(field)) for field in group):
            filled += 1
    return filled / len(groups_list)


def _filled_field_ratio(fields: Dict[str, Any], names: Iterable[str]) -> float:
    field_names = tuple(names)
    if not field_names:
        return 0.0
    filled = sum(1 for name in field_names if _has_value(fields.get(name)))
    return filled / len(field_names)


def _quality_score(value: Any) -> float:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized:
            return QUALITY_SCORES.get(normalized, 0.80)
    return 0.80


def _normalize_document_side(value: Any) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"front", "recto"}:
        return "front"
    if normalized in {"back", "verso", "versau"}:
        return "back"
    return None


def _has_value(value: Any) -> bool:
    return bool(value and str(value).strip())
