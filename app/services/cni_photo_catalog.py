"""Discovery et pairage des photos de CNI camerounaises."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


SUPPORTED_CNI_IMAGE_SUFFIXES = {".jpeg", ".jpg", ".png"}


@dataclass(frozen=True)
class CNIDocumentPhotoSet:
    document_id: str
    front_path: Optional[Path] = None
    back_path: Optional[Path] = None

    @property
    def has_pair(self) -> bool:
        return bool(self.front_path and self.back_path)


def infer_document_side_from_name(path_or_name: str | Path) -> Optional[str]:
    name = Path(path_or_name).name.lower()
    if any(token in name for token in ("verso", "versau", "back")):
        return "back"
    if any(token in name for token in ("recto", "front")):
        return "front"
    if "page-1" in name or "page_1" in name or "page1" in name:
        return "front"
    if "page-2" in name or "page_2" in name or "page2" in name:
        return "back"
    return None


def discover_cni_photo_sets(photos_dir: str | Path) -> Tuple[List[CNIDocumentPhotoSet], List[Path]]:
    """Retourne les images supportees groupees par document et les fichiers ignores."""

    base_path = Path(photos_dir)
    if not base_path.exists():
        raise FileNotFoundError(f"Dossier introuvable: {base_path}")

    supported = sorted(
        path for path in base_path.iterdir()
        if path.is_file() and path.suffix.lower() in SUPPORTED_CNI_IMAGE_SUFFIXES
    )
    skipped = sorted(
        path for path in base_path.iterdir()
        if path.is_file() and path.suffix.lower() not in SUPPORTED_CNI_IMAGE_SUFFIXES
    )

    grouped: dict[str, dict[str, Optional[Path]]] = {}
    ordered_keys: List[str] = []

    for path in supported:
        side = infer_document_side_from_name(path)
        base_key = _build_document_key(path)
        key = base_key

        if key in grouped and side and grouped[key].get(side):
            suffix = 2
            while f"{base_key}-{suffix}" in grouped:
                suffix += 1
            key = f"{base_key}-{suffix}"

        if key not in grouped:
            grouped[key] = {"front": None, "back": None}
            ordered_keys.append(key)

        if side == "front":
            grouped[key]["front"] = path
        elif side == "back":
            grouped[key]["back"] = path
        else:
            if grouped[key]["front"] is None:
                grouped[key]["front"] = path
            elif grouped[key]["back"] is None:
                grouped[key]["back"] = path
            else:
                suffix = 2
                while f"{base_key}-{suffix}" in grouped:
                    suffix += 1
                fallback_key = f"{base_key}-{suffix}"
                grouped[fallback_key] = {"front": path, "back": None}
                ordered_keys.append(fallback_key)

    photo_sets = [
        CNIDocumentPhotoSet(
            document_id=key,
            front_path=grouped[key]["front"],
            back_path=grouped[key]["back"],
        )
        for key in ordered_keys
    ]
    return photo_sets, skipped


def _build_document_key(path: Path) -> str:
    stem = path.stem.lower()
    stem = re.sub(r"page[-_ ]*1", "page", stem)
    stem = re.sub(r"page[-_ ]*2", "page", stem)
    stem = re.sub(r"(recto|verso|versau|front|back)", "", stem)
    stem = re.sub(r"[^a-z0-9]+", "", stem)
    return stem or "default"
