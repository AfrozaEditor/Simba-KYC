#!/usr/bin/env python
"""Extraction OCR CNI avec fusion recto/verso via le pipeline runtime."""

import asyncio
import base64
from pathlib import Path

from app.infrastructure.external.llm_factory import get_llm_router
from app.services.cni_ocr_runtime import extract_document_ocr
from app.services.cni_photo_catalog import discover_cni_photo_sets, infer_document_side_from_name


def _image_to_b64(image_path: Path) -> str:
    return base64.b64encode(image_path.read_bytes()).decode("utf-8")


async def _extract_from_photo_set(photo_set, llm_router):
    front_path = photo_set.front_path
    back_path = photo_set.back_path
    primary_path = front_path or back_path
    if primary_path is None:
        return {"error": "no_supported_image", "success": False}

    front_b64 = _image_to_b64(front_path) if front_path else ""
    back_b64 = _image_to_b64(back_path) if back_path else ""
    primary_b64 = front_b64 or back_b64
    primary_side = infer_document_side_from_name(primary_path)

    return await extract_document_ocr(
        llm_router,
        image_base64=primary_b64,
        image_back_base64=back_b64 if front_b64 else "",
        document_type="CNI_CAMEROON",
        document_side=None if front_b64 and back_b64 else primary_side,
    )


async def main():
    llm_router = get_llm_router()

    photo_sets, skipped = discover_cni_photo_sets("tests/unit/cni_photos")

    print("\n" + "=" * 120)
    print("🔍 EXTRACTION OCR DES PHOTOS CNI — PIPELINE DOCUMENTAIRE".center(120))
    print("=" * 120 + "\n")

    if skipped:
        print("📄 Fichiers ignorés:")
        for path in skipped:
            print(f"  - {path.name}")

    for photo_set in photo_sets:
        front_name = photo_set.front_path.name if photo_set.front_path else "-"
        back_name = photo_set.back_path.name if photo_set.back_path else "-"

        print(f"\n📄 Document: {photo_set.document_id}")
        print("-" * 120)
        print(f"  Recto: {front_name}")
        print(f"  Verso: {back_name}")

        result = await _extract_from_photo_set(photo_set, llm_router)

        if result.get("error"):
            print(f"  ❌ Erreur: {result['error']}")
            continue

        print(f"  ✓ Provider: {result.get('provider', 'Unknown')}")
        print(f"  ✓ Succès: {result.get('success', False)}")
        print(f"  ✓ Confiance globale: {result.get('confidence', 0):.2%}")

        detected_fields = result.get("detected_fields", {})
        if detected_fields:
            print("\n  📋 Champs extraits par OCR:")
            for key, value in detected_fields.items():
                print(f"     • {key}: {value}")

        confidence_scores = result.get("confidence_scores", {})
        if confidence_scores:
            print("\n  🎯 Scores de confiance par champ:")
            for key, score in confidence_scores.items():
                confidence_bar = "█" * int(score * 10) + "░" * (10 - int(score * 10))
                print(f"     • {key}: {confidence_bar} {score:.1%}")

        warnings = result.get("warnings", [])
        if warnings:
            print("\n  ⚠️  Avertissements:")
            for warning in warnings:
                print(f"     • {warning}")

    print("\n" + "=" * 120 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
