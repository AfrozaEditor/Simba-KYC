"""Helpers runtime pour OCR CNI et documents simples."""

from __future__ import annotations

from typing import Any, Dict, Optional

from app.services.cni_ocr_postprocessor import merge_cni_ocr_results, normalize_cni_ocr_result


async def extract_document_ocr(
    ocr_service: Any,
    *,
    image_base64: str,
    document_type: str = "CNI_CAMEROON",
    image_back_base64: str = "",
    document_side: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute l'OCR documentaire en appliquant les regles CNI si necessaire."""

    if ocr_service is None:
        return {
            "success": False,
            "provider": "ocr",
            "confidence": 0.0,
            "detected_fields": {},
            "confidence_scores": {},
            "warnings": ["ocr_service_unavailable"],
            "error": "OCR indisponible",
        }

    if document_type != "CNI_CAMEROON":
        return await ocr_service.extract_from_image(
            image_base64,
            document_type,
            document_side=document_side,
        )

    if image_back_base64:
        front_result = await ocr_service.extract_from_image(
            image_base64,
            document_type,
            document_side="front",
        )
        if not front_result.get("success", True):
            return front_result

        back_result = await ocr_service.extract_from_image(
            image_back_base64,
            document_type,
            document_side="back",
        )
        return merge_cni_ocr_results(front_result, back_result)

    result = await ocr_service.extract_from_image(
        image_base64,
        document_type,
        document_side=document_side,
    )
    if not result.get("success", True):
        return result
    return normalize_cni_ocr_result(result, document_side=document_side)
