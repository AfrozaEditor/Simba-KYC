#!/usr/bin/env python
"""Run full KYC flow on recto/verso/selfie triplets."""

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from app.api.v1.schemas.request.kyc_analyze import KYCAnalyzeRequest, KYCMetadata
from app.core.config import settings
from app.infrastructure.external.aws_liveness import AWSLiveness
from app.infrastructure.external.llm_factory import get_llm_router
from app.services.cni_photo_catalog import infer_document_side_from_name
from app.services.kyc_orchestrator import KYCOrchestrator
from app.services.liveness_checker import LivenessChecker

BASE_DIR = Path(__file__).resolve().parent / "tests" / "unit" / "cni_photos"
FOLDERS = [BASE_DIR / "kyc1", BASE_DIR / "kyc2"]
SUPPORTED = {".jpeg", ".jpg", ".png"}
logger = logging.getLogger(__name__)


def _to_b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def _pick_triplet(folder: Path) -> dict:
    files = [p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in SUPPORTED]
    front = None
    back = None
    selfie = None

    for path in files:
        name = path.name.lower()
        if "selfie" in name:
            selfie = path
            continue

        side = infer_document_side_from_name(path)
        if side == "front" and front is None:
            front = path
        elif side == "back" and back is None:
            back = path

    if selfie is None:
        leftovers = [p for p in files if p not in {front, back}]
        if len(leftovers) == 1:
            selfie = leftovers[0]

    return {"front": front, "back": back, "selfie": selfie, "files": files}


def _build_liveness_service():
    provider = (settings.LIVENESS_PROVIDER or "aws").strip().lower()
    if provider != "aws":
        raise RuntimeError("AWS-only mode: LIVENESS_PROVIDER must be 'aws'.")

    def _clean(value):
        if isinstance(value, str):
            value = value.strip()
        return value or None

    return AWSLiveness(
        region=settings.AWS_REGION,
        min_confidence=settings.AWS_LIVENESS_MIN_CONFIDENCE,
        aws_access_key_id=_clean(settings.AWS_ACCESS_KEY_ID),
        aws_secret_access_key=_clean(settings.AWS_SECRET_ACCESS_KEY),
        aws_session_token=_clean(settings.AWS_SESSION_TOKEN),
    )


async def _run_folder(folder: Path, orchestrator: KYCOrchestrator) -> dict:
    pick = _pick_triplet(folder)
    front = pick["front"]
    back = pick["back"]
    selfie = pick["selfie"]

    if not front or not selfie:
        return {
            "folder": str(folder),
            "error": "missing_front_or_selfie",
            "front": str(front) if front else None,
            "back": str(back) if back else None,
            "selfie": str(selfie) if selfie else None,
            "files": [p.name for p in pick["files"]],
        }

    request = KYCAnalyzeRequest(
        user_id=folder.name,
        document_front=_to_b64(front),
        document_back=_to_b64(back) if back else None,
        selfie=_to_b64(selfie),
        metadata=KYCMetadata(
            device_id=f"device-{folder.name}",
            ip_address="127.0.0.1",
            timestamp=datetime.now(timezone.utc),
            app_version="1.0.0",
        ),
    )

    result = await orchestrator.analyze_kyc(request)
    data = result.model_dump(mode="json")
    data.update({
        "folder": str(folder),
        "front": front.name,
        "back": back.name if back else None,
        "selfie": selfie.name,
    })
    return data


async def main() -> None:
    llm_router = get_llm_router()
    liveness = _build_liveness_service()
    checker = LivenessChecker(liveness)
    orchestrator = KYCOrchestrator(
        ocr_service=llm_router,
        liveness_service=liveness,
        liveness_checker=checker,
    )

    results = []
    for folder in FOLDERS:
        if not folder.exists():
            results.append({"folder": str(folder), "error": "folder_not_found"})
            continue
        results.append(await _run_folder(folder, orchestrator))

    print(json.dumps({"results": results}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
