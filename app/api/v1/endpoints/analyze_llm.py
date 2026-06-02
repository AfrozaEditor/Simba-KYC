"""Endpoint pour l'analyse KYC — Version LLM Multimodal (base64 + upload fichier)"""

import logging
import asyncio
import base64
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import Optional, List, Dict, Any
from app.api.v1.schemas.request.kyc_analyze import KYCAnalyzeRequest, KYCMetadata
from app.api.v1.schemas.response.kyc_analyze import KYCAnalyzeResponse
from app.services.kyc_orchestrator import KYCOrchestrator
from app.services.cni_ocr_runtime import extract_document_ocr
from app.services.liveness_checker import LivenessChecker  
from app.infrastructure.external.aws_liveness import AWSLiveness
from app.infrastructure.external.llm_factory import get_llm_router
from app.core.config import settings
from app.services.dashboard_events import dashboard_events
from app.services.kyc_dashboard_store import get_kyc_dashboard_store
from datetime import datetime, timezone
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# INITIALISATION DES SERVICES
# ─────────────────────────────────────────────

def _build_ocr_service():
    llm_router = get_llm_router()
    logger.info(f" OCR: LLM MULTIMODAL (Préféré: {settings.LLM_PREFER_PROVIDER})")
    logger.info(f" OCR providers status: {llm_router.get_provider_status()}")
    return llm_router


def _build_liveness_service():
    provider = (settings.LIVENESS_PROVIDER or "local").strip().lower()
    if provider != "aws":
        logger.error(
            "Simba KYC utilise AWS Rekognition: LIVENESS_PROVIDER='%s' is not allowed.",
            settings.LIVENESS_PROVIDER,
        )
        raise RuntimeError("LIVENESS_PROVIDER must be 'aws'.")

    logger.info(f" Liveness: AWS Rekognition (region: {settings.AWS_REGION})")
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
    

ocr_service = _build_ocr_service()
liveness_service = _build_liveness_service()

# Créer le LivenessChecker à partir du service
liveness_checker = LivenessChecker(liveness_service)

# Passer le LivenessChecker à l'orchestrateur
kyc_orchestrator = KYCOrchestrator(ocr_service, liveness_service, liveness_checker=liveness_checker)

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

MAX_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
MAX_SIZE_MB = 10
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}


async def _file_to_base64(file: UploadFile) -> str:
    """Convertit un UploadFile en base64 avec validation."""
    if file.content_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Type non supporté: {file.content_type}. Acceptés: JPEG, PNG, WEBP")
    content = await file.read()
    if len(content) > MAX_SIZE_BYTES:
        raise ValueError(f"Fichier '{file.filename}' trop volumineux (max {MAX_SIZE_MB}MB)")
    return base64.b64encode(content).decode()


def _validate_base64(value: str, field_name: str) -> str:
    """Valide et nettoie une chaîne base64."""
    if "," in value:
        value = value.split(",", 1)[1]
    if len(value) > MAX_SIZE_BYTES:
        raise ValueError(f"{field_name} trop volumineux (max {MAX_SIZE_MB}MB)")
    try:
        base64.b64decode(value, validate=True)
    except Exception:
        raise ValueError(f"{field_name} n'est pas un base64 valide")
    return value


def _dashboard_event_payload(record: dict) -> Dict[str, Any]:
    return {
        "id": record.get("id"),
        "user_id": record.get("user_id"),
        "status": record.get("status"),
        "decision": record.get("decision"),
        "recommendation": record.get("recommendation"),
        "kyc_score": record.get("kyc_score"),
        "valid": record.get("valid"),
        "reason": record.get("reason"),
        "error": record.get("error"),
    }


async def _create_dashboard_record(
    request: KYCAnalyzeRequest,
    *,
    source: str,
    filenames: Optional[Dict[str, str]] = None,
    content_types: Optional[Dict[str, str]] = None,
) -> str:
    store = get_kyc_dashboard_store()
    metadata = request.metadata.model_dump(mode="json")
    metadata["source"] = source
    record = store.create_request(
        user_id=request.user_id,
        source=source,
        metadata=metadata,
    )
    request_id = record["id"]
    filenames = filenames or {}
    content_types = content_types or {}

    for kind, value in (
        ("document_front", request.document_front),
        ("document_back", request.document_back),
        ("selfie", request.selfie),
        ("mrz_face", request.mrz_face),
    ):
        if value:
            store.add_asset_base64(
                request_id=request_id,
                kind=kind,
                image_base64=value,
                filename=filenames.get(kind),
                content_type=content_types.get(kind),
            )

    event = store.add_event(
        request_id=request_id,
        event_type="created",
        payload=_dashboard_event_payload(record),
    )
    await dashboard_events.broadcast(event)
    return request_id


async def _mark_dashboard_failed(request_id: Optional[str], error: str) -> None:
    if not request_id:
        return
    store = get_kyc_dashboard_store()
    record = store.mark_failed(request_id, error)
    event = store.add_event(
        request_id=request_id,
        event_type="failed",
        payload=_dashboard_event_payload(record),
    )
    await dashboard_events.broadcast(event)


async def _run_kyc(request: KYCAnalyzeRequest, *, request_id: Optional[str] = None) -> KYCAnalyzeResponse:
    """Exécute l'analyse KYC avec timeout — partagé par les deux endpoints."""
    try:
        result = await asyncio.wait_for(
            kyc_orchestrator.analyze_kyc(request),
            timeout=settings.KYC_ANALYZE_TIMEOUT
        )
        if request_id:
            store = get_kyc_dashboard_store()
            record = store.mark_completed(request_id, result)
            event = store.add_event(
                request_id=request_id,
                event_type="completed",
                payload=_dashboard_event_payload(record),
            )
            await dashboard_events.broadcast(event)
        logger.info(f"  KYC terminé — user: {request.user_id} — status: {result.status}")
        return KYCAnalyzeResponse(success=True, request_id=request_id, error=None, data=result)
    except asyncio.TimeoutError:
        logger.error(f"  Timeout KYC — user: {request.user_id} ({settings.KYC_ANALYZE_TIMEOUT}s)")
        await _mark_dashboard_failed(request_id, f"Analyse KYC timeout après {settings.KYC_ANALYZE_TIMEOUT}s")
        raise HTTPException(
            status_code=504,
            detail=f"Analyse KYC timeout après {settings.KYC_ANALYZE_TIMEOUT}s"
        )
    except Exception as exc:
        await _mark_dashboard_failed(request_id, str(exc))
        raise


# ─────────────────────────────────────────────
# ENDPOINT 1 — KYC JSON base64
# ─────────────────────────────────────────────

@router.post(
    "/kyc/analyze",
    response_model=KYCAnalyzeResponse,
    summary="Analyse KYC — JSON base64",
    description="Analyse KYC complète via JSON avec documents encodés en base64."
)
async def analyze_kyc_json(request: KYCAnalyzeRequest) -> KYCAnalyzeResponse:
    """Mode base64 JSON — Backend-to-backend ou mobile."""
    try:
        logger.info(f" [JSON] KYC reçu — user: {request.user_id}")
        request.document_front = _validate_base64(request.document_front, "document_front")
        if request.document_back:
            request.document_back = _validate_base64(request.document_back, "document_back")
        request.selfie = _validate_base64(request.selfie, "selfie")
        if request.mrz_face:
            request.mrz_face = _validate_base64(request.mrz_face, "mrz_face")
        request_id = await _create_dashboard_record(request, source="json")
        return await _run_kyc(request, request_id=request_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"  Erreur KYC JSON: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur serveur lors de l'analyse KYC")


# ─────────────────────────────────────────────
# ENDPOINT 2 — KYC Upload fichier
# ─────────────────────────────────────────────

@router.post(
    "/kyc/analyze/upload",
    response_model=KYCAnalyzeResponse,
    summary="Analyse KYC — Upload fichier",
    description="Analyse KYC complète via upload multipart. Idéal pour tests et formulaires web."
)
async def analyze_kyc_upload(
    user_id: str = Form(..., description="ID utilisateur"),
    document_front: UploadFile = File(..., description="Recto CNI/Passport (JPEG/PNG/WEBP, max 10MB)"),
    selfie: UploadFile = File(..., description="Photo selfie (JPEG/PNG/WEBP, max 10MB)"),
    document_back: Optional[UploadFile] = File(None, description="Verso document (optionnel)"),
    mrz_face: Optional[UploadFile] = File(None, description="Photo faciale externe (puce/NFC). Requise pour PASSPORT, ignoree pour CNI"),
    device_id: str = Form(default="upload-client"),
    ip_address: str = Form(default="0.0.0.0"),
    app_version: str = Form(default="1.0.0"),
) -> KYCAnalyzeResponse:
    """Mode upload fichier — Formulaire multipart."""
    try:
        logger.info(f" [UPLOAD] KYC reçu — user: {user_id}")
        doc_front_b64 = await _file_to_base64(document_front)
        selfie_b64 = await _file_to_base64(selfie)
        doc_back_b64 = await _file_to_base64(document_back) if document_back else None
        mrz_face_b64 = await _file_to_base64(mrz_face) if mrz_face else None

        request = KYCAnalyzeRequest(
            user_id=user_id,
            document_front=doc_front_b64,
            document_back=doc_back_b64,
            selfie=selfie_b64,
            mrz_face=mrz_face_b64,
            metadata=KYCMetadata(
                device_id=device_id,
                ip_address=ip_address,
                timestamp=datetime.now(timezone.utc),
                app_version=app_version
            )
        )
        request_id = await _create_dashboard_record(
            request,
            source="upload",
            filenames={
                "document_front": document_front.filename,
                "document_back": document_back.filename if document_back else "",
                "selfie": selfie.filename,
                "mrz_face": mrz_face.filename if mrz_face else "",
            },
            content_types={
                "document_front": document_front.content_type or "",
                "document_back": document_back.content_type if document_back else "",
                "selfie": selfie.content_type or "",
                "mrz_face": mrz_face.content_type if mrz_face else "",
            },
        )
        return await _run_kyc(request, request_id=request_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"  Erreur KYC upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur serveur lors de l'analyse KYC")


# ─────────────────────────────────────────────
# ENDPOINT 3 — OCR SEUL (base64 JSON)
# ─────────────────────────────────────────────

class OCRRequest(BaseModel):
    image: str = Field(..., description="Image principale du document en base64")
    image_back: Optional[str] = Field(None, description="Image verso en base64 pour les documents a deux faces")
    document_type: str = Field(default="CNI_CAMEROON", description="Type de document")
    document_side: Optional[str] = Field(
        default=None,
        description="Face du document pour un OCR sur image unique (front/back/recto/verso)",
    )


class OCRResponse(BaseModel):
    success: bool
    provider: str
    confidence: float
    document_type: str
    detected_fields: dict
    confidence_scores: dict
    warnings: list
    error: Optional[str] = None


@router.post(
    "/kyc/ocr",
    response_model=OCRResponse,
    summary="OCR seul — JSON base64",
    description="Extrait uniquement les données d'un document via LLM. Sans liveness."
)
async def ocr_only_json(request: OCRRequest) -> OCRResponse:
    """OCR uniquement — Extraction des champs d'un document."""
    try:
        logger.info(f"📷 [OCR JSON] Extraction — type: {request.document_type}")
        image_b64 = _validate_base64(request.image, "image")
        image_back_b64 = _validate_base64(request.image_back, "image_back") if request.image_back else ""
        return await _run_ocr(
            image_b64,
            request.document_type,
            image_back_b64=image_back_b64,
            document_side=request.document_side,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"  Erreur OCR JSON: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur serveur lors de l'extraction OCR")


# ─────────────────────────────────────────────
# ENDPOINT 4 — OCR SEUL (upload fichier)
# ─────────────────────────────────────────────

@router.post(
    "/kyc/ocr/upload",
    response_model=OCRResponse,
    summary="OCR seul — Upload fichier",
    description="Extrait les données d'un document via upload direct. Idéal pour tests rapides."
)
async def ocr_only_upload(
    image: UploadFile = File(..., description="Image du document (JPEG/PNG/WEBP, max 5MB)"),
    document_back: Optional[UploadFile] = File(None, description="Verso du document (JPEG/PNG/WEBP, max 5MB)"),
    document_type: str = Form(default="CNI_CAMEROON", description="Type de document"),
    document_side: Optional[str] = Form(
        default=None,
        description="Face du document pour un OCR sur image unique (front/back/recto/verso)",
    ),
) -> OCRResponse:
    """OCR upload — Test rapide depuis le terminal."""
    try:
        logger.info(f"📷 [OCR UPLOAD] Extraction — fichier: {image.filename}, type: {document_type}")
        image_b64 = await _file_to_base64(image)
        document_back_b64 = await _file_to_base64(document_back) if document_back else ""
        return await _run_ocr(
            image_b64,
            document_type,
            image_back_b64=document_back_b64,
            document_side=document_side,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"  Erreur OCR upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur serveur lors de l'extraction OCR")


# ─────────────────────────────────────────────
# ENDPOINT 5 — LIVENESS SEULE (JSON base64)
# ─────────────────────────────────────────────

class LivenessCheckRequest(BaseModel):
    selfie: str = Field(..., description="Image selfie en base64")


class LivenessCheckResponse(BaseModel):
    is_live: bool
    confidence: float
    liveness_score: float
    quality_score: float
    spoof_score: float
    flags: List[str]
    method: str
    face_count: int
    details: Optional[Dict[str, Any]] = None


@router.post(
    "/liveness/check",
    response_model=LivenessCheckResponse,
    summary="Vérification de liveness seule",
    description="Analyse la liveness d'un selfie sans OCR. Détecte les tentatives de spoofing."
)
async def check_liveness_only(request: LivenessCheckRequest) -> LivenessCheckResponse:
    """Vérifie si une photo selfie est authentique (vivante)."""
    try:
        logger.info("📸 Liveness check seul")
        selfie_b64 = _validate_base64(request.selfie, "selfie")
        
        # Utiliser LivenessChecker au lieu de liveness_service directement
        liveness = await liveness_checker.check_liveness(selfie_b64)
        
        return LivenessCheckResponse(
            is_live=liveness.passed,
            confidence=liveness.confidence,
            liveness_score=liveness.confidence,
            quality_score=liveness.quality_score or 0.0,
            spoof_score=liveness.spoof_score or 0.0,
            flags=liveness.flags or [],
            method=liveness.method,
            face_count=liveness.face_count or 0,
            details=None
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"  Erreur liveness: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur lors de la vérification de liveness")


# ─────────────────────────────────────────────
# ENDPOINT 6 — LIVENESS SEULE (upload fichier)
# ─────────────────────────────────────────────

@router.post(
    "/liveness/check/upload",
    response_model=LivenessCheckResponse,
    summary="Vérification de liveness seule — Upload",
    description="Analyse la liveness d'un selfie via upload direct."
)
async def check_liveness_upload(
    selfie: UploadFile = File(..., description="Photo selfie (JPEG/PNG/WEBP, max 5MB)"),
) -> LivenessCheckResponse:
    """Vérification de liveness avec upload de fichier."""
    try:
        logger.info(f"[UPLOAD] Liveness check — fichier: {selfie.filename}")
        selfie_b64 = await _file_to_base64(selfie)
        
        liveness = await liveness_checker.check_liveness(selfie_b64)
        
        return LivenessCheckResponse(
            is_live=liveness.passed,
            confidence=liveness.confidence,
            liveness_score=liveness.confidence,
            quality_score=liveness.quality_score or 0.0,
            spoof_score=liveness.spoof_score or 0.0,
            flags=liveness.flags or [],
            method=liveness.method,
            face_count=liveness.face_count or 0,
            details=None
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"  Erreur liveness upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur lors de la vérification de liveness")


# ─────────────────────────────────────────────
# ENDPOINT 7 — DÉTECTION SPOOFING SEULE
# ─────────────────────────────────────────────

class SpoofDetectionResponse(BaseModel):
    is_spoofed: bool
    spoof_confidence: float
    spoof_type: Optional[str]
    flags: List[str]
    method: str
    details: Optional[Dict[str, Any]] = None


@router.post(
    "/liveness/spoof",
    response_model=SpoofDetectionResponse,
    summary="Détection de spoofing seule",
    description="Analyse les tentatives de spoofing sans évaluer la qualité globale."
)
async def detect_spoof_only(request: LivenessCheckRequest) -> SpoofDetectionResponse:
    """Détecte spécifiquement les attaques de spoofing."""
    try:
        logger.info(" Spoof detection seul")
        selfie_b64 = _validate_base64(request.selfie, "selfie")
        
        # Utiliser LivenessChecker
        result = await liveness_checker.detect_spoof_attempts(selfie_b64)
        
        return SpoofDetectionResponse(
            is_spoofed=result.get("is_spoofed", False),
            spoof_confidence=result.get("spoof_confidence", 0.0),
            spoof_type=result.get("spoof_type"),
            flags=result.get("flags", []),
            method=result.get("method", "unknown"),
            details=result.get("details")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"  Erreur spoof detection: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur lors de la détection de spoofing")


# ─────────────────────────────────────────────
# ENDPOINT 8 — COMPARAISON FACIALE
# ─────────────────────────────────────────────

class FaceCompareRequest(BaseModel):
    selfie: str = Field(..., description="Image selfie en base64")
    document_face: str = Field(..., description="Photo extraite du document d'identité en base64")


class FaceCompareResponse(BaseModel):
    match: bool
    confidence: float
    similarity_score: float
    method: str
    error: Optional[str] = None


@router.post(
    "/faces/compare",
    response_model=FaceCompareResponse,
    summary="Comparaison faciale",
    description="Compare un selfie avec la photo d'un document d'identité."
)
async def compare_faces_endpoint(request: FaceCompareRequest) -> FaceCompareResponse:
    """Compare deux visages et détermine s'ils appartiennent à la même personne."""
    try:
        logger.info("👤 Comparaison faciale")
        selfie_b64 = _validate_base64(request.selfie, "selfie")
        document_b64 = _validate_base64(request.document_face, "document_face")
        
        # Utiliser LivenessChecker
        result = await liveness_checker.compare_faces(selfie_b64, document_b64)
        
        return FaceCompareResponse(
            match=result.get("match", False),
            confidence=result.get("confidence", 0.0),
            similarity_score=result.get("similarity_score", 0.0),
            method=result.get("method", "unknown"),
            error=result.get("error")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"  Erreur comparaison faciale: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur lors de la comparaison faciale")


# ─────────────────────────────────────────────
# ENDPOINT 9 — COMPARAISON FACIALE (upload)
# ─────────────────────────────────────────────

@router.post(
    "/faces/compare/upload",
    response_model=FaceCompareResponse,
    summary="Comparaison faciale — Upload",
    description="Compare deux visages via upload de fichiers."
)
async def compare_faces_upload(
    selfie: UploadFile = File(..., description="Photo selfie (JPEG/PNG/WEBP, max 5MB)"),
    document_face: UploadFile = File(..., description="Photo du document (JPEG/PNG/WEBP, max 5MB)"),
) -> FaceCompareResponse:
    """Comparaison faciale avec upload de fichiers."""
    try:
        logger.info(f" [UPLOAD] Comparaison faciale — selfie: {selfie.filename}, document: {document_face.filename}")
        selfie_b64 = await _file_to_base64(selfie)
        document_b64 = await _file_to_base64(document_face)
        
        result = await liveness_checker.compare_faces(selfie_b64, document_b64)
        
        return FaceCompareResponse(
            match=result.get("match", False),
            confidence=result.get("confidence", 0.0),
            similarity_score=result.get("similarity_score", 0.0),
            method=result.get("method", "unknown"),
            error=result.get("error")
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"  Erreur comparaison faciale upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Erreur lors de la comparaison faciale")


# ─────────────────────────────────────────────
# HELPER OCR COMMUN
# ─────────────────────────────────────────────

async def _run_ocr(
    image_b64: str,
    document_type: str,
    *,
    image_back_b64: str = "",
    document_side: Optional[str] = None,
) -> OCRResponse:
    """Exécute l'extraction OCR — partagé par les deux endpoints OCR."""
    try:
        result = await asyncio.wait_for(
            extract_document_ocr(
                ocr_service,
                image_base64=image_b64,
                image_back_base64=image_back_b64,
                document_type=document_type,
                document_side=document_side,
            ),
            timeout=settings.KYC_ANALYZE_TIMEOUT,
        )

        logger.info(
            f"  OCR terminé — provider: {result.get('provider')} "
            f"— confiance: {result.get('confidence', 0):.0%} "
            f"— champs: {len(result.get('detected_fields', {}))}"
        )

        return OCRResponse(
            success=result.get("success", False),
            provider=result.get("provider", "unknown"),
            confidence=result.get("confidence", 0.0),
            document_type=document_type,
            detected_fields=result.get("detected_fields", {}),
            confidence_scores=result.get("confidence_scores", {}),
            warnings=result.get("warnings", []),
            error=result.get("error")
        )

    except asyncio.TimeoutError:
        logger.error(f"  Timeout OCR ({settings.KYC_ANALYZE_TIMEOUT}s)")
        raise HTTPException(
            status_code=504,
            detail=f"OCR timeout après {settings.KYC_ANALYZE_TIMEOUT}s"
        )
