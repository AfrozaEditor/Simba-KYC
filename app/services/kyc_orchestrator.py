"""Orchestrateur KYC principal"""

import base64
import io
import logging
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, date
from app.api.v1.schemas.request.kyc_analyze import KYCAnalyzeRequest
from app.core.models.kyc_result import DocumentType, KYCResult, KYCStatus, KYCData, LivenessCheck
from app.core.models.fraud_indicators import FraudIndicators
from app.core.rules.kyc_rules import KYCRules
from app.services.cni_ocr_runtime import extract_document_ocr
from app.services.document_consistency import compute_document_consistency
from app.services.fraud_detector import FraudDetector
from app.services.liveness_checker import LivenessChecker
from app.services.mrz_service import MRZService
from app.services.qr_cni_decoder import QRCNIDecoder
from PIL import Image, ImageOps
import re

logger = logging.getLogger(__name__)


class KYCOrchestrator:
    """Orchestre le workflow complet d'analyse KYC"""
    
    def __init__(
        self,
        ocr_service=None,
        liveness_service=None,
        fraud_detector: Optional[FraudDetector] = None,
        liveness_checker: Optional[LivenessChecker] = None,
        qr_decoder: Optional[QRCNIDecoder] = None,
        mrz_service: Optional[MRZService] = None,
    ):
        """
        Initialise l'orchestrateur KYC
        
        Args:
            ocr_service: Service d'extraction documentaire (Groq multimodal)
            liveness_service: Service de vérification liveness (AWS Rekognition)
            fraud_detector: Service de détection de fraude
            liveness_checker: Service de vérification de vivacité
            qr_decoder: Service de decodage QR documentaire
            mrz_service: Service d'analyse MRZ (ICAO)
        """
        self.ocr = ocr_service
        self.liveness_service = liveness_service
        
        self.fraud_detector = fraud_detector or FraudDetector(ocr_service, liveness_service)
        self.liveness_checker = liveness_checker or LivenessChecker(liveness_service)
        self.qr_decoder = qr_decoder or QRCNIDecoder()
        self.mrz_service = mrz_service or MRZService()
        self._last_ocr_result: Optional[dict] = None
    
    async def analyze_kyc(self, request: KYCAnalyzeRequest) -> KYCResult:
        """
        Effectue l'analyse KYC complète
        
        Args:
            request: KYCAnalyzeRequest avec documents et selfie
        
        Returns:
            KYCResult avec le verdict d'approbation/rejet
        """
        
        try:
            logger.info(f"Démarrage analyse KYC pour utilisateur {request.user_id}")
            
            # Étape 1: Extraction du texte du document
            kyc_data = await self._extract_kyc_data(
                request.document_front,
                request.document_back or "",
            )
            
            if kyc_data is None:
                return self._create_rejection("Extraction des données document échouée")

            requires_external_face = self._expects_mrz_document(kyc_data)
            if requires_external_face and not request.mrz_face:
                logger.warning("Document PASSPORT sans source externe faciale (mrz_face manquante)")
                return self._create_rejection(
                    "Photo faciale externe requise pour PASSPORT (mrz_face manquante)"
                )
            
            # Étape 2: Vérification de vivacité
            liveness = await self.liveness_checker.check_liveness(request.selfie)
            
            # Étape 3: Comparaison des visages
            document_face_base64, face_extracted = self._extract_document_face(
                request.document_front,
                self._source_value(kyc_data, "document_type"),
            )
            if face_extracted:
                logger.info("Portrait document extrait avant compare_faces")
            else:
                return self._create_rejection("Portrait document introuvable sur la CNI")

            face_scores: List[float] = []

            # 1) Selfie vs photo imprimee sur le document
            printed_compare = await self.liveness_checker.compare_faces(
                request.selfie,
                document_face_base64,
            )
            printed_score = self._coerce_face_score(printed_compare)
            face_scores.append(printed_score)
            logger.info(f"Score selfie vs photo imprimee: {printed_score:.3f}")

            # 2) Source externe documentaire (ex: photo puce/NFC) requise pour PASSPORT
            if requires_external_face and request.mrz_face:
                external_compare = await self.liveness_checker.compare_faces(
                    request.selfie,
                    request.mrz_face,
                )
                external_score = self._coerce_face_score(external_compare)
                face_scores.append(external_score)
                logger.info(f"Score selfie vs source externe documentaire: {external_score:.3f}")

                # 3) Coherence interne: photo imprimee vs source externe documentaire
                consistency_compare = await self.liveness_checker.compare_faces(
                    document_face_base64,
                    request.mrz_face,
                )
                consistency_score = self._coerce_face_score(consistency_compare)
                face_scores.append(consistency_score)
                logger.info(f"Score photo imprimee vs source externe documentaire: {consistency_score:.3f}")
            elif request.mrz_face and not requires_external_face:
                logger.info("mrz_face fournie pour document non PASSPORT: comparaison externe ignorée")

            # Approche prudente: le maillon le plus faible gouverne le score final.
            face_match_score = min(face_scores) if face_scores else 0.0
            logger.info(f"Score facial final (mode prudent): {face_match_score:.3f}")

            # Etape 3.5: Analyse QR documentaire (si present)
            qr_analysis = self.qr_decoder.analyze(
                document_front_base64=request.document_front,
                document_back_base64=request.document_back or "",
            )
            qr_analysis["back_provided"] = bool(request.document_back)
            logger.info(
                "QR analyse: detected=%s error=%s",
                qr_analysis.get("detected"),
                qr_analysis.get("error"),
            )

            if kyc_data and qr_analysis.get("detected") and qr_analysis.get("required_fields_present"):
                kyc_data = self._merge_qr_identity_into_kyc_data(kyc_data, qr_analysis)

            mrz_lines, mrz_text = self._extract_mrz_inputs_from_ocr_result()
            mrz_analysis = self.mrz_service.analyze(
                mrz_lines=mrz_lines,
                raw_text=mrz_text,
                expected=self._expects_mrz_document(kyc_data),
            )
            logger.info(
                "MRZ analyse: expected=%s detected=%s parseable=%s error=%s",
                mrz_analysis.get("expected"),
                mrz_analysis.get("detected"),
                mrz_analysis.get("parseable"),
                mrz_analysis.get("error"),
            )
            
            # Étape 4: Détection de fraude
            fraud_indicators = await self.fraud_detector.analyze_fraud_indicators(
                document_front_base64=request.document_front,
                selfie_base64=request.selfie,
                document_back_base64=request.document_back or "",
                liveness_confidence=liveness.confidence,
                face_match_score=face_match_score,
                metadata=request.metadata,
                liveness_quality_score=liveness.quality_score,
                liveness_flags=liveness.flags,
                liveness_face_count=liveness.face_count,
                kyc_data=kyc_data,
                qr_analysis=qr_analysis,
                mrz_analysis=mrz_analysis,
            )

            consistency = compute_document_consistency(
                qr_analysis=qr_analysis,
                mrz_analysis=mrz_analysis,
                criteria_results=fraud_indicators.criteria_results,
                bonus_cap=100,
            )

            source_checks = self._build_source_checks(
                kyc_data=kyc_data,
                qr_analysis=qr_analysis,
                mrz_analysis=mrz_analysis,
                mobile_money_identity=self._metadata_value(
                    request.metadata,
                    "mobile_money_identity",
                ),
            )

            qr_identity = self._build_source_identity(qr_analysis)
            mrz_identity = self._build_source_identity(mrz_analysis)
            
            # Étape 5: Calcul du score KYC
            kyc_score = KYCRules.generate_kyc_score(
                liveness_confidence=liveness.confidence,
                face_match_score=face_match_score,
                document_integrity=fraud_indicators.document_integrity,
                fraud_flags=fraud_indicators.flags,      
                criteria_results=fraud_indicators.criteria_results,
                account_age_days=0,
                document_consistency_bonus=consistency["consistency_bonus"],
            )
            
            # Étape 6: Détermination du statut
            status, recommendation = KYCRules.determine_kyc_status(
                valid=True,
                liveness_passed=liveness.passed,
                liveness_confidence=liveness.confidence,
                face_match_score=face_match_score,
                document_integrity=fraud_indicators.document_integrity,
                fraud_flags=fraud_indicators.flags,
                kyc_score=kyc_score,
                hard_reject_criteria=fraud_indicators.hard_reject_criteria,
                manual_review_criteria=fraud_indicators.manual_review_criteria,
            )

            rejection_reason = self._derive_rejection_reason(
                status=status,
                liveness=liveness,
                face_match_score=face_match_score,
                fraud_indicators=fraud_indicators,
            )
            
            # Retour du résultat
            result = KYCResult(
                valid=status == KYCStatus.APPROVED or status == KYCStatus.MANUAL_REVIEW,
                status=KYCStatus(status),
                reason=rejection_reason,
                kyc_data=kyc_data,
                liveness=liveness,
                fraud_indicators=fraud_indicators,
                qr_confidence=consistency["qr_confidence"],
                mrz_confidence=consistency["mrz_confidence"],
                document_consistency=consistency["document_consistency"],
                source_checks=source_checks,
                qr_data=qr_identity,
                mrz_data=mrz_identity,
                kyc_score=kyc_score,
                recommendation=recommendation
            )
            
            logger.info(f"Analyse KYC complète: {status} pour {request.user_id}")
            return result
            
        except Exception as e:
            logger.error(f"Erreur analyse KYC: {str(e)}", exc_info=True)
            return self._create_error_result(str(e))
    
    async def _extract_kyc_data(
        self,
        document_front_base64: str,
        document_back_base64: str = "",
    ) -> Optional[KYCData]:
        """Extrait les données KYC du document"""
        
        if self.ocr is None:
            self._last_ocr_result = None
            logger.error("OCR indisponible")
            return None
        
        try:
            ocr_result = await extract_document_ocr(
                self.ocr,
                image_base64=document_front_base64,
                image_back_base64=document_back_base64,
                document_type="CNI_CAMEROON",
            )
            self._last_ocr_result = ocr_result
            if not ocr_result.get("success", True):
                if self._is_provider_failure(ocr_result):
                    raise RuntimeError(self._build_provider_failure_reason(ocr_result))
                return None
            fields = ocr_result.get("detected_fields") or {}
            
            # Parse dates from string format to date objects
            dob = self._parse_date(fields.get("date_of_birth"))
            expiry = self._parse_date(fields.get("expiry_date"))
            
            first_name = str(fields.get("first_name") or "").strip()
            last_name = str(fields.get("last_name") or "").strip()
            full_name = str(fields.get("full_name") or "").strip()
            if not full_name and (first_name or last_name):
                full_name = f"{first_name} {last_name}".strip()
            
            return KYCData(
                full_name=full_name,
                first_name=first_name,
                last_name=last_name,
                date_of_birth=dob or date.today(),
                national_id=fields.get("national_id", ""),
                document_type=fields.get("document_type", "CNI_CAMEROON"),
                expiry_date=expiry,
                country=fields.get("country", ""),
                address=fields.get("address"),
                gender=fields.get("gender")
            )
            
        except RuntimeError:
            raise
        except Exception as e:
            logger.error(f"Erreur extraction données KYC: {str(e)}")
            self._last_ocr_result = None
            return None

    @staticmethod
    def _is_provider_failure(result: Dict[str, Any]) -> bool:
        """Distingue une panne provider d'un document simplement illisible."""

        warnings = result.get("warnings") or []
        if any(w in {"all_providers_failed", "no_results"} for w in warnings):
            return True

        error_text = str(result.get("error") or "").lower()
        failure_markers = [
            "not configured",
            "connection refused",
            "timed out",
            "http ",
            "provider",
        ]
        return any(marker in error_text for marker in failure_markers)

    @staticmethod
    def _build_provider_failure_reason(result: Dict[str, Any]) -> str:
        """Construit un message lisible pour les pannes OCR provider."""

        attempts = result.get("all_attempts") or {}
        summarized = []
        for provider, attempt in attempts.items():
            if isinstance(attempt, dict):
                error = attempt.get("error") or attempt.get("warnings") or "unavailable"
                summarized.append(f"{provider}: {error}")

        if summarized:
            return f"OCR providers indisponibles ({'; '.join(summarized[:3])})"

        return "OCR providers indisponibles"

    def _extract_mrz_inputs_from_ocr_result(self) -> Tuple[List[str], str]:
        """Recupere des lignes MRZ candidates depuis la derniere sortie OCR."""

        if not self._last_ocr_result:
            return [], ""

        lines: List[str] = []
        text_chunks: List[str] = []
        result = self._last_ocr_result

        fields = result.get("detected_fields", {}) if isinstance(result, dict) else {}

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
            elif isinstance(value, list):
                for item in value:
                    add_line_candidate(item)

        for key in ("mrz_lines", "mrz_line1", "mrz_line2", "mrz_line3", "mrz", "mrz_text"):
            add_line_candidate(fields.get(key))
            add_line_candidate(result.get(key))

        for key in ("text", "raw_text", "raw_response"):
            chunk = result.get(key)
            if isinstance(chunk, str) and chunk.strip():
                text_chunks.append(chunk)

        # Dedup stable
        dedup_lines: List[str] = []
        seen = set()
        for line in lines:
            if line not in seen:
                seen.add(line)
                dedup_lines.append(line)

        return dedup_lines, "\n".join(text_chunks)

    def _build_source_checks(
        self,
        *,
        kyc_data: Optional[KYCData],
        qr_analysis: Optional[Dict[str, Any]],
        mrz_analysis: Optional[Dict[str, Any]],
        mobile_money_identity: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        checks: Dict[str, Any] = {}

        checks["ocr_vs_qr"] = self._compare_source(
            source="qr",
            ocr_data=kyc_data,
            parsed_fields=(qr_analysis or {}).get("parsed_fields", {}) or {},
            available=bool((qr_analysis or {}).get("detected")),
            unavailable_reason=(qr_analysis or {}).get("error"),
        )

        mrz_detected = bool((mrz_analysis or {}).get("detected"))
        mrz_parseable = bool((mrz_analysis or {}).get("parseable"))
        mrz_expected = bool((mrz_analysis or {}).get("expected"))
        if not mrz_expected and not mrz_detected:
            checks["ocr_vs_mrz"] = {
                "source": "mrz",
                "status": "skipped",
                "message": "MRZ non applicable pour ce document.",
                "checked_fields": [],
                "field_issues": [],
            }
        else:
            checks["ocr_vs_mrz"] = self._compare_source(
                source="mrz",
                ocr_data=kyc_data,
                parsed_fields=(mrz_analysis or {}).get("parsed_fields", {}) or {},
                available=mrz_detected and mrz_parseable,
                unavailable_reason=(mrz_analysis or {}).get("error"),
            )

        checks["ocr_vs_mobile_money"] = self._compare_mobile_money_source(
            ocr_data=kyc_data,
            mobile_money_identity=mobile_money_identity,
        )

        return checks

    def _compare_mobile_money_source(
        self,
        *,
        ocr_data: Optional[KYCData],
        mobile_money_identity: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not mobile_money_identity:
            return {
                "source": "mobile_money",
                "status": "not_available",
                "message": "Identité Mobile Money non fournie.",
                "checked_fields": [],
                "field_issues": [],
            }

        mobile_money_full_name = self._normalize_text(
            str(mobile_money_identity.get("mobile_money_full_name") or mobile_money_identity.get("full_name") or "")
        )
        if ocr_data is None:
            return {
                "source": "mobile_money",
                "status": "not_available",
                "message": "OCR indisponible pour comparaison Mobile Money.",
                "checked_fields": [],
                "field_issues": [],
            }

        ocr_full_name = self._normalize_text(self._build_full_name_from_ocr(ocr_data))
        if not ocr_full_name or not mobile_money_full_name:
            return {
                "source": "mobile_money",
                "status": "not_available",
                "message": "Nom CNI ou nom Mobile Money indisponible.",
                "checked_fields": [],
                "field_issues": [],
            }

        if ocr_full_name == mobile_money_full_name:
            return {
                "source": "mobile_money",
                "status": "matched",
                "message": "Nom CNI conforme au titulaire Mobile Money.",
                "checked_fields": ["full_name"],
                "field_issues": [],
            }

        return {
            "source": "mobile_money",
            "status": "mismatch",
            "message": "Nom CNI différent du titulaire Mobile Money.",
            "checked_fields": ["full_name"],
            "field_issues": [
                {
                    "field": "full_name",
                    "label": "Nom complet",
                    "declared": ocr_full_name,
                    "detected": mobile_money_full_name,
                    "severity": "warning",
                    "message": "Incoherence entre CNI OCR et titulaire Mobile Money.",
                }
            ],
        }

    def _compare_source(
        self,
        *,
        source: str,
        ocr_data: Optional[KYCData],
        parsed_fields: Dict[str, Any],
        available: bool,
        unavailable_reason: Optional[str],
    ) -> Dict[str, Any]:
        if not available:
            message = "Source non disponible."
            if unavailable_reason:
                message = f"Source non disponible ({unavailable_reason})."
            return {
                "source": source,
                "status": "not_available",
                "message": message,
                "checked_fields": [],
                "field_issues": [],
            }

        if ocr_data is None:
            return {
                "source": source,
                "status": "not_available",
                "message": "OCR indisponible pour comparaison.",
                "checked_fields": [],
                "field_issues": [],
            }

        ocr_full_name = self._normalize_text(self._build_full_name_from_ocr(ocr_data))
        ocr_national_id = self._normalize_text(str(ocr_data.national_id or ""))
        ocr_dob = self._normalize_date_value(ocr_data.date_of_birth)

        source_full_name = self._normalize_text(self._build_full_name_from_fields(parsed_fields))
        source_national_id = self._normalize_text(str(parsed_fields.get("national_id") or ""))
        source_dob = self._normalize_date_value(parsed_fields.get("date_of_birth"))

        compared: List[str] = []
        issues: List[Dict[str, Any]] = []
        matches = 0

        def compare_field(field: str, label: str, ocr_value: str, src_value: str) -> None:
            nonlocal matches
            if not ocr_value or not src_value:
                return
            compared.append(field)
            if ocr_value == src_value:
                matches += 1
                return
            issues.append(
                {
                    "field": field,
                    "label": label,
                    "declared": ocr_value,
                    "detected": src_value,
                    "severity": "warning",
                    "message": "Incoherence entre OCR et source.",
                }
            )

        compare_field("full_name", "Nom complet", ocr_full_name, source_full_name)
        compare_field("national_id", "Numero du document", ocr_national_id, source_national_id)
        compare_field("date_of_birth", "Date de naissance", ocr_dob, source_dob)

        if not compared:
            return {
                "source": source,
                "status": "not_available",
                "message": "Aucun champ comparable disponible.",
                "checked_fields": [],
                "field_issues": [],
            }

        if not issues:
            status = "matched"
            message = "Conforme."
        elif matches > 0:
            status = "partial_mismatch"
            message = "Ecarts mineurs detectes."
        else:
            status = "mismatch"
            message = "Incoherence detectee."

        return {
            "source": source,
            "status": status,
            "message": message,
            "checked_fields": compared,
            "field_issues": issues,
        }

    @staticmethod
    def _build_source_identity(source_analysis: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not source_analysis:
            return {}

        parsed_fields = source_analysis.get("parsed_fields") if isinstance(source_analysis, dict) else None
        if not isinstance(parsed_fields, dict):
            return {}

        def pick(field: str) -> str:
            return str(parsed_fields.get(field) or "").strip()

        full_name = pick("full_name")
        if not full_name:
            first = pick("first_name")
            last = pick("last_name")
            full_name = f"{first} {last}".strip()

        return {
            "full_name": full_name,
            "national_id": pick("national_id"),
            "date_of_birth": pick("date_of_birth"),
            "country": pick("country") or pick("nationality"),
        }

    @staticmethod
    def _build_full_name_from_ocr(kyc_data: KYCData) -> str:
        full_name = str(kyc_data.full_name or "").strip()
        if full_name:
            return full_name
        first = str(kyc_data.first_name or "").strip()
        last = str(kyc_data.last_name or "").strip()
        return f"{first} {last}".strip()

    @staticmethod
    def _build_full_name_from_fields(fields: Dict[str, Any]) -> str:
        full_name = str(fields.get("full_name") or "").strip()
        if full_name:
            return full_name
        first = str(fields.get("first_name") or "").strip()
        last = str(fields.get("last_name") or "").strip()
        return f"{first} {last}".strip()

    @staticmethod
    def _normalize_text(value: str) -> str:
        return re.sub(r"[^A-Z0-9]", "", (value or "").upper())

    @staticmethod
    def _normalize_date_value(value: Any) -> str:
        if value is None:
            return ""
        if hasattr(value, "isoformat"):
            return str(value.isoformat())
        if isinstance(value, str):
            parsed = KYCOrchestrator._parse_date(value)
            if parsed:
                return parsed.isoformat()
            return value.strip()
        return ""

    def _extract_document_face(
        self,
        document_front_base64: str,
        document_type: Optional[str] = None,
    ) -> Tuple[str, bool]:
        """Extrait le portrait principal du document; fallback sur l'image complete."""

        try:
            liveness_service = getattr(self.liveness_checker, "service", None)
            if liveness_service and hasattr(liveness_service, "extract_face_base64"):
                aws_result = liveness_service.extract_face_base64(document_front_base64)
                if isinstance(aws_result, dict) and aws_result.get("success"):
                    logger.info("Portrait document extrait via AWS DetectFaces")
                    return aws_result.get("face_base64", document_front_base64), True
        except Exception as exc:
            logger.warning(f"Echec extraction portrait document: {exc}")

        return document_front_base64, False

    def _extract_document_face_with_heuristic(
        self,
        document_front_base64: str,
        document_type: Optional[str] = None,
    ) -> Tuple[str, bool]:
        """Fallback sans OpenCV: crop heuristique de la zone portrait."""

        try:
            image_bytes = base64.b64decode(document_front_base64)
            image = Image.open(io.BytesIO(image_bytes))
            image = ImageOps.exif_transpose(image).convert("RGB")

            width, height = image.size
            if width < 64 or height < 64:
                return document_front_base64, False

            doc_type = str(document_type or "").upper()

            # Portrait le plus souvent a gauche sur les CNI; plus recentre pour le reste.
            if "CNI" in doc_type or "NATIONAL_ID" in doc_type:
                crop_box = (
                    0,
                    int(height * 0.10),
                    int(width * 0.42),
                    int(height * 0.92),
                )
            else:
                crop_box = (
                    int(width * 0.02),
                    int(height * 0.08),
                    int(width * 0.48),
                    int(height * 0.90),
                )

            crop = image.crop(crop_box)
            if crop.size[0] < 32 or crop.size[1] < 32:
                return document_front_base64, False

            out = io.BytesIO()
            crop.save(out, format="JPEG", quality=90, optimize=True)
            face_base64 = base64.b64encode(out.getvalue()).decode("utf-8")
            logger.info("Portrait document extrait via fallback heuristique")
            return face_base64, True
        except Exception as exc:
            logger.warning(f"Echec extraction portrait heuristique: {exc}")
            return document_front_base64, False

    @staticmethod
    def _coerce_face_score(compare_result: Any) -> float:
        """Normalise un score facial en float dans [0,1]."""

        if not isinstance(compare_result, dict):
            return 0.0

        raw_score = compare_result.get(
            "confidence",
            compare_result.get("similarity_score", 0.0),
        )
        if isinstance(raw_score, dict):
            return 0.0

        try:
            value = float(raw_score)
        except (TypeError, ValueError):
            return 0.0

        return max(0.0, min(1.0, value))

    @staticmethod
    def _expects_mrz_document(kyc_data: Optional[KYCData]) -> bool:
        """Determine si le document exige une MRZ/source faciale externe.

        Les CNI camerounaises peuvent contenir un QR ou des donnees exploitables,
        mais le flux APS ne fournit pas de photo faciale externe NFC/MRZ pour ce
        type de document. Cette exigence stricte est reservee aux passeports.
        """

        if kyc_data is None:
            return False

        document_type = str(KYCOrchestrator._source_value(kyc_data, "document_type") or "").upper()
        return document_type in {
            "DOCUMENTTYPE.PASSPORT",
            "PASSPORT",
        }

    @staticmethod
    def _source_value(source: Any, key: str) -> Any:
        if source is None:
            return None
        if isinstance(source, dict):
            return source.get(key)
        return getattr(source, key, None)

    @staticmethod
    def _derive_rejection_reason(
        status: Any,
        liveness: LivenessCheck,
        face_match_score: float,
        fraud_indicators: FraudIndicators,
    ) -> Optional[str]:
        """Retourne une raison explicite pour les rejets et revues manuelles."""

        status_value = str(status)
        if status_value not in {"REJECTED", "KYCStatus.REJECTED", "MANUAL_REVIEW", "KYCStatus.MANUAL_REVIEW"}:
            return None

        criteria_results = fraud_indicators.criteria_results or []

        def format_criterion_detail(criterion_id: str, evidence: Dict[str, Any]) -> str:
            if criterion_id == "AF-037":
                score = evidence.get("document_integrity")
                threshold = evidence.get("threshold")
                if isinstance(score, (int, float)) and isinstance(threshold, (int, float)):
                    gap = threshold - score
                    return f"score={score:.2f}, seuil={threshold:.2f}, ecart={gap:.2f}"

            if criterion_id in {"AF-042", "AF-043"}:
                signal = str(evidence.get("flag") or "")
                score = evidence.get("document_integrity")
                threshold = evidence.get("suspect_threshold")
                signal_label = {
                    "document_tampered_suspected": "anomalies visuelles de manipulation",
                    "document_fake_suspected": "indices de faux document",
                }.get(signal, signal)
                parts: List[str] = []
                if signal_label:
                    parts.append(f"signal={signal_label}")
                if isinstance(score, (int, float)) and isinstance(threshold, (int, float)):
                    gap = threshold - score
                    parts.append(f"score={score:.2f}, seuil_ref={threshold:.2f}, marge={gap:.2f}")
                if parts:
                    return ", ".join(parts)

            return ""

        def summarize(criteria_ids: List[str], *, level_name: str) -> Optional[str]:
            reasons: List[str] = []
            for criterion in criteria_results:
                if criterion.criterion_id in criteria_ids and criterion.reason:
                    detail = format_criterion_detail(criterion.criterion_id, criterion.evidence or {})
                    if detail:
                        reasons.append(f"{criterion.reason} ({detail})")
                    else:
                        reasons.append(criterion.reason)
            if reasons:
                unique_reasons = list(dict.fromkeys(reasons))
                return f"{level_name}: {'; '.join(unique_reasons[:3])}"
            return None

        hard_criteria = fraud_indicators.hard_reject_criteria or []
        if hard_criteria:
            detailed = summarize(hard_criteria, level_name="Rejet automatique")
            if detailed:
                return detailed
            return f"Rejet automatique: {', '.join(hard_criteria[:3])}"

        manual_criteria = fraud_indicators.manual_review_criteria or []
        if manual_criteria:
            detailed = summarize(manual_criteria, level_name="Revue manuelle requise")
            if detailed:
                return detailed
            return f"Revue manuelle requise: {', '.join(manual_criteria[:3])}"

        flags = fraud_indicators.flags or []
        if flags:
            return f"Signaux de fraude: {', '.join(flags[:3])}"

        if not liveness.passed:
            return "Verification de vivacite echouee"

        if face_match_score < 0.80:
            return f"Correspondance faciale insuffisante ({face_match_score:.2f})"

        if status_value in {"MANUAL_REVIEW", "KYCStatus.MANUAL_REVIEW"}:
            return "Revue manuelle requise"

        return "Rejet par les regles KYC"

    @staticmethod
    def _merge_qr_identity_into_kyc_data(kyc_data: KYCData, qr_analysis: Dict[str, Any]) -> KYCData:
        """Prend les champs d'identité du QR comme source de vérité pour la CNI."""

        parsed_fields = qr_analysis.get("parsed_fields") or {}
        if not parsed_fields:
            return kyc_data

        full_name = str(parsed_fields.get("full_name") or kyc_data.full_name or "").strip()
        name_parts = full_name.split() if full_name else []
        first_name = str(parsed_fields.get("first_name") or (name_parts[0] if name_parts else kyc_data.first_name)).strip()
        last_name = str(
            parsed_fields.get("last_name")
            or (" ".join(name_parts[1:]) if len(name_parts) > 1 else kyc_data.last_name)
        ).strip()
        date_of_birth = kyc_data.date_of_birth
        qr_dob = parsed_fields.get("date_of_birth")
        if qr_dob:
            parsed_dob = KYCOrchestrator._parse_date(qr_dob)
            if parsed_dob:
                date_of_birth = parsed_dob

        expiry_date = kyc_data.expiry_date
        qr_expiry = parsed_fields.get("expiry_date")
        if qr_expiry:
            parsed_expiry = KYCOrchestrator._parse_date(qr_expiry)
            if parsed_expiry:
                expiry_date = parsed_expiry

        country = str(parsed_fields.get("country") or kyc_data.country or "").strip()
        gender = str(parsed_fields.get("gender") or kyc_data.gender or "").strip() or None
        national_id = str(parsed_fields.get("national_id") or kyc_data.national_id or "").strip()

        return kyc_data.model_copy(
            update={
                "full_name": full_name,
                "first_name": first_name,
                "last_name": last_name,
                "date_of_birth": date_of_birth,
                "national_id": national_id,
                "expiry_date": expiry_date,
                "country": country,
                "gender": gender,
            }
        )
    
    @staticmethod
    def _parse_date(date_str: Optional[str]) -> Optional[date]:
        """Parse date string in YYYY-MM-DD or DD/MM/YYYY format"""
        if not date_str:
            return None
        
        try:
            # Try YYYY-MM-DD format
            if isinstance(date_str, str) and len(date_str) == 10 and date_str[4] == '-':
                parts = date_str.split('-')
                return date(int(parts[0]), int(parts[1]), int(parts[2]))
            
            # Try DD/MM/YYYY format
            if isinstance(date_str, str) and '/' in date_str:
                parts = date_str.split('/')
                if len(parts) == 3:
                    return date(int(parts[2]), int(parts[1]), int(parts[0]))
        
        except (ValueError, IndexError) as e:
            logger.warning(f"Impossible de parser la date '{date_str}': {str(e)}")
        
        return None
    
    def _create_rejection(self, reason: str) -> KYCResult:
        """Crée un résultat de rejet"""
        return KYCResult(
            valid=False,
            status=KYCStatus.REJECTED,
            reason=reason,
            kyc_data=None,
            liveness=None,
            fraud_indicators=FraudIndicators(
                document_integrity=0.0,
                face_match_score=0.0,
                is_suspicious=True,
                flags=["kyc_extraction_failed"]
            ),
            kyc_score=0,
            recommendation="AUTO_REJECT"
        )
    
    def _create_error_result(self, error_msg: str) -> KYCResult:
        """Crée un résultat d'erreur (demande révision manuelle)"""
        return KYCResult(
            valid=False,
            status=KYCStatus.MANUAL_REVIEW,
            reason=f"Erreur lors de l'analyse: {error_msg}",
            kyc_data=None,
            liveness=None,
            fraud_indicators=FraudIndicators(
                document_integrity=0.0,
                face_match_score=0.0,
                is_suspicious=True,
                flags=["kyc_analysis_error"]
            ),
            kyc_score=0,
            recommendation="MANUAL_REVIEW"
        )
