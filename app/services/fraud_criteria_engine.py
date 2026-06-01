"""Moteur de criteres anti-fraude AF-xxx (phase 0)."""

from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.core.models.fraud_indicators import (
    FraudCriterionLevel,
    FraudCriterionResult,
    FraudCriterionStatus,
)


class FraudCriteriaEngine:
    """Evalue un premier lot de criteres anti-fraude explicables.

    Cette implementation initialise l'architecture criteres/evidences sans
    casser le contrat existant. Les regles sont deterministes et traceables.
    """

    MIN_BASE64_LEN = 500
    MIN_LIVENESS_CONFIDENCE = 0.85
    MIN_FACE_MATCH = 0.80
    MIN_DOCUMENT_INTEGRITY = 0.75

    def evaluate(
        self,
        *,
        document_front_base64: str,
        selfie_base64: str,
        liveness_confidence: float,
        face_match_score: float,
        document_integrity: float,
        fraud_flags: List[str],
        metadata: Optional[Any] = None,
        liveness_quality_score: Optional[float] = None,
        liveness_flags: Optional[List[str]] = None,
        liveness_face_count: Optional[int] = None,
        kyc_data: Optional[Any] = None,
        qr_analysis: Optional[Dict[str, Any]] = None,
        mrz_analysis: Optional[Dict[str, Any]] = None,
    ) -> List[FraudCriterionResult]:
        """Retourne les criteres declenches uniquement (etat FAIL)."""

        results: List[FraudCriterionResult] = []
        flags = set(fraud_flags or [])
        liveness_flags_set = set(liveness_flags or [])
        qr_fields_for_cross: Dict[str, Any] = {}
        mrz_fields_for_cross: Dict[str, Any] = {}

        if bool((qr_analysis or {}).get("detected")):
            qr_fields_for_cross = (qr_analysis or {}).get("parsed_fields", {}) or {}

        # AF-001 / AF-002: donnees minimales manquantes
        if not document_front_base64:
            self._add_failure(
                results,
                criterion_id="AF-001",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-250,
                reason="Image document recto absente.",
                evidence={"field": "document_front"},
            )

        if not selfie_base64:
            self._add_failure(
                results,
                criterion_id="AF-002",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-250,
                reason="Image selfie absente.",
                evidence={"field": "selfie"},
            )

        # AF-003 / AF-004: payload trop court
        if document_front_base64 and len(document_front_base64) < self.MIN_BASE64_LEN:
            self._add_failure(
                results,
                criterion_id="AF-003",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-60,
                reason="Image document recto probablement tronquee ou tres faible.",
                evidence={"length": len(document_front_base64), "min": self.MIN_BASE64_LEN},
            )

        if selfie_base64 and len(selfie_base64) < self.MIN_BASE64_LEN:
            self._add_failure(
                results,
                criterion_id="AF-004",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-60,
                reason="Image selfie probablement tronquee ou tres faible.",
                evidence={"length": len(selfie_base64), "min": self.MIN_BASE64_LEN},
            )

        # AF-007: qualite selfie insuffisante
        if liveness_quality_score is not None and liveness_quality_score < 0.60:
            self._add_failure(
                results,
                criterion_id="AF-007",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-70,
                reason="Qualite selfie insuffisante pour une verification fiable.",
                evidence={"quality_score": liveness_quality_score, "threshold": 0.60},
            )

        # AF-008 / AF-009: cardinalite visage incoherente
        if liveness_face_count is not None and liveness_face_count > 1:
            self._add_failure(
                results,
                criterion_id="AF-008",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-90,
                reason="Plusieurs visages detectes sur le selfie.",
                evidence={"face_count": liveness_face_count},
            )

        if liveness_face_count is not None and liveness_face_count == 0:
            self._add_failure(
                results,
                criterion_id="AF-009",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-150,
                reason="Aucun visage detecte sur le selfie.",
                evidence={"face_count": liveness_face_count},
            )

        # AF-010 / AF-011: indicateurs de capture critique
        if "eyes_closed" in liveness_flags_set:
            self._add_failure(
                results,
                criterion_id="AF-010",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-40,
                reason="Selfie avec yeux fermes, verification d'identite moins fiable.",
                evidence={"liveness_flags": sorted(liveness_flags_set)},
            )

        if liveness_flags_set.intersection({"strong_reflection", "poor_lighting", "screen_pattern_detected"}):
            self._add_failure(
                results,
                criterion_id="AF-011",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-60,
                reason="Capture selfie degradee (reflet, lumiere, ou pattern ecran).",
                evidence={"liveness_flags": sorted(liveness_flags_set)},
            )

        has_strong_biometric_evidence = (
            liveness_confidence >= 0.90
            and face_match_score >= 0.90
            and "spoofing_attempt" not in flags
            and "no_face_match" not in flags
        )
        has_only_ambiguous_visual_flags = bool(
            flags.intersection({"document_tampered_suspected", "document_fake_suspected"})
        ) and not flags.intersection({"document_tampered", "document_fake"})
        suppress_ambiguous_visual_manual = (
            has_strong_biometric_evidence
            and has_only_ambiguous_visual_flags
            and document_integrity >= 0.35
        )

        # AF-037 / AF-084: integrite documentaire faible
        if document_integrity < self.MIN_DOCUMENT_INTEGRITY and not suppress_ambiguous_visual_manual:
            self._add_failure(
                results,
                criterion_id="AF-037",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-90,
                reason="Score d'integrite documentaire sous le seuil d'acceptation.",
                evidence={"document_integrity": document_integrity, "threshold": self.MIN_DOCUMENT_INTEGRITY},
            )

        if document_integrity < 0.30:
            self._add_failure(
                results,
                criterion_id="AF-084",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-200,
                reason="Integrite documentaire critique (< 0.30).",
                evidence={"document_integrity": document_integrity, "threshold": 0.30},
            )

        if "document_tampered_suspected" in flags and (
            not suppress_ambiguous_visual_manual or document_integrity < 0.35
        ):
            self._add_failure(
                results,
                criterion_id="AF-042",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-80,
                reason="Suspicion de manipulation documentaire a confirmer.",
                evidence={
                    "flag": "document_tampered_suspected",
                    "document_integrity": document_integrity,
                    "suspect_threshold": 0.35,
                },
            )

        if "document_fake_suspected" in flags and (
            not suppress_ambiguous_visual_manual or document_integrity < 0.35
        ):
            self._add_failure(
                results,
                criterion_id="AF-043",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-80,
                reason="Suspicion de faux document a confirmer.",
                evidence={
                    "flag": "document_fake_suspected",
                    "document_integrity": document_integrity,
                    "suspect_threshold": 0.35,
                },
            )

        # AF-040 / AF-041: fraude documentaire explicite
        if "document_tampered" in flags:
            self._add_failure(
                results,
                criterion_id="AF-040",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-220,
                reason="Document potentiellement manipule detecte.",
                evidence={"flag": "document_tampered"},
            )

        if "document_fake" in flags:
            self._add_failure(
                results,
                criterion_id="AF-041",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-220,
                reason="Document potentiellement faux detecte.",
                evidence={"flag": "document_fake"},
            )

        # AF-044 / AF-046: seuils de coherence biometrique
        if face_match_score < self.MIN_FACE_MATCH:
            self._add_failure(
                results,
                criterion_id="AF-044",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-100,
                reason="Correspondance faciale sous le seuil de confiance.",
                evidence={"face_match_score": face_match_score, "threshold": self.MIN_FACE_MATCH},
            )

        if liveness_confidence < self.MIN_LIVENESS_CONFIDENCE:
            self._add_failure(
                results,
                criterion_id="AF-046",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-100,
                reason="Confiance liveness sous le seuil minimum.",
                evidence={"liveness_confidence": liveness_confidence, "threshold": self.MIN_LIVENESS_CONFIDENCE},
            )

        # AF-074 / AF-076 / AF-078 / AF-079: flags anti-spoof et match visage
        if "spoofing_attempt" in flags:
            self._add_failure(
                results,
                criterion_id="AF-074",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-250,
                reason="Tentative de spoofing detectee.",
                evidence={"flag": "spoofing_attempt"},
            )

        if "liveness_suspicious" in flags:
            self._add_failure(
                results,
                criterion_id="AF-076",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-90,
                reason="Liveness suspecte, revue manuelle requise.",
                evidence={"flag": "liveness_suspicious"},
            )

        if "no_face_match" in flags:
            self._add_failure(
                results,
                criterion_id="AF-078",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-250,
                reason="Absence de correspondance faciale document/selfie.",
                evidence={"flag": "no_face_match"},
            )

        if "low_face_match" in flags:
            self._add_failure(
                results,
                criterion_id="AF-079",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-80,
                reason="Correspondance faciale faible.",
                evidence={"flag": "low_face_match"},
            )

        # AF-086: contradiction forte (liveness tres haute mais spoof explicite)
        if liveness_confidence >= 0.90 and "spoofing_attempt" in flags:
            self._add_failure(
                results,
                criterion_id="AF-086",
                level=FraudCriterionLevel.HARD_REJECT,
                score_impact=-220,
                reason="Contradiction forte: liveness elevee mais spoofing detecte.",
                evidence={"liveness_confidence": liveness_confidence, "flags": sorted(flags)},
            )

        # AF-089..AF-094: contexte et metadata
        ip_address = self._metadata_value(metadata, "ip_address")
        if ip_address and not self._is_valid_ip(ip_address):
            self._add_failure(
                results,
                criterion_id="AF-089",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-40,
                reason="Adresse IP invalide dans les metadata.",
                evidence={"ip_address": ip_address},
            )

        device_id = self._metadata_value(metadata, "device_id")
        if not device_id:
            self._add_failure(
                results,
                criterion_id="AF-090",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-50,
                reason="Device ID absent dans les metadata.",
                evidence={"device_id": device_id},
            )

        app_version = self._metadata_value(metadata, "app_version")
        if not app_version:
            self._add_failure(
                results,
                criterion_id="AF-093",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-30,
                reason="Version applicative absente dans les metadata.",
                evidence={"app_version": app_version},
            )
        elif not re.match(r"^\d+\.\d+(\.\d+)?$", str(app_version)):
            self._add_failure(
                results,
                criterion_id="AF-094",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-20,
                reason="Version applicative au format inattendu.",
                evidence={"app_version": app_version},
            )

        request_ts = self._normalize_timestamp(self._metadata_value(metadata, "timestamp"))
        if request_ts is not None:
            now = datetime.now(timezone.utc)
            if request_ts > now + timedelta(minutes=10):
                self._add_failure(
                    results,
                    criterion_id="AF-092",
                    level=FraudCriterionLevel.MANUAL_REVIEW,
                    score_impact=-40,
                    reason="Timestamp metadata dans le futur.",
                    evidence={"timestamp": request_ts.isoformat()},
                )
            if request_ts < now - timedelta(hours=24):
                self._add_failure(
                    results,
                    criterion_id="AF-091",
                    level=FraudCriterionLevel.MANUAL_REVIEW,
                    score_impact=-40,
                    reason="Timestamp metadata trop ancien.",
                    evidence={"timestamp": request_ts.isoformat()},
                )

        # AF-063..AF-069: securite QR documentaire (premier lot)
        if self._expects_qr(kyc_data):
            qr_detected = bool((qr_analysis or {}).get("detected"))
            qr_back_provided = bool((qr_analysis or {}).get("back_provided"))

            if not qr_detected:
                if qr_back_provided:
                    self._add_failure(
                        results,
                        criterion_id="AF-063",
                        level=FraudCriterionLevel.MANUAL_REVIEW,
                        score_impact=-80,
                        reason="QR documentaire non detecte ou non lisible.",
                        evidence={
                            "qr_detected": False,
                            "qr_error": (qr_analysis or {}).get("error"),
                            "back_provided": qr_back_provided,
                        },
                    )
            else:
                if (qr_analysis or {}).get("prefix_valid") is False:
                    self._add_failure(
                        results,
                        criterion_id="AF-064",
                        level=FraudCriterionLevel.INFO,
                        score_impact=-20,
                        reason="Prefixe QR inattendu (IDB1D non detecte).",
                        evidence={"prefix_valid": False, "source": (qr_analysis or {}).get("source")},
                    )

                if (qr_analysis or {}).get("base32_valid") is False:
                    self._add_failure(
                        results,
                        criterion_id="AF-065",
                        level=FraudCriterionLevel.MANUAL_REVIEW,
                        score_impact=-100,
                        reason="Decodage base32 du QR invalide.",
                        evidence={"base32_valid": False},
                    )

                if (qr_analysis or {}).get("decompression_valid") is False:
                    self._add_failure(
                        results,
                        criterion_id="AF-066",
                        level=FraudCriterionLevel.MANUAL_REVIEW,
                        score_impact=-100,
                        reason="Decompression QR invalide ou non conforme.",
                        evidence={"decompression_valid": False},
                    )

                if (qr_analysis or {}).get("required_fields_present") is False:
                    self._add_failure(
                        results,
                        criterion_id="AF-068",
                        level=FraudCriterionLevel.MANUAL_REVIEW,
                        score_impact=-120,
                        reason="Champs QR obligatoires incomplets.",
                        evidence={"parsed_fields": (qr_analysis or {}).get("parsed_fields", {})},
                    )

                mismatches = self._get_qr_identity_mismatches(
                    kyc_data=kyc_data,
                    qr_fields=(qr_analysis or {}).get("parsed_fields", {}),
                )
                if mismatches:
                    self._add_failure(
                        results,
                        criterion_id="AF-069",
                        level=FraudCriterionLevel.HARD_REJECT,
                        score_impact=-240,
                        reason="Incoherence forte entre QR et donnees OCR.",
                        evidence={"mismatches": mismatches},
                    )

        # AF-054..AF-062: securite MRZ documentaire (premier lot)
        if self._expects_mrz(kyc_data=kyc_data, mrz_analysis=mrz_analysis):
            mrz_detected = bool((mrz_analysis or {}).get("detected"))
            if not mrz_detected:
                self._add_failure(
                    results,
                    criterion_id="AF-054",
                    level=FraudCriterionLevel.INFO,
                    score_impact=-20,
                    reason="MRZ attendue mais non detectee.",
                    evidence={"mrz_detected": False, "mrz_error": (mrz_analysis or {}).get("error")},
                )
            else:
                mrz_parseable = bool((mrz_analysis or {}).get("parseable"))
                if not mrz_parseable:
                    self._add_failure(
                        results,
                        criterion_id="AF-055",
                        level=FraudCriterionLevel.MANUAL_REVIEW,
                        score_impact=-110,
                        reason="MRZ detectee mais non parseable.",
                        evidence={
                            "raw_lines": (mrz_analysis or {}).get("raw_lines", []),
                            "mrz_error": (mrz_analysis or {}).get("error"),
                        },
                    )
                else:
                    if self._is_mrz_format_incompatible(kyc_data=kyc_data, mrz_analysis=mrz_analysis):
                        self._add_failure(
                            results,
                            criterion_id="AF-055",
                            level=FraudCriterionLevel.MANUAL_REVIEW,
                            score_impact=-80,
                            reason="Format MRZ incompatible avec le type de document.",
                            evidence={
                                "document_type": self._document_type_code(kyc_data),
                                "expected_format": self._expected_mrz_format(kyc_data=kyc_data),
                                "detected_format": str((mrz_analysis or {}).get("format") or ""),
                            },
                        )
                    else:
                        mrz_fields_for_cross = (mrz_analysis or {}).get("parsed_fields", {}) or {}

                        ocr_full_name = self._build_ocr_full_name(kyc_data)
                        mrz_full_name = self._build_mrz_full_name(mrz_fields_for_cross)
                        if ocr_full_name and mrz_full_name and not self._names_match(ocr_full_name, mrz_full_name):
                            self._add_failure(
                                results,
                                criterion_id="AF-060",
                                level=FraudCriterionLevel.MANUAL_REVIEW,
                                score_impact=-110,
                                reason="Incoherence nom MRZ vs OCR.",
                                evidence={
                                    "ocr_full_name": ocr_full_name,
                                    "mrz_full_name": mrz_full_name,
                                },
                            )

                        checksums = (mrz_analysis or {}).get("checksums", {})

                        if self._is_checksum_invalid(checksums.get("document_number")):
                            self._add_failure(
                                results,
                                criterion_id="AF-056",
                                level=FraudCriterionLevel.HARD_REJECT,
                                score_impact=-240,
                                reason="Checksum MRZ numero document invalide.",
                                evidence={"check": checksums.get("document_number")},
                            )

                        if self._is_checksum_invalid(checksums.get("date_of_birth")):
                            self._add_failure(
                                results,
                                criterion_id="AF-057",
                                level=FraudCriterionLevel.HARD_REJECT,
                                score_impact=-240,
                                reason="Checksum MRZ date de naissance invalide.",
                                evidence={"check": checksums.get("date_of_birth")},
                            )

                        if self._is_checksum_invalid(checksums.get("expiry_date")):
                            self._add_failure(
                                results,
                                criterion_id="AF-058",
                                level=FraudCriterionLevel.HARD_REJECT,
                                score_impact=-240,
                                reason="Checksum MRZ date d'expiration invalide.",
                                evidence={"check": checksums.get("expiry_date")},
                            )

                        if self._is_checksum_invalid(checksums.get("composite")):
                            self._add_failure(
                                results,
                                criterion_id="AF-059",
                                level=FraudCriterionLevel.HARD_REJECT,
                                score_impact=-240,
                                reason="Checksum global MRZ invalide.",
                                evidence={"check": checksums.get("composite")},
                            )

                        mrz_mismatches = self._get_mrz_identity_mismatches(
                            kyc_data=kyc_data,
                            mrz_fields=(mrz_analysis or {}).get("parsed_fields", {}),
                        )

                        if "national_id" in mrz_mismatches:
                            self._add_failure(
                                results,
                                criterion_id="AF-061",
                                level=FraudCriterionLevel.HARD_REJECT,
                                score_impact=-250,
                                reason="Incoherence numero MRZ vs OCR.",
                                evidence={"mismatches": mrz_mismatches},
                            )

                        if any(field in mrz_mismatches for field in {"date_of_birth", "expiry_date"}):
                            self._add_failure(
                                results,
                                criterion_id="AF-062",
                                level=FraudCriterionLevel.HARD_REJECT,
                                score_impact=-250,
                                reason="Incoherence des dates MRZ vs OCR.",
                                evidence={"mismatches": mrz_mismatches},
                            )

        # AF-070: coherence QR <-> MRZ quand les deux sources sont disponibles
        if qr_fields_for_cross and mrz_fields_for_cross:
            qr_mrz_mismatches = self._get_qr_mrz_identity_mismatches(
                qr_fields=qr_fields_for_cross,
                mrz_fields=mrz_fields_for_cross,
            )
            if qr_mrz_mismatches:
                self._add_failure(
                    results,
                    criterion_id="AF-070",
                    level=FraudCriterionLevel.HARD_REJECT,
                    score_impact=-240,
                    reason="Incoherence forte entre QR et MRZ.",
                    evidence={"mismatches": qr_mrz_mismatches},
                )

        # AF-100: accumulation anormale de signaux
        if len(flags) >= 4:
            self._add_failure(
                results,
                criterion_id="AF-100",
                level=FraudCriterionLevel.MANUAL_REVIEW,
                score_impact=-100,
                reason="Accumulation anormale de signaux de fraude.",
                evidence={"flag_count": len(flags), "flags": sorted(flags)},
            )

        return results

    @staticmethod
    def _add_failure(
        results: List[FraudCriterionResult],
        *,
        criterion_id: str,
        level: FraudCriterionLevel,
        score_impact: int,
        reason: str,
        evidence: Dict[str, Any],
    ) -> None:
        results.append(
            FraudCriterionResult(
                criterion_id=criterion_id,
                status=FraudCriterionStatus.FAIL,
                level=level,
                score_impact=score_impact,
                reason=reason,
                evidence=evidence,
            )
        )

    @staticmethod
    def _metadata_value(metadata: Optional[Any], field_name: str) -> Any:
        if metadata is None:
            return None

        if isinstance(metadata, dict):
            return metadata.get(field_name)

        return getattr(metadata, field_name, None)

    @staticmethod
    def _normalize_timestamp(raw_timestamp: Any) -> Optional[datetime]:
        if raw_timestamp is None:
            return None

        if isinstance(raw_timestamp, datetime):
            parsed = raw_timestamp
        elif isinstance(raw_timestamp, str):
            try:
                parsed = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            except ValueError:
                return None
        else:
            return None

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _expects_qr(kyc_data: Optional[Any]) -> bool:
        """Determine si le document devrait contenir un QR exploitable."""

        document_type = FraudCriteriaEngine._document_type_code(kyc_data)
        return document_type in {"CNI_CAMEROON", "NATIONAL_ID"}

    @staticmethod
    def _expects_mrz(*, kyc_data: Optional[Any], mrz_analysis: Optional[Dict[str, Any]]) -> bool:
        """Determine si la verification MRZ doit etre appliquee."""

        if mrz_analysis and mrz_analysis.get("expected") is True:
            return True

        return FraudCriteriaEngine._document_type_code(kyc_data) in {"PASSPORT"}

    @staticmethod
    def _document_type_code(kyc_data: Optional[Any]) -> str:
        raw_value = str(FraudCriteriaEngine._source_value(kyc_data, "document_type") or "").strip()
        if "." in raw_value:
            raw_value = raw_value.split(".")[-1]
        return raw_value.upper()

    @staticmethod
    def _expected_mrz_format(*, kyc_data: Optional[Any]) -> Optional[str]:
        document_type = FraudCriteriaEngine._document_type_code(kyc_data)
        if document_type == "PASSPORT":
            return "TD3"
        if document_type in {"CNI_CAMEROON", "NATIONAL_ID"}:
            return "TD1"
        return None

    @staticmethod
    def _is_mrz_format_incompatible(*, kyc_data: Optional[Any], mrz_analysis: Optional[Dict[str, Any]]) -> bool:
        expected_format = FraudCriteriaEngine._expected_mrz_format(kyc_data=kyc_data)
        if not expected_format:
            return False

        detected_format = str((mrz_analysis or {}).get("format") or "").upper()
        if not detected_format:
            return False

        return detected_format != expected_format

    @staticmethod
    def _is_checksum_invalid(check: Any) -> bool:
        if not isinstance(check, dict):
            return False
        return bool(check.get("available") is True and check.get("valid") is False)

    def _get_qr_identity_mismatches(self, *, kyc_data: Optional[Any], qr_fields: Dict[str, Any]) -> List[str]:
        """Retourne les mismatches forts QR vs OCR qui justifient AF-069."""

        mismatches: List[str] = []
        if kyc_data is None or not qr_fields:
            return mismatches

        ocr_national_id = self._normalize_text(str(self._source_value(kyc_data, "national_id")))
        qr_national_id = self._normalize_text(str(qr_fields.get("national_id", "")))
        if ocr_national_id and qr_national_id and ocr_national_id != qr_national_id:
            mismatches.append("national_id")

        ocr_dob = self._normalize_date(self._source_value(kyc_data, "date_of_birth"))
        qr_dob = self._normalize_date(qr_fields.get("date_of_birth"))
        if ocr_dob and qr_dob and ocr_dob != qr_dob:
            mismatches.append("date_of_birth")

        ocr_full_name = self._build_ocr_full_name(kyc_data)
        qr_full_name = self._build_qr_full_name(qr_fields)
        if ocr_full_name and qr_full_name and not self._names_match(ocr_full_name, qr_full_name):
            mismatches.append("full_name")

        return mismatches

    @staticmethod
    def _normalize_text(value: str) -> str:
        return re.sub(r"[^A-Z0-9]", "", (value or "").upper())

    @classmethod
    def _names_match(cls, left: str, right: str) -> bool:
        """Compare deux noms de maniere robuste (ordre des tokens tolerant)."""

        left_tokens = set(cls._tokenize_name(left))
        right_tokens = set(cls._tokenize_name(right))
        if left_tokens and right_tokens:
            return left_tokens == right_tokens

        return cls._normalize_text(left) == cls._normalize_text(right)

    @staticmethod
    def _tokenize_name(value: str) -> List[str]:
        cleaned = re.sub(r"[^A-Z\s]", " ", (value or "").upper())
        return [token for token in cleaned.split() if token]

    def _build_ocr_full_name(self, kyc_data: Any) -> str:
        full_name = str(self._source_value(kyc_data, "full_name") or "").strip()
        if full_name:
            return full_name

        first_name = str(self._source_value(kyc_data, "first_name") or "").strip()
        last_name = str(self._source_value(kyc_data, "last_name") or "").strip()
        return f"{first_name} {last_name}".strip()

    def _build_qr_full_name(self, qr_fields: Dict[str, Any]) -> str:
        full_name = str(qr_fields.get("full_name", "")).strip()
        if full_name:
            return full_name

        first_name = str(qr_fields.get("first_name", "")).strip()
        last_name = str(qr_fields.get("last_name", "")).strip()
        return f"{first_name} {last_name}".strip()

    def _build_mrz_full_name(self, mrz_fields: Dict[str, Any]) -> str:
        full_name = str(mrz_fields.get("full_name", "")).strip()
        if full_name:
            return full_name

        first_name = str(mrz_fields.get("first_name", "")).strip()
        last_name = str(mrz_fields.get("last_name", "")).strip()
        return f"{first_name} {last_name}".strip()

    def _get_mrz_identity_mismatches(self, *, kyc_data: Optional[Any], mrz_fields: Dict[str, Any]) -> List[str]:
        """Retourne les mismatches critiques MRZ vs OCR pour AF-061/AF-062."""

        mismatches: List[str] = []
        if kyc_data is None or not mrz_fields:
            return mismatches

        ocr_national_id = self._normalize_text(str(self._source_value(kyc_data, "national_id")))
        mrz_document_number = self._normalize_text(
            str(mrz_fields.get("document_number") or mrz_fields.get("national_id") or "")
        )

        if ocr_national_id and mrz_document_number and ocr_national_id != mrz_document_number:
            mismatches.append("national_id")

        ocr_dob = self._normalize_date(self._source_value(kyc_data, "date_of_birth"))
        mrz_dob = self._normalize_date(mrz_fields.get("date_of_birth"))
        if ocr_dob and mrz_dob and ocr_dob != mrz_dob:
            mismatches.append("date_of_birth")

        ocr_expiry = self._normalize_date(self._source_value(kyc_data, "expiry_date"))
        mrz_expiry = self._normalize_date(mrz_fields.get("expiry_date"))
        if ocr_expiry and mrz_expiry and ocr_expiry != mrz_expiry:
            mismatches.append("expiry_date")

        return mismatches

    def _get_qr_mrz_identity_mismatches(self, *, qr_fields: Dict[str, Any], mrz_fields: Dict[str, Any]) -> List[str]:
        """Retourne les mismatches critiques QR vs MRZ pour AF-070."""

        mismatches: List[str] = []
        if not qr_fields or not mrz_fields:
            return mismatches

        qr_national_id = self._normalize_text(str(qr_fields.get("national_id") or ""))
        mrz_document_number = self._normalize_text(
            str(mrz_fields.get("document_number") or mrz_fields.get("national_id") or "")
        )
        if qr_national_id and mrz_document_number and qr_national_id != mrz_document_number:
            mismatches.append("national_id")

        qr_dob = self._normalize_date(qr_fields.get("date_of_birth"))
        mrz_dob = self._normalize_date(mrz_fields.get("date_of_birth"))
        if qr_dob and mrz_dob and qr_dob != mrz_dob:
            mismatches.append("date_of_birth")

        qr_full_name = self._build_qr_full_name(qr_fields)
        mrz_full_name = self._build_mrz_full_name(mrz_fields)
        if qr_full_name and mrz_full_name and not self._names_match(qr_full_name, mrz_full_name):
            mismatches.append("full_name")

        return mismatches

    @staticmethod
    def _normalize_date(value: Any) -> Optional[str]:
        if value is None:
            return None

        if isinstance(value, date):
            return value.isoformat()

        candidate = str(value).strip()
        if not candidate:
            return None

        for parser in (
            lambda v: datetime.strptime(v, "%Y-%m-%d").date(),
            lambda v: datetime.strptime(v, "%d/%m/%Y").date(),
            lambda v: datetime.strptime(v, "%Y/%m/%d").date(),
            lambda v: datetime.strptime(v, "%d-%m-%Y").date(),
            lambda v: datetime.strptime(v, "%d%m%Y").date(),
            lambda v: datetime.strptime(v, "%Y%m%d").date(),
        ):
            try:
                return parser(candidate).isoformat()
            except ValueError:
                continue

        return None

    @staticmethod
    def _source_value(source: Any, key: str) -> Any:
        if source is None:
            return None
        if isinstance(source, dict):
            return source.get(key)
        return getattr(source, key, None)
