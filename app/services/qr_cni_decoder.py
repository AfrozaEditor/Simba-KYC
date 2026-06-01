"""Decodeur QR CNI pour criteres anti-fraude numeriques."""

from __future__ import annotations

import base64
import binascii
import json
import re
import zlib
from datetime import date, datetime
from io import BytesIO
from typing import Any, Dict, Optional, Tuple

import numpy as np


class QRCNIDecoder:
    """Analyse un QR de piece d'identite depuis une image base64.

    Le service retourne un objet d'analyse tolerant aux erreurs pour alimenter
    le moteur de criteres (AF-063..AF-069).
    """

    REQUIRED_FIELDS = ("full_name", "national_id", "date_of_birth")
    TAG_MAP = {
        # Identite
        0xA0: ("texte", "nom"),
        0xA1: ("texte", "prenom"),
        0xA2: ("texte", "sexe"),
        0xA3: ("texte", "date_naissance"),
        0xA4: ("texte", "lieu_naissance"),
        0xA5: ("texte", "date_expiration"),
        0xA6: ("texte", "numero_document"),
        0xA9: ("texte", "niveau_education"),
        0xB0: ("texte", "profession_ou_statut"),
        0xB1: ("texte", "nom_mere"),
        0xB2: ("texte", "nom_pere"),
        0xB4: ("texte", "pays_emission"),
        # Securite / biometrie
        0xC1: ("binaire", "empreinte_digitale_1_FMR"),
        0xC2: ("binaire", "empreinte_digitale_2_FMR"),
        0x7F: ("binaire", "signature_cryptographique"),
    }
    FILIATION_TAGS = {0xB1, 0xB2}

    def analyze(self, document_front_base64: str, document_back_base64: str = "") -> Dict[str, Any]:
        """Decode et parse le QR depuis le verso (prioritaire) puis le recto."""

        result: Dict[str, Any] = {
            "detected": False,
            "source": None,
            "raw_payload": None,
            "prefix_valid": None,
            "base32_valid": None,
            "decompression_valid": None,
            "parsed_fields": {},
            "required_fields_present": None,
            "signature_present": None,
            "identite_titulaire": {},
            "filiation": {},
            "infrastructure_anti_fraude": {},
            "metadata": {},
            "error": None,
        }

        payload, source, error = self._decode_qr_payload(document_back_base64, document_front_base64)
        if error:
            result["error"] = error

        if not payload:
            return result

        payload_result = self.analyze_payload(payload)
        payload_result["source"] = source
        return payload_result

    def analyze_payload(self, qr_payload: str) -> Dict[str, Any]:
        """Analyse directe d'un payload QR deja extrait (utile pour tests/CLI)."""

        result: Dict[str, Any] = {
            "detected": bool(qr_payload),
            "source": None,
            "raw_payload": qr_payload,
            "prefix_valid": None,
            "base32_valid": None,
            "decompression_valid": None,
            "parsed_fields": {},
            "required_fields_present": None,
            "signature_present": None,
            "identite_titulaire": {},
            "filiation": {},
            "infrastructure_anti_fraude": {},
            "metadata": {},
            "error": None,
        }

        decoded = self._decode_payload_robust(qr_payload)
        result["prefix_valid"] = decoded["prefix_valid"]
        result["base32_valid"] = decoded["base32_valid"]
        result["decompression_valid"] = decoded["decompression_valid"]
        result["metadata"] = decoded["metadata"]
        result["identite_titulaire"] = decoded["identite_titulaire"]
        result["filiation"] = decoded["filiation"]
        result["infrastructure_anti_fraude"] = decoded["infrastructure_anti_fraude"]
        result["error"] = decoded["error"]

        if decoded["error"]:
            return result

        parsed_fields = self._canonicalize_fields(
            identite=decoded["identite_titulaire"],
            filiation=decoded["filiation"],
            security=decoded["infrastructure_anti_fraude"],
        )

        # Fallback generic sur texte libre si TLV incomplet
        if not parsed_fields and decoded["decompressed_bytes"]:
            parsed_fields = self._parse_fields(decoded["decompressed_bytes"])

        # Fallback heuristique: certaines CNI utilisent un schema de tags different
        # mais contiennent tout de meme des segments texte exploitables.
        if decoded["decompressed_bytes"] and not self._has_required_fields(parsed_fields):
            heuristic_fields = self._extract_identity_hints_from_bytes(decoded["decompressed_bytes"])
            parsed_fields = self._merge_missing_fields(parsed_fields, heuristic_fields)

        result["parsed_fields"] = parsed_fields
        result["required_fields_present"] = self._has_required_fields(parsed_fields)
        result["signature_present"] = bool(
            parsed_fields.get("signature")
            or decoded["infrastructure_anti_fraude"].get("signature_cryptographique")
        )

        return result

    def decode_cni_cameroon_full_robust(self, qr_data: str) -> Dict[str, Any]:
        """Expose l'algorithme robuste CNI pour usage debug/validation."""

        decoded = self._decode_payload_robust(qr_data)
        if decoded["error"]:
            return {"error": decoded["error"]}

        return {
            "metadata": decoded["metadata"],
            "identite_titulaire": decoded["identite_titulaire"],
            "filiation": decoded["filiation"],
            "infrastructure_anti_fraude": decoded["infrastructure_anti_fraude"],
        }

    def _decode_payload_robust(self, qr_data: str) -> Dict[str, Any]:
        cleaned_payload = (qr_data or "").replace("\n", "").replace("\r", "").strip()
        prefix_valid, encoded_segment = self._extract_prefixed_segment(cleaned_payload)

        result: Dict[str, Any] = {
            "prefix_valid": prefix_valid,
            "base32_valid": None,
            "decompression_valid": None,
            "decompressed_bytes": b"",
            "identite_titulaire": {},
            "filiation": {},
            "infrastructure_anti_fraude": {},
            "metadata": {
                "taille_totale_octets": 0,
            },
            "error": None,
        }

        if not encoded_segment:
            result["base32_valid"] = False
            result["decompression_valid"] = False
            result["error"] = "Payload QR vide apres nettoyage"
            return result

        payload = encoded_segment + "=" * ((8 - len(encoded_segment) % 8) % 8)

        try:
            compressed = base64.b32decode(payload, casefold=True)
            result["base32_valid"] = True
        except Exception as exc:
            result["base32_valid"] = False
            result["decompression_valid"] = False
            result["error"] = f"Echec du decodage base32: {exc}"
            return result

        try:
            decompressed = zlib.decompress(compressed)
            result["decompression_valid"] = True
        except Exception as exc:
            result["decompression_valid"] = False
            result["error"] = f"Echec de decompression zlib: {exc}"
            return result

        result["decompressed_bytes"] = decompressed
        result["metadata"]["taille_totale_octets"] = len(decompressed)

        identite, filiation, security = self._parse_tlv_sliding(decompressed)
        result["identite_titulaire"] = identite
        result["filiation"] = filiation
        result["infrastructure_anti_fraude"] = security

        return result

    def _parse_tlv_sliding(self, raw_bytes: bytes) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
        """Parseur BER-TLV glissant robuste (anti faux positifs)."""

        identite: Dict[str, str] = {}
        filiation: Dict[str, str] = {}
        security: Dict[str, str] = {}

        i = 0
        while i < len(raw_bytes):
            tag = raw_bytes[i]

            if tag not in self.TAG_MAP:
                i += 1
                continue

            if i + 1 >= len(raw_bytes):
                break

            length = raw_bytes[i + 1]
            header_size = 2

            if length == 0x81:
                if i + 2 >= len(raw_bytes):
                    break
                length = raw_bytes[i + 2]
                header_size = 3
            elif length == 0x82:
                if i + 3 >= len(raw_bytes):
                    break
                length = (raw_bytes[i + 2] << 8) | raw_bytes[i + 3]
                header_size = 4

            if i + header_size + length > len(raw_bytes):
                i += 1
                continue

            value_bytes = raw_bytes[i + header_size : i + header_size + length]
            data_type, field_name = self.TAG_MAP[tag]

            if data_type == "texte":
                try:
                    value_str = value_bytes.decode("ascii").strip()
                except UnicodeDecodeError:
                    i += 1
                    continue

                if tag in self.FILIATION_TAGS:
                    filiation[field_name] = value_str
                else:
                    identite[field_name] = value_str
            else:
                security[field_name] = value_bytes.hex()

            i += header_size + length

        return identite, filiation, security

    def _canonicalize_fields(
        self,
        *,
        identite: Dict[str, str],
        filiation: Dict[str, str],
        security: Dict[str, str],
    ) -> Dict[str, str]:
        """Mappe les champs CNI tagues vers un schema canonique compare OCR."""

        parsed: Dict[str, str] = {}

        nom = (identite.get("nom") or "").strip()
        prenom = (identite.get("prenom") or "").strip()

        if prenom:
            parsed["first_name"] = prenom
        if nom:
            parsed["last_name"] = nom
        if prenom or nom:
            parsed["full_name"] = f"{prenom} {nom}".strip()

        if identite.get("numero_document"):
            parsed["national_id"] = identite["numero_document"].strip()

        normalized_dob = self._normalize_date(identite.get("date_naissance", ""))
        if normalized_dob:
            parsed["date_of_birth"] = normalized_dob

        normalized_expiry = self._normalize_date(identite.get("date_expiration", ""))
        if normalized_expiry:
            parsed["expiry_date"] = normalized_expiry

        if identite.get("sexe"):
            parsed["gender"] = identite["sexe"].strip()
        if identite.get("pays_emission"):
            parsed["country"] = identite["pays_emission"].strip()

        if filiation.get("nom_mere"):
            parsed["mother_name"] = filiation["nom_mere"].strip()
        if filiation.get("nom_pere"):
            parsed["father_name"] = filiation["nom_pere"].strip()

        if security.get("signature_cryptographique"):
            parsed["signature"] = security["signature_cryptographique"]

        return parsed

    def _decode_qr_payload(self, back_b64: str, front_b64: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        payload, source, first_error = self._decode_qr_payload_with_opencv(back_b64, front_b64)
        if payload:
            return payload, source, first_error

        zxing_payload, zxing_source, zxing_error = self._decode_qr_payload_with_zxing(back_b64, front_b64)
        if zxing_payload:
            return zxing_payload, zxing_source, first_error

        if first_error and zxing_error:
            return None, None, f"{first_error}; {zxing_error}"

        return None, None, first_error or zxing_error

    def _decode_qr_payload_with_opencv(
        self, back_b64: str, front_b64: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        try:
            import cv2
        except ImportError:
            return None, None, "cv2_not_installed_for_qr_detection"

        detector = cv2.QRCodeDetector()
        first_error: Optional[str] = None

        for source, image_b64 in (("back", back_b64), ("front", front_b64)):
            if not image_b64:
                continue

            try:
                image = self._decode_image(image_b64)
            except ValueError as exc:
                if first_error is None:
                    first_error = f"invalid_{source}_image: {exc}"
                continue

            payload, _, _ = detector.detectAndDecode(image)
            if payload:
                return payload.strip(), source, first_error

            # Fallback multi-QR detection
            try:
                decoded_ok, decoded_values, _, _ = detector.detectAndDecodeMulti(image)
                if decoded_ok and decoded_values:
                    for value in decoded_values:
                        if value:
                            return value.strip(), source, first_error
            except Exception:
                pass

        return None, None, first_error

    def _decode_qr_payload_with_zxing(
        self, back_b64: str, front_b64: str
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Fallback ZXing pour les QR denses que OpenCV decode mal."""

        try:
            import zxingcpp
            from PIL import Image
        except ImportError:
            return None, None, "zxingcpp_or_pillow_not_installed"

        first_error: Optional[str] = None

        for source, image_b64 in (("back", back_b64), ("front", front_b64)):
            if not image_b64:
                continue

            try:
                image = self._decode_pil_image(image_b64, Image)
            except ValueError as exc:
                if first_error is None:
                    first_error = f"invalid_{source}_image: {exc}"
                continue

            try:
                result = zxingcpp.read_barcode(image)
            except Exception as exc:
                if first_error is None:
                    first_error = f"zxing_decode_error_{source}: {exc}"
                continue

            if result is not None and getattr(result, "text", None):
                return str(result.text).strip(), source, first_error

        return None, None, first_error

    @staticmethod
    def _decode_image(image_b64: str) -> np.ndarray:
        try:
            import cv2
        except ImportError as exc:
            raise ValueError("cv2_not_installed") from exc

        payload = image_b64.split(",", 1)[1] if "," in image_b64 else image_b64

        try:
            raw = base64.b64decode(payload, validate=True)
        except binascii.Error as exc:
            raise ValueError("base64_invalid") from exc

        array = np.frombuffer(raw, dtype=np.uint8)
        image = cv2.imdecode(array, cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError("image_decode_failed")

        return image

    @staticmethod
    def _decode_pil_image(image_b64: str, pil_image_module: Any) -> Any:
        payload = image_b64.split(",", 1)[1] if "," in image_b64 else image_b64

        try:
            raw = base64.b64decode(payload, validate=True)
        except binascii.Error as exc:
            raise ValueError("base64_invalid") from exc

        try:
            image = pil_image_module.open(BytesIO(raw))
            image.load()
            return image
        except Exception as exc:
            raise ValueError("image_decode_failed") from exc

    @staticmethod
    def _extract_prefixed_segment(payload: str) -> Tuple[bool, str]:
        normalized = payload.strip()
        if normalized.startswith("IDB1D:"):
            return True, normalized[6:]

        if normalized.startswith("IDB1D"):
            return True, normalized[5:]

        return False, normalized

    @staticmethod
    def _decode_base32(segment: str) -> Optional[bytes]:
        compact = re.sub(r"[^A-Z2-7=]", "", segment.upper())
        if not compact:
            return None

        padding = (-len(compact)) % 8
        compact += "=" * padding

        try:
            return base64.b32decode(compact, casefold=True)
        except binascii.Error:
            return None

    @staticmethod
    def _inflate_payload(data: bytes) -> Tuple[bytes, bool]:
        try:
            return zlib.decompress(data), True
        except zlib.error:
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS), True
            except zlib.error:
                return data, False

    def _parse_fields(self, data: bytes) -> Dict[str, str]:
        text = data.decode("utf-8", errors="ignore").strip()
        if not text:
            return {}

        json_fields = self._parse_json(text)
        if json_fields:
            return json_fields

        kv_fields = self._parse_kv(text)
        if kv_fields:
            return kv_fields

        return self._parse_pattern_fallback(text)

    def _parse_json(self, text: str) -> Dict[str, str]:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return {}

        if not isinstance(obj, dict):
            return {}

        fields: Dict[str, str] = {}
        for canonical_name, aliases in self._aliases().items():
            for alias in aliases:
                if alias in obj and obj[alias] not in (None, ""):
                    value = str(obj[alias]).strip()
                    if canonical_name == "date_of_birth":
                        normalized = self._normalize_date(value)
                        if normalized:
                            value = normalized
                    fields[canonical_name] = value
                    break

        return fields

    def _parse_kv(self, text: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        tokens = re.split(r"[\n;|]", text)

        for token in tokens:
            part = token.strip()
            if not part:
                continue

            if "=" in part:
                key, value = part.split("=", 1)
            elif ":" in part:
                key, value = part.split(":", 1)
            else:
                continue

            canonical_key = self._map_key(key)
            if not canonical_key:
                continue

            cleaned_value = value.strip()
            if not cleaned_value:
                continue

            if canonical_key == "date_of_birth":
                normalized = self._normalize_date(cleaned_value)
                if normalized:
                    cleaned_value = normalized

            fields[canonical_key] = cleaned_value

        return fields

    @staticmethod
    def _parse_pattern_fallback(text: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}

        national_id_match = re.search(r"\b[A-Z]{1,4}[0-9]{5,}\b", text.upper())
        if national_id_match:
            fields["national_id"] = national_id_match.group(0)

        dob_match = re.search(r"\b\d{4}-\d{2}-\d{2}\b", text)
        if dob_match:
            fields["date_of_birth"] = dob_match.group(0)
        else:
            dob_match = re.search(r"\b\d{2}/\d{2}/\d{4}\b", text)
            if dob_match:
                fields["date_of_birth"] = dob_match.group(0)

        # Fallback faible: nom apres mot cle NAME/NOM
        name_match = re.search(r"(?:NAME|NOM)\s*[:=]\s*([A-Z\-\s]{5,})", text, flags=re.IGNORECASE)
        if name_match:
            fields["full_name"] = re.sub(r"\s+", " ", name_match.group(1)).strip()

        return fields

    def _extract_identity_hints_from_bytes(self, data: bytes) -> Dict[str, str]:
        """Recupere des champs identite depuis segments ASCII imprimes."""

        fields: Dict[str, str] = {}
        printable = "".join(chr(b) if 32 <= b <= 126 else " " for b in data)

        # National ID
        id_matches = re.findall(r"\b[A-Z]{1,4}[0-9]{5,}\b", printable.upper())
        if id_matches:
            fields["national_id"] = id_matches[0]

        # Dates candidates
        raw_date_candidates = re.findall(
            r"\b(?:\d{2}[./-]\d{2}[./-]\d{4}|\d{4}[./-]\d{2}[./-]\d{2}|\d{8})\b",
            printable,
        )
        normalized_dates = []
        for candidate in raw_date_candidates:
            normalized = self._normalize_date(candidate)
            if normalized:
                normalized_dates.append(normalized)

        if normalized_dates:
            sorted_dates = sorted(set(normalized_dates))
            fields["date_of_birth"] = sorted_dates[0]
            if len(sorted_dates) > 1:
                fields["expiry_date"] = sorted_dates[-1]

        # Nom complet probable
        name_candidates = re.findall(r"\b[A-Z]{3,}(?:\s+[A-Z]{3,}){1,5}\b", printable.upper())
        blacklist = {
            "CMR",
            "FMR",
            "REPUBLIC",
            "CAMEROUN",
            "NATIONAL",
            "IDENTITY",
            "CARD",
            "ETUDIANT",
            "ETUDIANTE",
            "SIGEU",
        }

        filtered = []
        for candidate in name_candidates:
            words = [w for w in candidate.split() if w]
            if len(words) < 2:
                continue
            if any(word in blacklist for word in words):
                continue
            filtered.append(" ".join(words))

        if filtered:
            # Preferer un nom de taille moyenne (2-4 mots)
            filtered.sort(key=lambda n: (abs(len(n.split()) - 3), len(n)))
            fields["full_name"] = filtered[0].title().upper()

        return fields

    def _has_required_fields(self, parsed_fields: Dict[str, str]) -> bool:
        return all(bool(parsed_fields.get(field_name)) for field_name in self.REQUIRED_FIELDS)

    @staticmethod
    def _merge_missing_fields(base_fields: Dict[str, str], fallback_fields: Dict[str, str]) -> Dict[str, str]:
        merged = dict(base_fields)
        for key, value in fallback_fields.items():
            if key not in merged or not merged[key]:
                merged[key] = value
        return merged

    @classmethod
    def _aliases(cls) -> Dict[str, Tuple[str, ...]]:
        return {
            "full_name": ("full_name", "name", "nom", "holder_name", "nom_complet"),
            "first_name": ("first_name", "given_name", "prenom", "firstName"),
            "last_name": ("last_name", "surname", "nom_famille", "lastName"),
            "national_id": ("national_id", "id_number", "document_number", "numero", "nin"),
            "date_of_birth": ("date_of_birth", "dob", "birth_date", "date_naissance"),
            "signature": ("signature", "sig", "digital_signature"),
        }

    def _map_key(self, raw_key: str) -> Optional[str]:
        normalized = re.sub(r"[^a-z0-9]", "", raw_key.lower())
        alias_map: Dict[str, str] = {}

        for canonical_name, aliases in self._aliases().items():
            for alias in aliases:
                alias_map[re.sub(r"[^a-z0-9]", "", alias.lower())] = canonical_name

        return alias_map.get(normalized)

    @staticmethod
    def _normalize_date(value: str) -> Optional[str]:
        candidate = value.strip()
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

        # Si deja de type date dans un flux amont
        if isinstance(value, date):
            return value.isoformat()

        return None
