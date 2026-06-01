"""Implémentation Groq (Llama 4 Vision) — API gratuite pour documents"""

import base64
import asyncio
import logging
import json
import io
from typing import Dict, Any, Optional
import aiohttp

from app.services.cni_ocr_confidence import calculate_cni_confidence, calculate_cni_field_scores
import os


from app.infrastructure.external.llm_multimodal_interface import LLMMultimodalInterface

logger = logging.getLogger(__name__)


class GroqModel(LLMMultimodalInterface):
    """Provider Groq avec Llama 4 Vision (gratuit)"""
    MAX_IMAGE_BYTES = 4 * 1024 * 1024
    
    def __init__(self, api_key: Optional[str] = None, 
                 api_base: str = "https://api.groq.com/openai/v1",
                 model: str = "meta-llama/llama-4-scout-17b-16e-instruct",
                 timeout: int = 30):
        self.api_base = api_base
        self.model = model
        self.timeout = max(5, int(timeout or 30))
        
        # Récupérer la clé API
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        
        if not self.api_key:
            logger.warning("  GROQ_API_KEY non configuré - provider indisponible")
        else:
            logger.info(f"  Groq initialisé avec modèle {model}")

    def _prepare_image_base64(self, image_base64: str) -> str:
        """Réduit automatiquement une image trop lourde pour Groq (4MB max)."""
        candidate = image_base64.split(",", 1)[1] if "," in image_base64 else image_base64

        try:
            decoded = base64.b64decode(candidate)
        except Exception:
            return candidate

        if len(decoded) <= self.MAX_IMAGE_BYTES:
            return candidate

        try:
            from PIL import Image

            image = Image.open(io.BytesIO(decoded))
            if image.mode != "RGB":
                image = image.convert("RGB")

            resampling = getattr(Image, "Resampling", Image)
            lanczos = getattr(resampling, "LANCZOS", Image.LANCZOS)

            working = image.copy()
            working.thumbnail((1600, 1600), lanczos)

            qualities = [85, 75, 65, 55, 45, 35]
            scales = [1.0, 0.85, 0.70, 0.55, 0.40]

            for scale in scales:
                if scale < 1.0:
                    resized = working.resize(
                        (
                            max(1, int(working.width * scale)),
                            max(1, int(working.height * scale)),
                        ),
                        lanczos,
                    )
                else:
                    resized = working

                for quality in qualities:
                    buffer = io.BytesIO()
                    resized.save(
                        buffer,
                        format="JPEG",
                        quality=quality,
                        optimize=True,
                    )
                    compressed = buffer.getvalue()
                    if len(compressed) <= self.MAX_IMAGE_BYTES:
                        optimized = base64.b64encode(compressed).decode("utf-8")
                        logger.info(
                            "Image optimisée pour Groq: %.2fMB -> %.2fMB",
                            len(decoded) / 1024 / 1024,
                            len(compressed) / 1024 / 1024,
                        )
                        return optimized

        except Exception as exc:
            logger.warning(f"Impossible d'optimiser l'image pour Groq: {exc}")

        return candidate

    async def extract_from_image(
        self,
        image_base64: str,
        document_type: str = "CNI_CAMEROON",
        document_side: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Extraire champs via Groq Llama 4 Vision"""
        try:
            if not self.api_key:
                return self._error_response("GROQ_API_KEY not configured")
            
            logger.info("  Groq extraction debute (%s, side=%s)", document_type, document_side or "unknown")

            image_base64 = self._prepare_image_base64(image_base64)
            
            # Vérifier la taille de l'image (max 4MB pour base64)
            image_size_mb = len(image_base64) * 3 / 4 / 1024 / 1024
            if image_size_mb > (self.MAX_IMAGE_BYTES / 1024 / 1024):
                logger.warning(f"Image trop grande: {image_size_mb:.2f}MB")
                return self._error_response(f"Image too large: {image_size_mb:.2f}MB (max 4MB)")
            
            # ========== PROMPT STRUCTURÉ ==========
            if document_type == "CNI_CAMEROON":
                system_prompt, user_prompt = self._build_cameroon_cni_prompts(document_side)
            else:
                system_prompt = f"You are an expert document extraction system for {document_type} documents."
                user_prompt = f"Extract all visible information from this {document_type} document. Return ONLY valid JSON."
            
            # ========== APPEL GROQ (format OpenAI) ==========
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Format pour Groq (OpenAI compatible)
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{image_base64}"
                                }
                            },
                            {
                                "type": "text",
                                "text": user_prompt
                            }
                        ]
                    }
                ],
                "max_tokens": 1024,
                "temperature": 0.1,
                "response_format": {"type": "json_object"}  # Llama 4 supporte JSON mode
            }
            
            logger.debug("Envoi requête à Groq API")
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status != 200:
                        error_text = await resp.text()
                        logger.error(f"  Groq erreur HTTP {resp.status}: {error_text[:200]}")
                        return self._error_response(f"HTTP {resp.status}: {error_text[:200]}")
                    
                    result = await resp.json()
            
            # ========== EXTRACTION RÉPONSE ==========
            if "choices" not in result or not result["choices"]:
                logger.error("  Groq réponse invalide")
                return self._error_response("Invalid response format")
            
            raw_response = result["choices"][0]["message"]["content"]
            logger.debug(f"Réponse brute: {raw_response[:200]}...")
            
            # ========== PARSING JSON ==========
            try:
                fields = json.loads(raw_response)
            except json.JSONDecodeError:
                # Essayer d'extraire le JSON du texte
                import re
                json_match = re.search(r'\{.*\}', raw_response, re.DOTALL)
                if json_match:
                    fields = json.loads(json_match.group())
                else:
                    raise
            
            if document_type == "CNI_CAMEROON" and document_side == "back":
                mrz_text = str(fields.get("mrz_text") or "").strip()
                if not mrz_text:
                    mrz_text = await self._extract_mrz_only(image_base64)
                    if mrz_text:
                        fields["mrz_text"] = mrz_text
                        logger.info("  MRZ extrait via passe MRZ-only")

            confidence = self._calculate_confidence(fields)
            
            logger.info(f"  Groq extraction réussie - Confiance: {confidence:.2f}")
            
            return {
                "success": True,
                "provider": "groq",
                "confidence": confidence,
                "detected_fields": {k: v for k, v in fields.items() 
                                   if k not in ["confidence_notes", "warnings", "extraction_quality"]},
                "confidence_scores": self._calculate_field_scores(fields),
                "warnings": fields.get("warnings", []),
                "raw_response": raw_response[:500]
            }
        
        except json.JSONDecodeError as e:
            logger.error(f"  JSON parsing error: {e}")
            return self._error_response(f"Invalid JSON response: {e}")
        except asyncio.TimeoutError:
            logger.error("  Groq timeout")
            return self._error_response("Groq request timeout")
        except Exception as e:
            logger.error(f"  Groq erreur: {e}", exc_info=True)
            return self._error_response(str(e))

    def _build_cameroon_cni_prompts(self, document_side: Optional[str]) -> tuple[str, str]:
        side = self._normalize_document_side(document_side)

        shared_rules = """Vous etes un expert en extraction de cartes nationales d'identite camerounaises.

REGLES ABSOLUES:
- Si vous ne voyez pas clairement une information sur l'image, retournez une chaine vide ""
- N'inventez rien et n'approximez rien
- Retournez uniquement du JSON valide
- Les dates doivent etre au format YYYY-MM-DD
- Le vrai numero CNI apparait sous l'etiquette "NUMERO CNI" ou "NIC NUMBER"
- Ne jamais utiliser un numero vertical, un numero proche de la photo, un motif MRZ, ni un numero de securite comme national_id"""

        if side == "front":
            system_prompt = f"""{shared_rules}

CONTEXTE RECTO:
- Cette image montre le recto de la CNI
- Les champs titulaires visibles sont surtout NOM / SURNAME, PRENOMS / GIVEN NAMES, DATE DE NAISSANCE, SEXE, DATE D'EXPIRATION
- Le numero imprime pres du portrait n'est pas le national_id"""

            user_prompt = """Analysez cette image RECTO de CNI camerounaise.

Retournez ce JSON exact:
{
    "national_id": "",
    "full_name": "",
    "last_name": "",
    "first_name": "",
    "date_of_birth": "",
    "gender": "",
    "expiry_date": "",
    "mrz_text": "",
    "country": "CM",
    "document_type": "CNI_CAMEROON",
    "document_side": "front",
    "extraction_quality": "",
    "warnings": []
}

Instructions:
1. last_name -> valeur lue sous NOM / SURNAME
2. first_name -> valeur lue sous PRENOMS / GIVEN NAMES
3. full_name -> nom du titulaire uniquement, recompose comme "<first_name> <last_name>"
4. national_id -> laissez vide sauf si l'etiquette NUMERO CNI / NIC NUMBER est clairement visible sur cette image
5. mrz_text -> si une zone MRZ (lignes avec <<) est visible, recopiez les lignes telles quelles et separez-les par "\n"
6. N'utilisez jamais le numero imprime pres de la photo comme national_id"""
            return system_prompt, user_prompt

        if side == "back":
            system_prompt = f"""{shared_rules}

CONTEXTE VERSO:
- Cette image montre le verso de la CNI
- Le vrai numero CNI apparait sous NUMERO CNI / NIC NUMBER et commence souvent par A, AB, AA, etc.
- Le verso contient aussi les noms des parents, le lieu de naissance, la profession, la date de delivrance et la taille
- Ne remplissez pas full_name, first_name ou last_name a partir des noms des parents"""

            user_prompt = """Analysez cette image VERSO de CNI camerounaise.

Retournez ce JSON exact:
{
    "national_id": "",
    "father_name": "",
    "mother_name": "",
    "place_of_birth": "",
    "profession": "",
    "issue_date": "",
    "height": "",
    "mrz_text": "",
    "country": "CM",
    "document_type": "CNI_CAMEROON",
    "document_side": "back",
    "extraction_quality": "",
    "warnings": []
}

Instructions:
1. national_id -> uniquement la valeur lue sous NUMERO CNI / NIC NUMBER
2. father_name -> uniquement sous NOM DU PERE / FATHER'S NAME
3. mother_name -> uniquement sous NOM DE LA MERE / MOTHER'S NAME
4. place_of_birth -> uniquement sous LIEU DE NAISSANCE / PLACE OF BIRTH
5. profession -> uniquement sous PROFESSION / OCCUPATION
6. issue_date -> uniquement sous DATE DE DELIVRANCE / DATE OF ISSUE
7. height -> uniquement sous TAILLE / HEIGHT
8. mrz_text -> si une zone MRZ (lignes avec <<) est visible, recopiez les lignes telles quelles et separez-les par "\n"
9. N'utilisez jamais la colonne verticale a droite ni le texte du QR comme national_id"""
            return system_prompt, user_prompt

        system_prompt = f"""{shared_rules}

CONTEXTE:
- Determinez d'abord si l'image montre le recto ou le verso
- Le recto contient le titulaire; le verso contient le numero CNI et souvent les noms des parents"""

        user_prompt = """Analysez cette image de CNI camerounaise.

Retournez ce JSON exact:
{
    "national_id": "",
    "full_name": "",
    "last_name": "",
    "first_name": "",
    "date_of_birth": "",
    "gender": "",
    "expiry_date": "",
    "father_name": "",
    "mother_name": "",
    "place_of_birth": "",
    "profession": "",
    "issue_date": "",
    "height": "",
    "mrz_text": "",
    "country": "CM",
    "document_type": "CNI_CAMEROON",
    "document_side": "",
    "extraction_quality": "",
    "warnings": []
}

Instructions:
1. Si c'est un recto, remplissez seulement les champs du titulaire visibles
2. Si c'est un verso, remplissez surtout national_id et les champs parents/naissance/profession
3. national_id -> uniquement la valeur lue sous NUMERO CNI / NIC NUMBER
4. mrz_text -> si une zone MRZ (lignes avec <<) est visible, recopiez les lignes telles quelles et separez-les par "\n"
5. Ne jamais utiliser un numero proche du portrait ou une colonne verticale comme national_id"""
        return system_prompt, user_prompt

    async def _extract_mrz_only(self, image_base64: str) -> str:
        if not self.api_key:
            return ""

        system_prompt = """Vous etes un expert MRZ (ICAO 9303) pour CNI camerounaises."""

        user_prompt = """Analysez l'image VERSO. Extrayez uniquement la MRZ.

Retournez ce JSON exact:
{
  "mrz_text": ""
}

Instructions:
- Si une zone MRZ est visible, recopiez les lignes telles quelles, avec les caracteres '<'.
- La MRZ commence souvent par I<CMR.
- Conservez les sauts de ligne entre les lignes MRZ.
- Si aucune MRZ n'est visible, laissez "mrz_text" vide.
"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{image_base64}"
                            },
                        },
                        {"type": "text", "text": user_prompt},
                    ],
                },
            ],
            "max_tokens": 256,
            "temperature": 0.0,
            "response_format": {"type": "json_object"},
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status != 200:
                        logger.warning("  MRZ-only HTTP %s", resp.status)
                        return ""
                    result = await resp.json()
        except Exception as exc:
            logger.warning("  MRZ-only erreur: %s", exc)
            return ""

        try:
            raw = result["choices"][0]["message"]["content"]
            data = json.loads(raw)
            return str(data.get("mrz_text") or "").strip()
        except Exception as exc:
            logger.warning("  MRZ-only parsing error: %s", exc)
            return ""

    @staticmethod
    def _normalize_document_side(document_side: Optional[str]) -> Optional[str]:
        if not document_side:
            return None
        normalized = str(document_side).strip().lower()
        if normalized in {"front", "recto"}:
            return "front"
        if normalized in {"back", "verso", "versau"}:
            return "back"
        return None

    def _calculate_confidence(self, fields: Dict[str, Any]) -> float:
        """Calculer confiance basée sur les champs"""
        if not fields:
            return 0.0

        if fields.get("document_type") == "CNI_CAMEROON":
            return calculate_cni_confidence(fields, document_side=fields.get("document_side"))

        # Fallback generique hors CNI
        critical = ["national_id", "full_name", "date_of_birth"]
        critical_filled = sum(1 for f in critical if fields.get(f) and str(fields.get(f)).strip())
        critical_ratio = critical_filled / len(critical)

        quality = fields.get("extraction_quality", "medium").lower()
        quality_scores = {"high": 0.95, "medium": 0.75, "low": 0.45}
        quality_score = quality_scores.get(quality, 0.75)

        confidence = round(0.6 * quality_score + 0.4 * (0.5 + critical_ratio * 0.5), 2)
        return min(confidence, 0.99)

    def _calculate_field_scores(self, fields: Dict[str, Any]) -> Dict[str, float]:
        """Scoring par champ"""
        if fields.get("document_type") == "CNI_CAMEROON":
            return calculate_cni_field_scores(fields, document_side=fields.get("document_side"))

        scores = {}
        quality = fields.get("extraction_quality", "medium").lower()
        base_score = {"high": 0.95, "medium": 0.75, "low": 0.45}.get(quality, 0.75)
        
        for key, value in fields.items():
            if key in ["confidence_notes", "warnings", "extraction_quality"]:
                continue
            if value and str(value).strip():
                scores[key] = base_score
            else:
                scores[key] = 0.0
        
        return scores

    async def analyze_document_integrity(self, image_base64: str) -> Dict[str, Any]:
        """Analyser l'intégrité du document via Groq"""
        try:
            if not self.api_key:
                return self._error_response_integrity("GROQ_API_KEY not configured")
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a document authentication expert. Analyze if the document is real or fake."
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{image_base64}"
                                }
                            },
                            {
                                "type": "text",
                                "text": """Analyze this ID document for authenticity.

Return JSON:
{
    "is_real": true/false,
    "is_tampered": true/false,
    "integrity_score": 0.0-1.0,
    "image_quality": "good" | "acceptable" | "poor",
    "warnings": ["List of detected issues"]
}

Return ONLY JSON."""
                            }
                        ]
                    }
                ],
                "max_tokens": 512,
                "temperature": 0.1,
                "response_format": {"type": "json_object"}
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    if resp.status != 200:
                        return self._error_response_integrity(f"HTTP {resp.status}")
                    
                    result = await resp.json()
            
            response_text = result["choices"][0]["message"]["content"]
            
            # Extraire le JSON
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(response_text)
            
            return {
                "integrity_score": data.get("integrity_score", 0.5),
                "is_tampered": data.get("is_tampered", False),
                "is_fake": not data.get("is_real", True),
                "warnings": data.get("warnings", [])
            }
        
        except Exception as e:
            logger.error(f"Groq integrity check error: {e}")
            return self._error_response_integrity(str(e))

    def _error_response(self, error: str) -> Dict[str, Any]:
        """Réponse d'erreur standardisée"""
        return {
            "success": False,
            "provider": "groq",
            "confidence": 0.0,
            "detected_fields": {},
            "confidence_scores": {},
            "warnings": ["groq_failed"],
            "error": error
        }

    def _error_response_integrity(self, error: str) -> Dict[str, Any]:
        """Réponse d'erreur intégrité"""
        return {
            "integrity_score": 0.0,
            "is_tampered": False,
            "is_fake": False,
            "warnings": ["integrity_check_failed"],
            "error": error
        }

    @property
    def name(self) -> str:
        return "groq"

    @property
    def is_available(self) -> bool:
        """Groq disponible si une clé API existe"""
        return bool(self.api_key)

    
