"""Interface pour AWS Rekognition"""

from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class LivenessInterface(ABC):
    """Interface abstraite pour la vérification de vivacité"""
    
    @abstractmethod
    async def check_liveness(self, selfie_base64: str) -> Dict[str, Any]:
        """Vérifie la vivacité"""
        pass
    
    @abstractmethod
    async def compare_faces(self, selfie_base64: str, document_face_base64: str) -> Dict[str, Any]:
        """Compare deux visages"""
        pass
    
    @abstractmethod
    async def detect_spoof_attempts(self, selfie_base64: str) -> Dict[str, Any]:
        """Détecte les tentatives de spoofing"""
        pass


class AWSLiveness(LivenessInterface):
    """Implémentation d'AWS Rekognition pour liveness et face compare"""

    def __init__(
        self,
        region: str = "eu-west-1",
        min_confidence: float = 0.85,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
    ):
        """
        Initialise le client AWS Rekognition
        
        Args:
            region: Région AWS (default: eu-west-1)
            min_confidence: Score de confiance minimum pour approuver liveness
        """
        import boto3
        from botocore.config import Config
        
        self.region = region
        self.min_confidence = min_confidence
        self.max_attempts = 3
        
        # Initialiser boto3 client — credentials récupérées depuis .env
        # (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        client_kwargs: Dict[str, Any] = {
            "region_name": region,
            "config": Config(
                connect_timeout=10,
                read_timeout=60,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        }
        if aws_access_key_id and aws_secret_access_key:
            client_kwargs.update(
                {
                    "aws_access_key_id": aws_access_key_id,
                    "aws_secret_access_key": aws_secret_access_key,
                }
            )
            if aws_session_token:
                client_kwargs["aws_session_token"] = aws_session_token

        self.client = boto3.client("rekognition", **client_kwargs)

    @staticmethod
    def _is_transient_error(error_message: str) -> bool:
        """Identifie les erreurs AWS transitoires qui méritent un retry."""
        lowered = (error_message or "").lower()
        markers = [
            "connection was closed",
            "endpointconnectionerror",
            "read timed out",
            "requesttimeout",
            "throttling",
            "serviceunavailable",
            "internalservererror",
        ]
        return any(marker in lowered for marker in markers)

    def _detect_faces_with_retry(self, image_bytes: bytes, attributes: list) -> Dict[str, Any]:
        """DetectFaces avec retry léger pour absorber les erreurs réseau ponctuelles."""
        import time

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                return self.client.detect_faces(
                    Image={"Bytes": image_bytes},
                    Attributes=attributes,
                )
            except Exception as exc:
                last_exc = exc
                if attempt < self.max_attempts and self._is_transient_error(str(exc)):
                    time.sleep(0.2 * attempt)
                    continue
                raise

        if last_exc:
            raise last_exc
        return {"FaceDetails": []}

    def _compare_faces_with_retry(self, source_bytes: bytes, target_bytes: bytes) -> Dict[str, Any]:
        """CompareFaces avec retry léger pour les erreurs transitoires."""
        import time

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                return self.client.compare_faces(
                    SourceImage={'Bytes': source_bytes},
                    TargetImage={'Bytes': target_bytes},
                    SimilarityThreshold=70.0,
                )
            except Exception as exc:
                last_exc = exc
                if attempt < self.max_attempts and self._is_transient_error(str(exc)):
                    time.sleep(0.2 * attempt)
                    continue
                raise

        if last_exc:
            raise last_exc
        return {"FaceMatches": []}

    def _prepare_image_bytes(
        self,
        image_base64: str,
        max_dim: int = 1600,
        quality: int = 85,
        always_transcode: bool = False,
    ) -> bytes:
        """Décode et optimise une image pour limiter les erreurs réseau."""
        import base64
        import io

        raw_bytes = base64.b64decode(image_base64)

        # Evite du traitement inutile pour les petites images si aucun transcodage imposé.
        if not always_transcode and len(raw_bytes) <= 1_500_000:
            return raw_bytes

        try:
            from PIL import Image, ImageOps

            img = Image.open(io.BytesIO(raw_bytes))
            img = ImageOps.exif_transpose(img).convert("RGB")
            img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

            out = io.BytesIO()
            img.save(out, format="JPEG", quality=quality, optimize=True)
            optimized = out.getvalue()

            if optimized:
                return optimized
            return raw_bytes
        except Exception:
            # Fallback sur l'image brute si Pillow ou transcodage indisponible.
            return raw_bytes

    async def check_liveness(self, selfie_base64: str) -> Dict[str, Any]:
        """
        Vérifie la vivacité via AWS Rekognition DetectFaces
        
        Args:
            selfie_base64: Image du selfie en base64
        
        Returns:
            Dict avec is_live, confidence, liveness_score, method, details
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._sync_liveness, selfie_base64
        )

    def _sync_liveness(self, selfie_base64: str) -> Dict[str, Any]:
        """Vérification synchrone (exécutée dans un thread pool)"""
        
        try:
            import base64

            # Re-encode to a clean JPEG to improve Rekognition detection, then
            # fallback to raw bytes if needed.
            img_bytes = self._prepare_image_bytes(
                selfie_base64,
                max_dim=1600,
                quality=85,
                always_transcode=True,
            )
            raw_bytes = base64.b64decode(selfie_base64)
            
            # Appel AWS Rekognition DetectFaces
            response = self._detect_faces_with_retry(
                image_bytes=img_bytes,
                attributes=['ALL'],
            )

            if not response.get("FaceDetails"):
                response = self._detect_faces_with_retry(
                    image_bytes=raw_bytes,
                    attributes=['ALL'],
                )
            
            # Vérifier qu'un visage a été détecté
            if not response['FaceDetails']:
                return {
                    "is_live": False,
                    "confidence": 0.0,
                    "liveness_score": 0.0,
                    "method": "aws_rekognition",
                    "reason": "no_face_detected",
                    "face_count": 0,
                    "details": {}
                }

            face = response['FaceDetails'][0]
            confidence = face['Confidence'] / 100.0
            
            # Extraire les scores de qualité
            quality = face.get('Quality', {})
            brightness = quality.get('Brightness', 50) / 100.0
            sharpness = quality.get('Sharpness', 50) / 100.0

            # Score composite: confiance détection + qualité image
            # Pondération: 60% confiance, 20% luminosité, 20% netteté
            liveness_score = (
                confidence * 0.6 +
                brightness * 0.2 +
                sharpness * 0.2
            )
            
            is_live = liveness_score >= self.min_confidence

            return {
                "is_live": is_live,
                "confidence": round(liveness_score, 3),
                "liveness_score": round(liveness_score, 3),
                "quality_score": round((brightness + sharpness) / 2, 3),
                "method": "aws_rekognition",
                "face_count": len(response['FaceDetails']),
                "details": {
                    "face_confidence": round(confidence, 3),
                    "brightness": round(brightness, 3),
                    "sharpness": round(sharpness, 3),
                    "threshold": self.min_confidence
                }
            }
        except Exception as e:
            return {
                "is_live": False,
                "confidence": 0.0,
                "liveness_score": 0.0,
                "face_count": 0,
                "method": "aws_rekognition",
                "error": str(e),
                "details": {}
            }

    async def compare_faces(self, selfie_base64: str,
                             document_face_base64: str) -> Dict[str, Any]:
        """
        Compare le visage du selfie avec la photo du document
        
        Args:
            selfie_base64: Image du selfie en base64
            document_face_base64: Photo du visage du document en base64
        
        Returns:
            Dict avec match, confidence, similarity_score
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._sync_compare, selfie_base64, document_face_base64
        )

    def _sync_compare(self, selfie_base64: str,
                       document_face_base64: str) -> Dict[str, Any]:
        """Comparaison synchrone (exécutée dans un thread pool)"""
        
        try:
            import base64

            source_bytes = self._prepare_image_bytes(
                selfie_base64,
                max_dim=1280,
                quality=82,
                always_transcode=True,
            )
            target_bytes = self._prepare_image_bytes(
                document_face_base64,
                max_dim=1280,
                quality=82,
                always_transcode=True,
            )

            source_faces = self._detect_faces_with_retry(
                image_bytes=source_bytes,
                attributes=["DEFAULT"],
            ).get("FaceDetails", [])
            target_faces = self._detect_faces_with_retry(
                image_bytes=target_bytes,
                attributes=["DEFAULT"],
            ).get("FaceDetails", [])

            # Fallback: certains formats détectent mieux en octets bruts.
            if not source_faces:
                raw_source = base64.b64decode(selfie_base64)
                raw_source_faces = self._detect_faces_with_retry(
                    image_bytes=raw_source,
                    attributes=["DEFAULT"],
                ).get("FaceDetails", [])
                if raw_source_faces:
                    source_bytes = raw_source
                    source_faces = raw_source_faces

            if not target_faces:
                raw_target = base64.b64decode(document_face_base64)
                raw_target_faces = self._detect_faces_with_retry(
                    image_bytes=raw_target,
                    attributes=["DEFAULT"],
                ).get("FaceDetails", [])
                if raw_target_faces:
                    target_bytes = raw_target
                    target_faces = raw_target_faces

            if not source_faces:
                return {
                    "match": False,
                    "confidence": 0.0,
                    "similarity_score": 0.0,
                    "method": "aws_rekognition",
                    "error": "no_face_detected_source",
                }

            if not target_faces:
                return {
                    "match": False,
                    "confidence": 0.0,
                    "similarity_score": 0.0,
                    "method": "aws_rekognition",
                    "error": "no_face_detected_target",
                }

            # Appel AWS Rekognition CompareFaces
            response = self._compare_faces_with_retry(
                source_bytes=source_bytes,
                target_bytes=target_bytes,
            )
            
            matches = response.get('FaceMatches', [])
            
            if not matches:
                # Aucun visage correspondant trouvé
                return {
                    "match": False,
                    "confidence": 0.0,
                    "similarity_score": 0.0,
                    "method": "aws_rekognition"
                }
            
            # Prendre le meilleur match
            best = max(matches, key=lambda x: x['Similarity'])
            similarity = best['Similarity'] / 100.0
            
            # Considérer match si similarité >= 80%
            is_match = similarity >= 0.80

            return {
                "match": is_match,
                "confidence": round(similarity, 3),
                "similarity_score": round(similarity, 3),
                "method": "aws_rekognition"
            }
        except Exception as e:
            error_message = str(e)
            if "InvalidParameterException" in error_message:
                error_message = "invalid_face_input"
            return {
                "match": False,
                "confidence": 0.0,
                "similarity_score": 0.0,
                "method": "aws_rekognition",
                "error": error_message
            }

    def extract_face_base64(self, image_base64: str) -> Dict[str, Any]:
        """Extrait le visage principal d'une image via DetectFaces (AWS)."""
        try:
            import base64
            import io
            from PIL import Image, ImageOps

            image_bytes = self._prepare_image_bytes(
                image_base64,
                max_dim=1600,
                quality=85,
                always_transcode=True,
            )

            faces = self._detect_faces_with_retry(
                image_bytes=image_bytes,
                attributes=["DEFAULT"],
            ).get("FaceDetails", [])

            if not faces:
                raw_bytes = base64.b64decode(image_base64)
                faces = self._detect_faces_with_retry(
                    image_bytes=raw_bytes,
                    attributes=["DEFAULT"],
                ).get("FaceDetails", [])
                if faces:
                    image_bytes = raw_bytes

            if not faces:
                return {
                    "success": False,
                    "error": "no_face_detected",
                }

            # Prendre le plus grand visage
            def _area(face: Dict[str, Any]) -> float:
                box = face.get("BoundingBox") or {}
                return float(box.get("Width", 0.0)) * float(box.get("Height", 0.0))

            face = max(faces, key=_area)
            box = face.get("BoundingBox") or {}

            image = Image.open(io.BytesIO(image_bytes))
            image = ImageOps.exif_transpose(image).convert("RGB")
            width, height = image.size

            left = float(box.get("Left", 0.0))
            top = float(box.get("Top", 0.0))
            w = float(box.get("Width", 0.0))
            h = float(box.get("Height", 0.0))

            margin = 0.15
            x1 = max(0, int((left - margin * w) * width))
            y1 = max(0, int((top - margin * h) * height))
            x2 = min(width, int((left + w + margin * w) * width))
            y2 = min(height, int((top + h + margin * h) * height))

            if x2 <= x1 or y2 <= y1:
                return {
                    "success": False,
                    "error": "invalid_face_box",
                }

            crop = image.crop((x1, y1, x2, y2))
            out = io.BytesIO()
            crop.save(out, format="JPEG", quality=90, optimize=True)
            return {
                "success": True,
                "face_base64": base64.b64encode(out.getvalue()).decode("utf-8"),
                "method": "aws_detect_faces",
            }
        except Exception as exc:
            return {
                "success": False,
                "error": str(exc),
            }

    async def detect_spoof_attempts(self, selfie_base64: str) -> Dict[str, Any]:
        """
        Détecte les tentatives de spoofing (photo d'une photo, écran, etc.)
        
        Args:
            selfie_base64: Image du selfie en base64
        
        Returns:
            Dict avec is_spoofed, spoof_confidence, spoof_type, flags
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._sync_spoof, selfie_base64
        )

    def _sync_spoof(self, selfie_base64: str) -> Dict[str, Any]:
        """Détection spoofing synchrone (exécutée dans un thread pool)"""
        
        try:
            import re

            img_bytes = self._prepare_image_bytes(selfie_base64)
            
            # Appel AWS Rekognition DetectLabels
            # Détecte les objets/étiquettes pour identifier des indices de spoofing
            resp = self.client.detect_labels(
                Image={'Bytes': img_bytes},
                MaxLabels=10,
                MinConfidence=80
            )

            def normalize(value: str) -> str:
                return re.sub(r"[^a-z0-9]+", "_", value.strip().lower())

            critical_patterns = (
                "screen",
                "monitor",
                "display",
                "television",
                "tv",
            )
            warning_patterns = (
                "paper",
                "document",
                "printed",
                "text",
                "photography",
                "photo",
            )

            labels = [
                {
                    "name": item.get("Name", ""),
                    "confidence": float(item.get("Confidence", 0.0)),
                }
                for item in resp.get("Labels", [])
            ]

            critical_hits = [
                label for label in labels
                if label["confidence"] >= 90.0
                and any(pattern in label["name"].lower() for pattern in critical_patterns)
            ]

            warning_hits = [
                label for label in labels
                if label["confidence"] >= 85.0
                and any(pattern in label["name"].lower() for pattern in warning_patterns)
            ]

            is_spoofed = bool(critical_hits)
            spoof_confidence = 0.98 if critical_hits else 0.0
            spoof_type = critical_hits[0]["name"] if critical_hits else None

            flags = [normalize(hit["name"]) for hit in critical_hits]
            if not critical_hits and warning_hits:
                flags.extend([f"suspicious_{normalize(hit['name'])}" for hit in warning_hits])

            return {
                "is_spoofed": is_spoofed,
                "spoof_confidence": spoof_confidence,
                "spoof_type": spoof_type,
                "flags": sorted(set(flags)),
                "method": "aws_rekognition"
            }
        except Exception as e:
            return {
                "is_spoofed": False,
                "spoof_confidence": 0.0,
                "spoof_type": None,
                "flags": [],
                "method": "aws_rekognition",
                "error": str(e)
            }

