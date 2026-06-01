# Simba KYC

Microservice autonome de verification d'identite reutilisable par plusieurs applications.

Simba KYC expose une API HTTP dediee au KYC:

- OCR documentaire via Groq multimodal.
- Decodage QR de CNI camerounaise.
- Analyse MRZ pour passeports/documents compatibles.
- Liveness et comparaison faciale via AWS Rekognition.
- Catalogue de criteres anti-fraude explicables avec verdict `AUTO_APPROVE`, `MANUAL_REVIEW` ou `AUTO_REJECT`.

Le service ne depend pas d'Afroza, Phoenix, Django ou d'une base de donnees applicative. Les applications clientes envoient les images et les metadata, puis consomment la decision KYC retournee par API.

## Endpoints

| Methode | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/kyc/analyze` | Analyse KYC complete en JSON base64 |
| `POST` | `/api/v1/kyc/analyze/upload` | Analyse KYC complete en multipart upload |
| `POST` | `/api/v1/kyc/ocr` | OCR documentaire seul |
| `POST` | `/api/v1/kyc/ocr/upload` | OCR documentaire seul en upload |
| `POST` | `/api/v1/liveness/check` | Liveness selfie seule |
| `POST` | `/api/v1/liveness/check/upload` | Liveness selfie seule en upload |
| `POST` | `/api/v1/liveness/spoof` | Detection de spoofing |
| `POST` | `/api/v1/faces/compare` | Comparaison selfie/document |
| `POST` | `/api/v1/faces/compare/upload` | Comparaison selfie/document en upload |
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe |

L'ancien endpoint de scoring credit `/api/v1/score` a ete retire. Le seul score restant est `kyc_score`, un score interne de confiance KYC de 0 a 1000.

## Configuration

Copier `.env.example` vers `.env`, puis definir au minimum:

```env
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxx
LIVENESS_PROVIDER=aws
AWS_REGION=eu-west-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
API_KEY=une-cle-interne-longue
ALLOW_ANONYMOUS=false
```

`GROQ_API_KEYS` reste accepte pour compatibilite avec les anciennes configurations; si plusieurs cles sont separees par virgule, la premiere non vide est utilisee.

`LLM_PREFER_PROVIDER` et `LLM_FALLBACK_CHAIN` doivent rester centres sur `groq`; les providers locaux LLaVA/Ollama ne font plus partie du microservice KYC cible.

`LIVENESS_PROVIDER` doit rester `aws`. Les pipelines locaux YOLO/DeepFace ont ete retires de ce microservice.

## Authentification API

Tous les endpoints metier exigent l'en-tete:

```http
X-API-Key: <API_KEY>
```

`/health`, `/ready` et `/` restent publics pour les probes. Les docs FastAPI sont masquees par defaut; les exposer uniquement en environnement controle avec:

```env
EXPOSE_API_DOCS=true
```

## Demarrage local

```bash
cd simba_bot
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

Health checks:

```bash
curl http://localhost:8001/health
curl http://localhost:8001/ready
```

## Exemple KYC complet

```bash
curl -X POST http://localhost:8001/api/v1/kyc/analyze/upload \
  -H "X-API-Key: $SIMBA_KYC_API_KEY" \
  -F "user_id=user-001" \
  -F "document_front=@/path/to/cni-recto.jpg" \
  -F "document_back=@/path/to/cni-verso.jpg" \
  -F "selfie=@/path/to/selfie.jpg" \
  -F "device_id=device-123" \
  -F "ip_address=203.0.113.10" \
  -F "app_version=1.0.0"
```

Reponse simplifiee:

```json
{
  "success": true,
  "data": {
    "valid": true,
    "status": "APPROVED",
    "kyc_data": {
      "full_name": "AQIL BELL",
      "national_id": "AB05011462",
      "document_type": "CNI_CAMEROON",
      "country": "CM"
    },
    "liveness": {
      "passed": true,
      "confidence": 0.95,
      "method": "aws_rekognition"
    },
    "fraud_indicators": {
      "document_integrity": 0.98,
      "face_match_score": 0.92,
      "is_suspicious": false,
      "flags": [],
      "criteria_results": []
    },
    "kyc_score": 750,
    "recommendation": "AUTO_APPROVE"
  },
  "error": null
}
```

## Docker

```bash
docker build -t simba-kyc .
docker run --env-file .env -p 8001:8001 simba-kyc
```

Le service est concu pour etre deploye sur un serveur ou domaine dedie, puis appele en backend-to-backend depuis les applications clientes.

## Tests

```bash
cd simba_bot
pytest
```

Les tests unitaires couvrent les regles QR/MRZ, le post-traitement OCR CNI, les criteres anti-fraude et les decisions KYC.
