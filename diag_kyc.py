import base64, asyncio, sys
from datetime import datetime
from app.core.config import settings
from app.infrastructure.external.llm_factory import get_llm_router
from app.infrastructure.external.aws_liveness import AWSLiveness
from app.services.liveness_checker import LivenessChecker
from app.services.kyc_orchestrator import KYCOrchestrator
from app.api.v1.schemas.request.kyc_analyze import KYCAnalyzeRequest, KYCMetadata

p='tests/unit/cni_photos/20260424_202529.jpg.jpeg'
with open(p,'rb') as f:
    b=base64.b64encode(f.read()).decode('utf-8')

async def main():
    router=get_llm_router()
    def _clean(value):
        if isinstance(value, str):
            value = value.strip()
        return value or None

    aws=AWSLiveness(
        region=settings.AWS_REGION,
        min_confidence=settings.AWS_LIVENESS_MIN_CONFIDENCE,
        aws_access_key_id=_clean(settings.AWS_ACCESS_KEY_ID),
        aws_secret_access_key=_clean(settings.AWS_SECRET_ACCESS_KEY),
        aws_session_token=_clean(settings.AWS_SESSION_TOKEN),
    )
    checker=LivenessChecker(aws)

    integrity = await router.analyze_document_integrity(b)
    print('INTEGRITY_SCORE', integrity.get('integrity_score'))
    print('IS_TAMPERED', integrity.get('is_tampered'))
    print('IS_FAKE', integrity.get('is_fake'))

    orch=KYCOrchestrator(ocr_service=router,liveness_service=aws,liveness_checker=checker)
    req=KYCAnalyzeRequest(
        user_id='diag-why-conclude',
        document_front=b,
        selfie=b,
        metadata=KYCMetadata(device_id='diag',ip_address='127.0.0.1',timestamp=datetime.utcnow(),app_version='1.0.0')
    )
    res=await orch.analyze_kyc(req)
    print('STATUS', res.status)
    print('REASON', res.reason)
    if res.fraud_indicators:
        print('HARD', ','.join(res.fraud_indicators.hard_reject_criteria))
        print('MANUAL', ','.join(res.fraud_indicators.manual_review_criteria))
        print('FLAGS', ','.join(res.fraud_indicators.flags))

if __name__ == "__main__":
    asyncio.run(main())
