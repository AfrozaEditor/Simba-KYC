#!/usr/bin/env python
"""Rapport comparatif OCR vs QR pour les photos CNI."""

import asyncio
import base64
import json
from pathlib import Path
from app.services.qr_cni_decoder import QRCNIDecoder
from app.infrastructure.external.llm_factory import get_llm_router

async def get_base64_image(image_path):
    """Convertir une image en base64."""
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

async def extract_ocr_fields(photo_path, llm_router):
    """Extraire les champs OCR via LLM."""
    try:
        front_b64 = await get_base64_image(photo_path)
        result = await llm_router.extract_from_image(
            image_base64=front_b64,
            document_type="CNI_CAMEROON"
        )
        return result.get('detected_fields', {}) if result.get('success') else {}
    except Exception as e:
        return {}

def extract_qr_fields(photo_path):
    """Extraire les champs QR."""
    try:
        decoder = QRCNIDecoder()
        front_b64 = base64.b64encode(Path(photo_path).read_bytes()).decode('utf-8')
        result = decoder.analyze(document_front_base64=front_b64, document_back_base64="")
        return result.get('parsed_fields', {}) if result.get('detected') else {}
    except Exception as e:
        return {}

def compare_fields(ocr_fields, qr_fields, photo_name):
    """Comparer les champs OCR vs QR."""
    
    # Les champs à comparer
    FIELDS = ['national_id', 'full_name', 'first_name', 'last_name', 'date_of_birth', 
              'expiry_date', 'gender', 'country']
    
    print(f"\n📊 RAPPORT: {photo_name}")
    print("="*140)
    
    print(f"\n{'Champ':<20} | {'OCR (Groq LLM)':<50} | {'QR (Decoder)':<50} | {'Match?':<10}")
    print("-"*140)
    
    matches = 0
    comparisons = 0
    
    for field in FIELDS:
        ocr_val = str(ocr_fields.get(field, '-')).strip() or '-'
        qr_val = str(qr_fields.get(field, '-')).strip() or '-'
        
        # Normaliser pour comparaison
        ocr_norm = ocr_val.lower() if ocr_val != '-' else ''
        qr_norm = qr_val.lower() if qr_val != '-' else ''
        
        # Vérifier correspondance
        if ocr_val != '-' and qr_val != '-':
            comparisons += 1
            is_match = ocr_norm == qr_norm
            if is_match:
                matches += 1
            status = "✅ MATCH" if is_match else "❌ DIFF"
        else:
            status = "⊘ N/A"
        
        print(f"{field:<20} | {ocr_val:<50} | {qr_val:<50} | {status:<10}")
    
    # Score de concordance
    if comparisons > 0:
        score = (matches / comparisons) * 100
        print(f"\n📈 Score de concordance: {matches}/{comparisons} ({score:.0f}%)")
    
    return (matches, comparisons)

async def main():
    llm_router = get_llm_router()
    image_dir = Path("tests/unit/cni_photos")
    images = sorted([f for f in image_dir.iterdir() if f.suffix.lower() in ['.jpeg', '.jpg', '.png']])
    
    print("\n" + "="*140)
    print("🔄 COMPARAISON OCR (LLM) vs QR (Décodeur)".center(140))
    print("="*140)
    
    total_matches = 0
    total_comparisons = 0
    
    for img_path in images:
        print(f"\n⏳ Traitement: {img_path.name}")
        
        ocr_fields = await extract_ocr_fields(str(img_path), llm_router)
        qr_fields = extract_qr_fields(str(img_path))
        
        if not ocr_fields and not qr_fields:
            print(f"⚠️  Aucune donnée extraite (OCR et QR vides)")
            continue
        
        matches, comparisons = compare_fields(ocr_fields, qr_fields, img_path.name)
        total_matches += matches
        total_comparisons += comparisons
    
    # Résumé final
    print("\n" + "="*140)
    print("📊 RÉSUMÉ GLOBAL".center(140))
    print("="*140)
    
    if total_comparisons > 0:
        global_score = (total_matches / total_comparisons) * 100
        print(f"\n✅ Matches totales: {total_matches}/{total_comparisons} ({global_score:.0f}%)")
        print(f"   • {total_comparisons - total_matches} divergences détectées")
    else:
        print("\n⚠️  Aucune comparaison disponible")
    
    print(f"\n📌 Observations:")
    print(f"   • OCR (Groq LLM): Extraction via reconnaissance optique de caractères")
    print(f"   • QR (Décodeur): Extraction via code QR encodé dans le document")
    print(f"   • Les divergences peuvent indiquer des erreurs OCR ou des données QR corrompues")
    
    print("\n" + "="*140 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
