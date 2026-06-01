#!/usr/bin/env python
"""Extraction des champs OCR/QR depuis les photos CNI réelles."""

import base64
import json
from pathlib import Path
from app.services.qr_cni_decoder import QRCNIDecoder

def get_base64_image(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

def extract_fields_from_photo(photo_path):
    """Extrait les champs OCR/QR d'une photo CNI."""
    decoder = QRCNIDecoder()
    
    front_b64 = get_base64_image(photo_path)
    analysis = decoder.analyze(document_front_base64=front_b64, document_back_base64="")
    
    return analysis

def main():
    image_dir = Path("tests/unit/cni_photos")
    images = sorted([f for f in image_dir.iterdir() if f.suffix.lower() in ['.jpeg', '.jpg', '.png']])
    
    print("\n" + "="*100)
    print("🔍 EXTRACTION OCR/QR DES PHOTOS CNI".center(100))
    print("="*100 + "\n")
    
    for img_path in images:
        print(f"\n📄 Fichier: {img_path.name}")
        print("-" * 100)
        
        try:
            result = extract_fields_from_photo(str(img_path))
            
            # Afficher les informations de détection
            print(f"  ✓ QR détecté: {result.get('detected', False)}")
            print(f"  ✓ Source: {result.get('source', 'N/A')}")
            print(f"  ✓ Erreur: {result.get('error', 'Aucune')}")
            
            # Afficher les champs parsés
            if result.get('parsed_fields'):
                print(f"\n  📋 Champs extraits:")
                for key, value in result['parsed_fields'].items():
                    print(f"     • {key}: {value}")
            
            # Afficher les données brutes si disponibles
            if result.get('raw_payload'):
                print(f"\n  📦 QR Payload: {result.get('raw_payload')[:80]}...")
                
            # Afficher analyse détaillée si présente
            if result.get('prefix_valid') is not None:
                print(f"\n  🔐 Validation QR:")
                print(f"     • Prefix valide: {result.get('prefix_valid')}")
                print(f"     • Base32 valide: {result.get('base32_valid')}")
                print(f"     • Décompression: {result.get('decompression_valid')}")
                print(f"     • Champs requis: {result.get('required_fields_present')}")
                print(f"     • Signature présente: {result.get('signature_present')}")
        
        except Exception as e:
            print(f"  ❌ Erreur: {str(e)}")
    
    print("\n" + "="*100 + "\n")

if __name__ == "__main__":
    main()
