import base64
import os
import shutil
import subprocess
from pathlib import Path
from app.services.qr_cni_decoder import QRCNIDecoder

pdf = Path('tests/unit/cni_photos/Scanned_20260303_210748.pdf')
out_dir = Path('tests/unit/cni_photos/.tmp_pdf_pages_fast')
if out_dir.exists():
    shutil.rmtree(out_dir)
out_dir.mkdir(parents=True, exist_ok=True)

subprocess.run(['pdftoppm', '-png', '-r', '300', '-f', '1', '-l', '2', str(pdf), str(out_dir / 'page')], check=True)
rendered = sorted(out_dir.glob('page-*.png'))
print('rendered_pages=', len(rendered))

decoder = QRCNIDecoder()
for p in rendered:
    analysis = decoder.analyze(document_front_base64=base64.b64encode(p.read_bytes()).decode('ascii'), document_back_base64='')
    parsed = analysis.get('parsed_fields', {})
    print('---')
    print('page_file:', p.name)
    print('detected:', analysis.get('detected'))
    print('required_fields_present:', analysis.get('required_fields_present'))
    print('full_name:', parsed.get('full_name'))
    print('national_id:', parsed.get('national_id'))
    print('date_of_birth:', parsed.get('date_of_birth'))
    print('expiry_date:', parsed.get('expiry_date'))
    print('error:', analysis.get('error'))
