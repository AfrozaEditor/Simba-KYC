import base64, re, zlib, sys
from pathlib import Path
try:
    from app.services.qr_cni_decoder import QRCNIDecoder
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

p = Path('tests/unit/cni_photos/.tmp_pdf_pages_fast/page-2.png')
if not p.exists():
    print(f"File not found: {p}")
    sys.exit(1)

img_b64 = base64.b64encode(p.read_bytes()).decode('ascii')
analysis = QRCNIDecoder().analyze(document_front_base64=img_b64, document_back_base64='')
raw = analysis.get('raw_payload') or ''
if not raw:
    print("No raw_payload found")
    sys.exit(0)

print(f"raw_payload_start: {raw[:20]}")

if raw.startswith('IDB1D'):
    payload = raw[5:]
else:
    payload = raw
payload += '=' * ((8 - len(payload) % 8) % 8)
try:
    compressed = base64.b32decode(payload, casefold=True)
    decomp = zlib.decompress(compressed)
    print('decomp_len=', len(decomp))

    # heuristic printable segments
    printable = ''.join(chr(b) if 32 <= b <= 126 else ' ' for b in decomp)
    segments = [s for s in re.split(r'\s+', printable) if len(s) >= 4]
    print('segments_sample=', segments[:30])

    # identity-like regex matches
    id_matches = re.findall(r'[A-Z]{1,4}[0-9]{5,}', printable)
    date_matches = re.findall(r'(?:\d{2}[./-]\d{2}[./-]\d{4}|\d{8}|\d{4}[./-]\d{2}[./-]\d{2})', printable)
    name_matches = re.findall(r'[A-Z]{3,}(?:\s+[A-Z]{3,}){1,4}', printable)
    print('id_matches=', id_matches[:10])
    print('date_matches=', date_matches[:10])
    print('name_matches=', name_matches[:10])
except Exception as e:
    print(f"Error processing payload: {e}")
