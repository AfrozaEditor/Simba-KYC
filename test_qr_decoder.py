import base64
import os
from app.services.qr_cni_decoder import QRCNIDecoder

def get_base64_image(image_path):
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode('utf-8')

image_dir = "tests/unit/cni_photos"
images = [f for f in os.listdir(image_dir) if f.endswith('.jpeg')]
images.sort()

decoder = QRCNIDecoder()

print(f"{'front_name':<40} | {'back_name':<40} | {'detected':<8} | {'source':<10} | {'national_id':<20} | {'error'}")
print("-" * 150)

def run_test(front_name, back_name=None):
    front_b64 = get_base64_image(os.path.join(image_dir, front_name))
    back_b64 = None
    if back_name:
        back_b64 = get_base64_image(os.path.join(image_dir, back_name))
    
    result = decoder.analyze(document_front_base64=front_b64, document_back_base64=back_b64)
    
    detected = result.get('detected', False)
    source = result.get('source', '-')
    national_id = result.get('national_id', '-')
    error = result.get('error', '')
    
    back_display = back_name if back_name else '-'
    print(f"{front_name:<40} | {back_display:<40} | {str(detected):<8} | {str(source):<10} | {str(national_id):<20} | {error}")

# Test each image alone as front
for img in images:
    run_test(img)

# Test every pair (i != j)
for i in range(len(images)):
    for j in range(len(images)):
        if i == j:
            continue
        run_test(images[i], images[j])
