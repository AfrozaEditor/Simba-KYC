import cv2
import numpy as np
import os
import glob

def try_decode(img):
    # OpenCV detectAndDecode
    detector = cv2.QRCodeDetector()
    try:
        val, points, straight_qrcode = detector.detectAndDecode(img)
        if val:
            return val
    except Exception:
        pass

    # OpenCV detectAndDecodeMulti
    try:
        results = detector.detectAndDecodeMulti(img)
        # Results can be (retval, decoded_info, points, straight_qrcode)
        if results and results[0]:
            for info in results[1]:
                if info:
                    return info
    except Exception:
        pass

    try:
        import zxingcpp
        results = zxingcpp.read_barcodes(img)
        for res in results:
            if res.text:
                return res.text
    except ImportError:
        pass

    return None

def process_image(img_path):
    img = cv2.imread(img_path)
    if img is None:
        return "Error: Could not read image"

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    variations = [
        ("Original", img),
        ("Grayscale", gray),
    ]
    
    variations.append(("EqualizeHist", cv2.equalizeHist(gray)))
    
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
    variations.append(("CLAHE", clahe.apply(gray)))
    
    variations.append(("Blur", cv2.GaussianBlur(gray, (5, 5), 0)))
    
    _, thresh = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
    variations.append(("Threshold", thresh))
    
    # Rotations
    variations.append(("Rotate 90", cv2.rotate(img, cv2.ROTATE_90_CLOCKWISE)))
    variations.append(("Rotate 180", cv2.rotate(img, cv2.ROTATE_180)))
    variations.append(("Rotate 270", cv2.rotate(img, cv2.ROTATE_90_COUNTERCLOCKWISE)))
    
    # Upscale
    variations.append(("Upscale x2", cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)))

    for name, v_img in variations:
        payload = try_decode(v_img)
        if payload:
            return f"{name}: {payload[:20]}"
    
    return None

images = glob.glob("tests/unit/cni_photos/*.jpeg")
unsuccessful = []

for img_path in images:
    result = process_image(img_path)
    if result:
        print(f"Image: {os.path.basename(img_path)} -> {result}")
    else:
        print(f"Image: {os.path.basename(img_path)} -> FAILED")
        unsuccessful.append(os.path.basename(img_path))

print("\n--- Summary ---")
if unsuccessful:
    print(f"Images failing all variations: {', '.join(unsuccessful)}")
else:
    print("All images decoded successfully!")
