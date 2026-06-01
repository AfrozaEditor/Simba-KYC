from pathlib import Path
from PIL import Image, ImageOps, ImageEnhance
import zxingcpp
import sys

folder = Path('tests/unit/cni_photos')
if not folder.exists():
    print(f"Folder {folder} not found")
    sys.exit(1)

def variants(img):
    out = [('orig', img)]
    gray = ImageOps.grayscale(img)
    out.append(('gray', gray))

    for f in (1.5, 2.0):
        out.append((f'contrast_{f}', ImageEnhance.Contrast(gray).enhance(f)))

    w, h = img.size
    crops = {
        'crop_tl': (0, 0, int(w*0.7), int(h*0.7)),
        'crop_tr': (int(w*0.3), 0, w, int(h*0.7)),
        'crop_bl': (0, int(h*0.3), int(w*0.7), h),
        'crop_br': (int(w*0.3), int(h*0.3), w, h),
    }
    for n, box in crops.items():
        c = img.crop(box)
        out.append((n, c))
        out.append((n+'_gray', ImageOps.grayscale(c)))

    rots = []
    for n, im in list(out):
        rots.append((n+'_r90', im.rotate(90, expand=True)))
        rots.append((n+'_r180', im.rotate(180, expand=True)))
        rots.append((n+'_r270', im.rotate(270, expand=True)))
    out.extend(rots)
    return out

files = sorted(folder.glob('*.jpeg'))
print(f"Found {len(files)} files")

for p in files:
    img = Image.open(p)
    found = None
    variant = None
    all_variants = variants(img)
    for name, v in all_variants:
        try:
            res = zxingcpp.read_barcode(v)
            if res is not None and res.valid:
                found = res.text
                variant = name
                break
        except Exception:
            continue

    print('---')
    print('file:', p.name)
    print('decoded:', bool(found))
    if found:
        print('variant:', variant)
        print('prefix:', repr(found[:20]))
        print('length:', len(found))
