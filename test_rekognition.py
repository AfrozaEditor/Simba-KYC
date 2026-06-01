import boto3
import os
from dotenv import load_dotenv

def main():
    load_dotenv()
    
    client = boto3.client('rekognition', region_name='us-east-1')
    
    files = [
        "tests/unit/cni_photos/20260424_202455.jpg.jpeg",
        "tests/unit/cni_photos/20260424_202529.jpg.jpeg"
    ]
    
    results = {}
    
    for file_path in files:
        if not os.path.exists(file_path):
            print(f"Error: {file_path} not found")
            results[file_path] = 0
            continue
            
        with open(file_path, 'rb') as image_file:
            image_bytes = image_file.read()
            
        response = client.detect_faces(Image={'Bytes': image_bytes})
        face_count = len(response.get('FaceDetails', []))
        print(f"{file_path}: {face_count} FaceDetails")
        results[file_path] = face_count
        
    if all(count >= 1 for count in results.values()):
        print("Verdict: compare_faces peut être exécuté proprement.")
    else:
        print("Verdict: compare_faces ne peut pas être exécuté proprement (visage manquant dans au moins une image).")

if __name__ == "__main__":
    main()
