from pydantic import BaseModel, Field, ConfigDict
from typing import Any, Dict, Optional
from datetime import datetime


class KYCMetadata(BaseModel):
    """Métadonnées de la requête KYC"""
    
    device_id: str = Field(..., description="ID unique du device")
    ip_address: str = Field(..., description="Adresse IP du client")
    timestamp: datetime = Field(..., description="Timestamp ISO8601")
    app_version: str = Field(..., description="Version de l'app client")
    mobile_money_identity: Optional[Dict[str, Any]] = Field(
        None,
        description="Identité Mobile Money opérateur récupérée par le backend appelant.",
    )


class KYCAnalyzeRequest(BaseModel):
    """Requête d'analyse KYC vers Simba KYC."""
    
    user_id: str = Field(
        ..., 
        description="UUID unique de l'utilisateur"
    )
    document_front: str = Field(
        ..., 
        description="Image du recto du document (base64)"
    )
    document_back: Optional[str] = Field(
        None, 
        description="Image du verso du document (base64), optionnel"
    )
    selfie: str = Field(
        ..., 
        description="Image du selfie (base64)"
    )
    mrz_face: Optional[str] = Field(
        None,
        description="Photo faciale issue d'une source documentaire externe (ex: puce/NFC). Requise pour PASSPORT, ignoree pour CNI. Le MRZ texte n'embarque pas d'image."
    )
    metadata: KYCMetadata = Field(
        ..., 
        description="Métadonnées de la requête"
    )
    
    model_config = ConfigDict(json_schema_extra={
        "example": {
            "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "document_front": "base64_encoded_string...",
            "document_back": "base64_encoded_string...",
            "selfie": "base64_encoded_string...",
            "mrz_face": "base64_encoded_string...",
            "metadata": {
                "device_id": "device-uuid-123",
                "ip_address": "192.168.1.1",
                "timestamp": "2024-03-24T12:00:00Z",
                "app_version": "1.0.0"
            }
        }
    })
