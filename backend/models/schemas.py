from pydantic import BaseModel
from typing import Optional
from uuid import UUID
from datetime import datetime

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ScanResponse(BaseModel):
    id: UUID
    file_name: str
    file_size: Optional[int]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    vt_status: Optional[str]
    vt_detections: Optional[int]
    vt_total_engines: Optional[int]
    vt_permalink: Optional[str]
    created_at: datetime