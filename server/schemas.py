from typing import List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Absolute or relative path to target directory or file")
    scan_type: str = Field(default="custom", description="Scan mode: quick, full, or custom")


class DetectionItem(BaseModel):
    file_path: str
    file_name: str
    sha256: str
    verdict: str
    risk_score: int
    reasons: str
    quarantined: bool


class ScanResponse(BaseModel):
    id: str
    target_path: str
    scan_type: str
    status: str
    files_scanned: int
    threats_found: int
    started_at: str
    completed_at: Optional[str] = None
    detections: List[DetectionItem] = []


class QuarantineRequest(BaseModel):
    file_path: str


class QuarantineItem(BaseModel):
    id: int
    original_path: str
    vault_filename: str
    sha256: str
    verdict: str
    reasons: str
    quarantined_at: str


class StatusResponse(BaseModel):
    realtime_protection: bool
    total_scans: int
    threats_found: int
    quarantined_files: int
    last_scan_time: Optional[str] = None