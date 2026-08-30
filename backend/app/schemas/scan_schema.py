from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to analyze", max_length=2048)

class MessageScanRequest(BaseModel):
    message: str = Field(..., description="Suspicious SMS/Chat message text", max_length=10000)

class EmailScanRequest(BaseModel):
    subject: Optional[str] = Field("", description="Email Subject line", max_length=500)
    body: str = Field(..., description="Email Body content", max_length=20000)

class IndicatorItem(BaseModel):
    code: str
    label: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    description: str
    weight: int

class ExplanationDetail(BaseModel):
    summary: str
    why_risky: str
    possible_impact: List[str]
    evidence_breakdown: List[str]

class ScanResultResponse(BaseModel):
    content_hash: str
    input_type: str  # 'url', 'message', 'email', 'qr'
    normalized_input: str
    risk_score: int  # 0 - 100
    risk_level: str  # 'SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    threat_category: str
    detected_indicators: List[IndicatorItem]
    explanation: ExplanationDetail
    recommendations: List[str]
    stored_intel_found: bool = False
    stored_intel_details: Optional[Dict[str, Any]] = None
    db_status: str = "connected"  # 'connected' or 'storage_unavailable'
    analyzed_at: str


