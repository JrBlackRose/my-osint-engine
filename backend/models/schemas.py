from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class TriageRequest(BaseModel):
    # OWASP A03 Mitigation: Cap input at 5,000 chars to prevent DoS via massive payloads
    raw_text: str = Field(..., max_length=5000, description="The raw incident text")

class ExtractedIOCs(BaseModel):
    phone_numbers: List[str] = []
    bank_accounts: List[str] = []
    urls: List[str] = []
    ip_addresses: List[str] = []

class AIAnalysisReport(BaseModel):
    scam_certainty_percentage: int
    threat_category: str
    evidence_breakdown: List[str]
    action_plan: List[str]

class TriageResponse(BaseModel):
    status: str
    extracted_iocs: ExtractedIOCs
    osint_intelligence: List[Dict[str, Any]]
    ai_report: AIAnalysisReport
