from pydantic import BaseModel
from typing import List, Dict, Any

class ExtractedIOCs(BaseModel):
    phone_numbers: List[str] = []
    bank_accounts: List[str] = []
    urls: List[str] = []

class OSINTResult(BaseModel):
    phone_checks: Dict[str, Any] = {}
    bank_checks: Dict[str, Any] = {}
    url_checks: Dict[str, Any] = {}

class AIAnalysisReport(BaseModel):
    scam_certainty_percentage: int
    threat_category: str
    evidence_breakdown: List[str]
    action_plan: List[str]

class TriageRequest(BaseModel):
    raw_text: str

class TriageResponse(BaseModel):
    status: str
    extracted_iocs: ExtractedIOCs
    osint_intelligence: Dict[str, Any]
    ai_report: AIAnalysisReport
