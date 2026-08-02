from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class TriageRequest(BaseModel):
    raw_text: str

class ExtractedIOCs(BaseModel):
    phone_numbers: List[str]
    bank_accounts: List[str]

class OSINTResult(BaseModel):
    value: str
    type: str # "phone" or "bank_account"
    pdrm_semak_mule: Dict[str, Any]
    caller_id: Dict[str, Any]

# --- NEW SCHEMAS FOR AI ANALYSIS ---

class AIAnalysisReport(BaseModel):
    scam_certainty_percentage: int
    threat_category: str
    evidence_breakdown: List[str]
    action_plan: List[str]

class TriageResponse(BaseModel):
    status: str
    extracted_iocs: ExtractedIOCs
    osint_intelligence: List[OSINTResult]
    ai_report: AIAnalysisReport # Added the AI report
