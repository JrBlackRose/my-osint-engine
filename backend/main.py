from fastapi import FastAPI
from models.schemas import TriageRequest, TriageResponse, ExtractedIOCs, AIAnalysisReport
from services.ioc_extractor import extract_iocs
from services.osint_lookup import run_osint_enrichment
from services.ai_analyzer import analyze_threat_context

app = FastAPI(
    title="Malaysian OSINT Triage Engine",
    description="Backend API for parsing and triaging local scam indicators.",
    version="0.2.0"
)

@app.get("/")
def health_check():
    return {"status": "operational", "engine": "OSINT Triage V2.0"}

@app.post("/api/analyze", response_model=TriageResponse)
async def analyze_story(request: TriageRequest):
    # Step 1: Extract IOCs
    raw_iocs = extract_iocs(request.raw_text)
    
    # Step 2: Enrich IOCs via simulated OSINT
    enriched_iocs = await run_osint_enrichment(raw_iocs)
    
    # Step 3: AI Threat Analysis (passing raw text + OSINT data)
    ai_results = await analyze_threat_context(request.raw_text, enriched_iocs)
    
    return TriageResponse(
        status="success",
        extracted_iocs=ExtractedIOCs(
            phone_numbers=raw_iocs["phone_numbers"],
            bank_accounts=raw_iocs["bank_accounts"],
            urls=raw_iocs.get("urls", []),
            ip_addresses=raw_iocs.get("ip_addresses", [])
        ),
        osint_intelligence=enriched_iocs,
        ai_report=AIAnalysisReport(
            scam_certainty_percentage=ai_results.get("scam_certainty_percentage", 0),
            threat_category=ai_results.get("threat_category", "Unknown"),
            evidence_breakdown=ai_results.get("evidence_breakdown", []),
            action_plan=ai_results.get("action_plan", ["Call NSRC 997 if in doubt."])
        )
    )
