from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from models.schemas import TriageRequest, TriageResponse, ExtractedIOCs, AIAnalysisReport
from services.ioc_extractor import extract_iocs
from services.osint_lookup import run_osint_enrichment
from services.ai_analyzer import analyze_threat_context
from services.database import init_db, log_scan, get_recent_telemetry
import difflib

# Initialize Rate Limiter (Track by IP)
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Malaysian OSINT Triage Engine",
    description="Backend API for parsing and triaging local scam indicators.",
    version="0.3.2"
)

# SECURE PROXY ROUTING: Extracts the TRUE client IP from Render's load balancer, ignoring spoofed headers.
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

# Bind Rate Limiter to FastAPI app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# OWASP A05 Mitigation: Strict CORS Policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://voxintel.streamlit.app", 
        "http://localhost:8501",
        "http://127.0.0.1:8501"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

init_db()

SCAM_TEMPLATES = {
    "Macau Scam": "Sila buat bayaran segera ke akaun bank untuk mengelakkan waran tangkap dari PDRM LHDN mahkamah.",
    "APK Phishing": "Sila muat turun aplikasi apk ini untuk menuntut bantuan e-wallet jemputan perkahwinan file.",
    "Job / Investment Scam": "Buat tugasan VIP Shopee Lazada untuk komisen tinggi. Masukkan wang ke akaun.",
    "Tech Support Scam": "Akaun anda telah disekat. Sila hubungi nombor ini untuk pengesahan segera."
}

def calculate_semantic_match(user_text: str) -> str:
    best_match = None
    highest_ratio = 0.0
    for scam_type, template in SCAM_TEMPLATES.items():
        ratio = difflib.SequenceMatcher(None, user_text.lower(), template.lower()).ratio()
        if ratio > highest_ratio:
            highest_ratio = ratio
            best_match = scam_type
    
    percentage_score = int(highest_ratio * 100)
    
    if percentage_score > 40:
        return f"SYSTEM METRIC: This incident shares an {percentage_score}% structural pattern match with historically documented 2026 {best_match} fraud vectors."
    return "SYSTEM METRIC: No strong historical structural pattern match found in the local archive."

@app.get("/")
def health_check():
    return {"status": "operational", "engine": "OSINT Triage V3.1 - Hardened"}

@app.get("/api/telemetry")
@limiter.limit("30/minute") # Protect the dashboard polling
def fetch_telemetry(request: Request):
    return get_recent_telemetry()

@app.post("/api/analyze", response_model=TriageResponse)
@limiter.limit("10/minute") # OWASP A04 Mitigation: Block API Spam
async def analyze_story(request: Request, payload: TriageRequest):
    # Notice we changed the parameter slightly to inject the Request object for the limiter
    raw_iocs = extract_iocs(payload.raw_text)
    enriched_iocs = await run_osint_enrichment(raw_iocs)
    ai_results = await analyze_threat_context(payload.raw_text, enriched_iocs)

    semantic_string = calculate_semantic_match(payload.raw_text)
    if "evidence_breakdown" in ai_results:
        ai_results["evidence_breakdown"].append(semantic_string)

    scam_type = ai_results.get("threat_category", "Unknown")
    confidence = ai_results.get("scam_certainty_percentage", 0)
    log_scan(scam_type, confidence)

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
            scam_certainty_percentage=confidence,
            threat_category=scam_type,
            evidence_breakdown=ai_results.get("evidence_breakdown", []),
            action_plan=ai_results.get("action_plan", ["Call NSRC 997 immediately."])
        )
    )
