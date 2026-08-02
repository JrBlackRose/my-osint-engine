import asyncio
from typing import Dict, List, Any

# ==========================================
# MOCK THREAT INTELLIGENCE DATABASES
# (Simulating PDRM Semak Mule & Caller ID)
# ==========================================

MOCK_PDRM_SEMAK_MULE = {
    # High-risk Macau Scam bank accounts
    "162234567890": {"reports": 12, "last_reported": "2026-07-20", "status": "BLACKLISTED"},
    "8001234567": {"reports": 5, "last_reported": "2026-08-01", "status": "BLACKLISTED"},
    
    # Suspicious Phone Numbers
    "01127450352": {"reports": 8, "last_reported": "2025-09-21", "status": "HIGH_RISK", "tag": "Impersonation (LHDN)"},
    "0178889999": {"reports": 2, "last_reported": "2026-01-15", "status": "MODERATE_RISK", "tag": "APK Phishing"}
}

MOCK_CALLER_ID_DB = {
    "01127450352": {"name": "Scam LHDN Fake", "provider": "Whoscall/Truecaller Mock"},
    "0123456789": {"name": "Ahmad Courier J&T", "provider": "Whoscall/Truecaller Mock"},
    "0178889999": {"name": "TNG Ewallet Support Fake", "provider": "Whoscall/Truecaller Mock"}
}

async def lookup_indicator(ioc_type: str, value: str) -> Dict[str, Any]:
    """
    Simulates an asynchronous API call to external OSINT sources.
    """
    # Simulate network latency
    await asyncio.sleep(0.5) 
    
    result = {
        "value": value,
        "type": ioc_type,
        "pdrm_semak_mule": {"found": False},
        "caller_id": {"found": False}
    }

    # 1. Check PDRM Semak Mule (Simulated)
    if value in MOCK_PDRM_SEMAK_MULE:
        result["pdrm_semak_mule"] = {
            "found": True,
            "details": MOCK_PDRM_SEMAK_MULE[value]
        }

    # 2. Check Caller ID (Only for phone numbers)
    if ioc_type == "phone" and value in MOCK_CALLER_ID_DB:
         result["caller_id"] = {
             "found": True,
             "details": MOCK_CALLER_ID_DB[value]
         }
         
    return result

async def run_osint_enrichment(extracted_iocs: dict) -> List[Dict[str, Any]]:
    """
    Takes the dictionary of extracted IOCs from ioc_extractor.py and 
    runs parallel OSINT lookups on all of them.
    """
    tasks = []
    
    for phone in extracted_iocs.get("phone_numbers", []):
        tasks.append(lookup_indicator("phone", phone))
        
    for bank in extracted_iocs.get("bank_accounts", []):
        tasks.append(lookup_indicator("bank_account", bank))

    # Execute all lookups concurrently for speed
    enriched_results = await asyncio.gather(*tasks)
    return enriched_results
