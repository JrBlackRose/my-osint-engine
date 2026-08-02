import asyncio
from typing import Dict, List, Any
import re

MOCK_PDRM_SEMAK_MULE = {
    "162234567890": {"reports": 12, "last_reported": "2026-07-20", "status": "BLACKLISTED"},
    "8001234567": {"reports": 5, "last_reported": "2026-08-01", "status": "BLACKLISTED"},
    "01127450352": {"reports": 8, "last_reported": "2025-09-21", "status": "HIGH_RISK", "tag": "Impersonation (LHDN)"},
    "0178889999": {"reports": 2, "last_reported": "2026-01-15", "status": "MODERATE_RISK", "tag": "APK Phishing"}
}

MOCK_CALLER_ID_DB = {
    "01127450352": {"name": "Scam LHDN Fake", "provider": "Whoscall/Truecaller Mock"},
    "0123456789": {"name": "Ahmad Courier J&T", "provider": "Whoscall/Truecaller Mock"},
    "0178889999": {"name": "TNG Ewallet Support Fake", "provider": "Whoscall/Truecaller Mock"}
}

MOCK_ABUSE_IPDB = {
    "185.220.101.46": {"reports": 45, "country": "Russia", "status": "KNOWN_TOR_NODE"},
    "103.240.192.1": {"reports": 12, "country": "Malaysia", "status": "COMPROMISED_SERVER"}
}

HIGH_RISK_URL_KEYWORDS = ["vip", "task", "shopee-", "lazada-", "apk", "login-", "verify-", "coinbase-", "crypto-", "register"]
SUSPICIOUS_TLDS = [".top", ".xyz", ".vip", ".site", ".tk", ".cc", ".icu", ".app"]

def analyze_url_reputation(url: str) -> Dict[str, Any]:
    url_lower = url.lower()
    detected_flags = []
    for kw in HIGH_RISK_URL_KEYWORDS:
        if kw in url_lower: detected_flags.append(f"Contains high-risk scam keyword: '{kw}'")
    for tld in SUSPICIOUS_TLDS:
        if tld in url_lower: detected_flags.append(f"Uses high-risk TLD: '{tld}'")
    if url_lower.startswith("http://"):
        detected_flags.append("Unencrypted connection (HTTP)")

    is_suspicious = len(detected_flags) > 0
    return {
        "found": is_suspicious,
        "details": {
            "risk_score": 85 if is_suspicious else 10,
            "category": "Phishing / Malicious Domain" if is_suspicious else "Unflagged URL",
            "flags": detected_flags if detected_flags else ["No immediate heuristic flags detected"]
        }
    }

async def lookup_indicator(ioc_type: str, value: str) -> Dict[str, Any]:
    await asyncio.sleep(0.3)
    
    result = {
        "value": value,
        "type": ioc_type,
        "pdrm_semak_mule": {"found": False},
        "caller_id": {"found": False},
        "url_reputation": {"found": False},
        "ip_reputation": {"found": False}
    }

    if value in MOCK_PDRM_SEMAK_MULE:
        result["pdrm_semak_mule"] = {"found": True, "details": MOCK_PDRM_SEMAK_MULE[value]}

    if ioc_type == "phone" and value in MOCK_CALLER_ID_DB:
        result["caller_id"] = {"found": True, "details": MOCK_CALLER_ID_DB[value]}

    if ioc_type == "url":
        result["url_reputation"] = analyze_url_reputation(value)

    if ioc_type == "ip" and value in MOCK_ABUSE_IPDB:
        result["ip_reputation"] = {"found": True, "details": MOCK_ABUSE_IPDB[value]}

    return result

async def run_osint_enrichment(extracted_iocs: dict) -> List[Dict[str, Any]]:
    tasks = []
    for phone in extracted_iocs.get("phone_numbers", []): tasks.append(lookup_indicator("phone", phone))
    for bank in extracted_iocs.get("bank_accounts", []): tasks.append(lookup_indicator("bank_account", bank))
    for url in extracted_iocs.get("urls", []): tasks.append(lookup_indicator("url", url))
    for ip in extracted_iocs.get("ip_addresses", []): tasks.append(lookup_indicator("ip", ip))

    enriched_results = await asyncio.gather(*tasks)
    return enriched_results
