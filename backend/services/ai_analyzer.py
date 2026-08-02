import json
import os
from typing import Dict, Any
from groq import AsyncGroq

client = AsyncGroq(api_key=os.environ.get("GROQ_API_KEY"))

async def analyze_threat_context(raw_text: str, osint_data: list) -> Dict[str, Any]:
    system_prompt = """
    You are an expert Malaysian Cybersecurity Forensics AI. 
    Analyze the user's reported incident and the provided OSINT data.
    
    CRITICAL INSTRUCTIONS:
    1. DYNAMIC LANGUAGE MATCHING: Detect the primary language/dialect of the user's incident description (Bahasa Melayu, English, Manglish, Chinese, Tamil, etc.). Generate the `evidence_breakdown` and `action_plan` in THAT EXACT SAME LANGUAGE.
    
    2. STRICT SCAM CATEGORIZATION RULES:
       - "Macau Scam": IMPERSONATION of government agencies (LHDN, Inland Revenue, PDRM/Police, Courts, Kastam, Pos Laju) demanding urgent funds to avoid arrest or legal action.
       - "Job / Investment Scam": Offers for part-time tasks, illegal investment returns, or Telegram crypto schemes.
       - "APK Phishing": Prompts to download third-party Android apps (.apk).
       - "Safe / Unknown": No suspicious indicators.
       
    3. MANDATORY HOTLINE RULE:
       - The `action_plan` MUST explicitly direct the user to call the National Scam Response Centre (NSRC) hotline at 997 immediately.
       - Example (BM): "Hubungi Pusat Respons Scam Kebangsaan (NSRC) di talian 997 dengan kadar segera."
       - NEVER mention 999 for financial scams.
    
    You MUST return the output strictly as a JSON object matching this structure:
    {
        "scam_certainty_percentage": 90,
        "threat_category": "Macau Scam",
        "evidence_breakdown": ["Point 1", "Point 2"],
        "action_plan": ["Action 1", "Action 2"]
    }
    """

    user_prompt = f"""
    User Story: "{raw_text}"
    
    OSINT Intelligence Gathered:
    {json.dumps(osint_data, indent=2)}
    """

    try:
        response = await client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        
        result = json.loads(response.choices[0].message.content)
        
        corrected_action_plan = []
        for action in result.get('action_plan', []):
            corrected_action = action.replace('999', '997')
            corrected_action_plan.append(corrected_action)
            
        result['action_plan'] = corrected_action_plan
        
        return result
        
    except Exception as e:
        print(f"Groq Cloud AI Analysis Error: {e}")
        return {
            "scam_certainty_percentage": 0,
            "threat_category": "Error - Cloud LLM Failed",
            "evidence_breakdown": [str(e)],
            "action_plan": ["Sila hubungi NSRC di talian 997 dengan kadar segera / Call NSRC at 997 immediately."]
        }
