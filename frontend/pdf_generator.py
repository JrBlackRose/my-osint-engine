from fpdf import FPDF
import json

class ForensicPDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 16)
        self.cell(0, 10, "VoxIntel - Official Forensic Incident Report", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "I", 10)
        self.cell(0, 10, "Generated for PDRM / Financial Institution Submission", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def create_pdf(report_data: dict) -> bytes:
    pdf = ForensicPDF()
    pdf.add_page()
    
    ai = report_data.get("ai_report", {})
    iocs = report_data.get("extracted_iocs", {})

    # 1. AI Threat Assessment
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "1. AI Threat Assessment", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 11)
    pdf.multi_cell(0, 6, f"Threat Category: {ai.get('threat_category', 'Unknown')}")
    pdf.multi_cell(0, 6, f"Scam Certainty: {ai.get('scam_certainty_percentage', 0)}%")
    pdf.ln(5)

    # Evidence Breakdown
    pdf.set_font("helvetica", "B", 11)
    pdf.cell(0, 8, "Evidence Breakdown:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 11)
    for point in ai.get("evidence_breakdown", []):
        # Encode/decode handles any weird characters Llama might spit out
        clean_point = point.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 6, f"- {clean_point}")
    pdf.ln(5)

    # 2. Extracted Indicators of Compromise
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "2. Extracted Indicators of Compromise (IOCs)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 11)
    pdf.multi_cell(0, 6, f"Phone Numbers: {', '.join(iocs.get('phone_numbers', [])) or 'None'}")
    pdf.multi_cell(0, 6, f"Bank Accounts: {', '.join(iocs.get('bank_accounts', [])) or 'None'}")
    pdf.multi_cell(0, 6, f"URLs: {', '.join(iocs.get('urls', [])) or 'None'}")
    pdf.multi_cell(0, 6, f"IP Addresses: {', '.join(iocs.get('ip_addresses', [])) or 'None'}")
    pdf.ln(5)

    # 3. Action Plan
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "3. Recommended Action Plan", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "B", 11)
    for action in ai.get("action_plan", []):
        clean_action = action.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 6, f"- {clean_action}")

    return bytes(pdf.output())
