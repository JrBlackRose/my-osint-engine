from fpdf import FPDF

class ForensicPDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 16)
        self.cell(200, 10, txt="VoxIntel - Official Forensic Incident Report", ln=1, align="C")
        self.set_font("helvetica", "I", 10)
        self.cell(200, 10, txt="Generated for PDRM / Financial Institution Submission", ln=1, align="C")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 10, txt=f"Page {self.page_no()}", align="C")

def create_pdf(report_data: dict) -> bytes:
    pdf = ForensicPDF()
    # Explicitly set margins so the library doesn't miscalculate them as 0
    pdf.set_margins(15, 15, 15)
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    ai = report_data.get("ai_report", {})
    iocs = report_data.get("extracted_iocs", {})

    def safe_text(text):
        # Strips unsupported characters that cause width-calculation crashes
        return str(text).replace('\n', ' ').encode('latin-1', 'ignore').decode('latin-1')

    def add_section(title, lines):
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, txt=safe_text(title), ln=1)
        pdf.set_font("helvetica", "", 11)
        for line in lines:
            # pdf.write is immune to the multi_cell horizontal space bug
            pdf.write(6, txt=safe_text(line))
            pdf.ln(8) 
        pdf.ln(5)

    add_section("1. AI Threat Assessment", [
        f"Threat Category: {ai.get('threat_category', 'Unknown')}",
        f"Scam Certainty: {ai.get('scam_certainty_percentage', 0)}%"
    ])

    add_section("Evidence Breakdown:", [f"- {pt}" for pt in ai.get("evidence_breakdown", [])])

    add_section("2. Extracted Indicators of Compromise (IOCs)", [
        f"Phone Numbers: {', '.join(iocs.get('phone_numbers', [])) or 'None'}",
        f"Bank Accounts: {', '.join(iocs.get('bank_accounts', [])) or 'None'}",
        f"URLs: {', '.join(iocs.get('urls', [])) or 'None'}",
        f"IP Addresses: {', '.join(iocs.get('ip_addresses', [])) or 'None'}"
    ])

    add_section("3. Recommended Action Plan", [f"- {act}" for act in ai.get("action_plan", [])])

    # Safely output bytes depending on fpdf version
    try:
        return bytes(pdf.output(dest='S'))
    except Exception:
        return bytes(pdf.output())
