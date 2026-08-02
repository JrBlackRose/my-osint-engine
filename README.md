# 🇲🇾 Malaysian Incident Triage & OSINT Engine (Local Edition)

An automated, multimodal incident triage and OSINT intelligence platform designed specifically for the Malaysian threat landscape. Built with a 100% local architecture ensuring absolute data privacy and zero API costs.

## 🚀 Key Features

*   **Multimodal Intake:** Analyzes raw text stories or extracts data directly from uploaded SMS/WhatsApp screenshots using Tesseract OCR.
*   **Intelligent Regex Extraction:** Standardizes Malaysian phone numbers (`+60`, `01x`) and local bank account numbers while preventing data overlap using custom post-extraction filtering.
*   **Simulated OSINT Enrichment:** Queries extracted indicators against mock databases simulating the PDRM Semak Mule and Truecaller/Whoscall registries.
*   **Local AI Reasoning Engine:** Leverages the local **Llama 3.1** model via Ollama to analyze the threat context, assign a Scam Certainty Percentage, and generate an evidence breakdown.
*   **Localized Action Plan:** Provides specific, actionable mitigation steps for victims in Malaysia (e.g., hardcoded guidance to contact NSRC at 997, not 999).

## 🛠️ Architecture

*   **Backend:** FastAPI (Python), Uvicorn
*   **Frontend:** Streamlit
*   **AI Engine:** Ollama (Llama 3.1)
*   **OCR:** Tesseract, pytesseract, Pillow

## ⚙️ Setup Instructions

### 1. Prerequisites
Ensure you have Python 3.13+, Tesseract OCR, and Ollama installed on your system.

```bash
# Install Tesseract (Debian/Kali)
sudo apt update && sudo apt install tesseract-ocr

# Install Ollama
curl -fsSL [https://ollama.com/install.sh](https://ollama.com/install.sh) | sh
