from pdf_generator import create_pdf
import streamlit as st
import requests
import pytesseract
from PIL import Image
from groq import Groq
import tempfile
import os

BACKEND_URL = os.environ.get("BACKEND_URL", "https://my-osint-engine.onrender.com/api/analyze")

st.set_page_config(page_title="VoxIntel OSINT Engine", page_icon="🕵️", layout="wide")
st.title("🇲🇾 VoxIntel: Incident Triage & OSINT Engine")
st.markdown("Automated fraud analysis powered by Groq Cloud (Llama 3.1 & Whisper), OSINT lookups, and OCR.")
# Sidebar Telemetry Dashboard
st.sidebar.title("📊 Live Telemetry Dashboard")
st.sidebar.markdown("Anonymized threat statistics from recent scans.")

TELEMETRY_URL = BACKEND_URL.replace("/analyze", "/telemetry")
try:
    tel_response = requests.get(TELEMETRY_URL, timeout=5)
    if tel_response.status_code == 200:
        tel_data = tel_response.json()
        if tel_data:
            df = pd.DataFrame(tel_data)
            
            # Render Average Confidence
            avg_conf = int(df['confidence'].mean())
            st.sidebar.metric("Average Threat Confidence", f"{avg_conf}%")
            
            # Render Bar Chart of Scam Types
            st.sidebar.subheader("Recent Scam Vectors")
            type_counts = df['scam_type'].value_counts()
            st.sidebar.bar_chart(type_counts)
        else:
            st.sidebar.info("Database is currently empty. Run a scan to populate telemetry.")
    else:
        st.sidebar.error("Telemetry offline.")
except Exception as e:
    st.sidebar.error("Could not connect to Telemetry database.")

groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

@st.cache_data
def transcribe_audio_file(audio_bytes, file_ext):
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_ext}") as tmp_file:
        tmp_file.write(audio_bytes)
        tmp_path = tmp_file.name

    try:
        with open(tmp_path, "rb") as file:
            transcription = groq_client.audio.transcriptions.create(
                file=(os.path.basename(tmp_path), file.read()),
                model="whisper-large-v3",
            )
        os.remove(tmp_path)
        return transcription.text
    except Exception as e:
        os.remove(tmp_path)
        raise e

st.subheader("Report an Incident")
tab1, tab2, tab3 = st.tabs(["📝 Text Input", "🖼️ Upload Screenshot", "🎙️ Voice Note"])

user_story = ""

with tab1:
    text_input = st.text_area("Paste the suspicious message, email, or describe the phone call:", height=150)
    if text_input.strip():
        user_story = text_input

with tab2:
    uploaded_file = st.file_uploader("Upload a WhatsApp or SMS screenshot (PNG, JPG)", type=["png", "jpg", "jpeg"])
    if uploaded_file is not None:
        image = Image.open(uploaded_file)
        st.image(image, caption="Uploaded Screenshot", width=300)
        with st.spinner("Running Local OCR to extract text from image..."):
            try:
                extracted_text = pytesseract.image_to_string(image)
                st.info("Review and edit the extracted text before analyzing:")
                edited_ocr_text = st.text_area("Extracted Text", value=extracted_text, height=150, label_visibility="collapsed")
                user_story = edited_ocr_text
            except Exception as e:
                st.error(f"OCR failed. Error: {e}")

with tab3:
    uploaded_audio = st.file_uploader(
        "Upload a WhatsApp voice note or audio recording",
        type=["ogg", "mp3", "wav", "m4a", "aac", "opus", "oga"]
    )
    if uploaded_audio is not None:
        st.audio(uploaded_audio)
        with st.spinner("Transcribing audio instantly via Groq Cloud Whisper..."):
            try:
                file_ext = uploaded_audio.name.split('.')[-1]
                raw_transcript = transcribe_audio_file(uploaded_audio.getvalue(), file_ext)

                st.info("Review and edit the transcription below if Whisper missed any details:")
                edited_audio_text = st.text_area("Transcribed Text", value=raw_transcript, height=150, label_visibility="collapsed")
                user_story = edited_audio_text
            except Exception as e:
                st.error(f"Voice transcription failed: {e}")

if st.button("Analyze Threat", type="primary"):
    if not user_story.strip():
        st.warning("Please provide text, upload a screenshot, or upload a voice note to analyze.")
    else:
        success_data = None
        with st.spinner("Extracting IOCs, querying OSINT, and running AI reasoning via Groq..."):
            try:
                response = requests.post(
                    BACKEND_URL,
                    json={"raw_text": user_story},
                    timeout=120
                )
                if response.status_code == 200:
                    success_data = response.json()
                else:
                    st.error(f"Backend Error: {response.status_code}")
            except Exception as e:
                st.error(f"Failed to connect to backend. Error: {e}")

        # Outside the spinner and request try/except block
        if success_data:
            ai = success_data["ai_report"]
            st.divider()
            col1, col2 = st.columns([1, 2])

            with col1:
                st.metric("Scam Certainty", f"{ai['scam_certainty_percentage']}%")
                st.metric("Threat Category", ai['threat_category'])
                st.subheader("Extracted IOCs")
                st.json(success_data["extracted_iocs"])

            with col2:
                st.subheader("🧠 AI Evidence Breakdown")
                for evidence in ai['evidence_breakdown']:
                    st.markdown(f"- {evidence}")

                st.subheader("🚨 Recommended Action Plan")
                for action in ai['action_plan']:
                    st.markdown(f"- {action}")

            with st.expander("View Raw OSINT Intelligence Data"):
                st.json(success_data["osint_intelligence"])

            st.divider()
            try:
                pdf_bytes = create_pdf(success_data)
                st.download_button(
                    label="📄 Download Forensic PDF Report for PDRM",
                    data=pdf_bytes,
                    file_name="VoxIntel_Forensic_Report.pdf",
                    mime="application/pdf",
                    type="primary"
                )
            except Exception as e:
                st.error(f"PDF Generation Failed: {e}")
