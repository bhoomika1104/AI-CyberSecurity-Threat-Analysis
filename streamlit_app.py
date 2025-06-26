import streamlit as st
import pandas as pd
import os
import sys

# Add the parent directory to sys.path to import main.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import CybersecurityThreatDetector

st.set_page_config(page_title="AI-Powered Cybersecurity Threat Detection", layout="wide")

@st.cache_resource
def load_detector():
    detector = CybersecurityThreatDetector()
    detector.load_models()
    return detector

detector = load_detector()

st.title("AI-Powered Cybersecurity Threat Detection System")

menu = ["Home", "Network Threat Detection", "Malware Detection", "Phishing Detection", "Dashboard"]
choice = st.sidebar.selectbox("Select Functionality", menu)

if choice == "Home":
    st.write("Welcome to the AI-Powered Cybersecurity Threat Detection System.")
    st.write("Use the sidebar to navigate between different threat detection modules.")

elif choice == "Network Threat Detection":
    st.header("Network Threat Detection")
    st.write("Paste your network CSV data below (with columns like bytes_sent, bytes_received, duration, port, protocol_type, service, flag).")
    csv_data = st.text_area("Network CSV Data", height=200)
    if st.button("Detect Network Threats"):
        if not csv_data.strip():
            st.error("Please enter network CSV data.")
        else:
            try:
                df = pd.read_csv(pd.compat.StringIO(csv_data))
                results = detector.detect_network_threats(df)
                if results:
                    st.success(f"Detected {results['num_anomalies']} anomalies out of {len(df)} records ({results['anomaly_percentage']:.2f}%).")
                    st.dataframe(pd.DataFrame({'Anomaly': results['anomalies'], 'Score': results['scores']}))
                else:
                    st.warning("No results returned. Ensure models are loaded and data is correct.")
            except Exception as e:
                st.error(f"Error processing network data: {e}")

elif choice == "Malware Detection":
    st.header("Malware Detection")
    uploaded_files = st.file_uploader("Upload executable files for malware detection", accept_multiple_files=True, type=['exe'])
    if st.button("Detect Malware"):
        if not uploaded_files:
            st.error("Please upload at least one executable file.")
        else:
            results = []
            for uploaded_file in uploaded_files:
                with open(os.path.join("temp_uploads", uploaded_file.name), "wb") as f:
                    f.write(uploaded_file.getbuffer())
                results.append(detector.detect_malware([os.path.join("temp_uploads", uploaded_file.name)])[0])
            for res in results:
                if 'error' in res:
                    st.error(f"File {res['file_path']}: {res['error']}")
                else:
                    status = "MALWARE" if res['is_malware'] else "BENIGN"
                    st.write(f"File {res['file_path']}: {status} (Confidence: {res['malware_probability']*100:.1f}%)")
            # Clean up temp files
            for uploaded_file in uploaded_files:
                try:
                    os.remove(os.path.join("temp_uploads", uploaded_file.name))
                except Exception:
                    pass

elif choice == "Phishing Detection":
    st.header("Phishing Detection")
    email_text = st.text_area("Enter email text for phishing detection", height=200)
    if st.button("Detect Phishing"):
        if not email_text.strip():
            st.error("Please enter email text.")
        else:
            results = detector.detect_phishing([email_text])
            if results:
                res = results[0]
                if 'error' in res:
                    st.error(f"Error: {res['error']}")
                else:
                    status = "PHISHING" if res['is_phishing'] else "LEGITIMATE"
                    st.write(f"Email is classified as: {status} (Confidence: {res['phishing_probability']*100:.1f}%)")
            else:
                st.warning("No results returned. Ensure models are loaded and input is correct.")

elif choice == "Dashboard":
    st.header("Dashboard")
    st.write("Dashboard functionality can be implemented here.")
