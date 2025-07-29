import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime
from fpdf import FPDF
import tempfile
import plotly.express as px
import os

# --- Column Normalization Map ---
FW_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'bytes_sent': ['bytes_sent', 'bytes', 'sent_bytes', 'data_sent'],
    'bytes_received': ['bytes_received', 'received_bytes', 'data_received'],
    'action': ['action', 'activity'],
    'country': ['country', 'geo_country'],
}

REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())

# --- Column Normalization ---
def _normalize_columns(df, column_map):
    col_rename = {}
    df_cols = {col.lower().replace(" ", "").replace("_", ""): col for col in df.columns}
    for std_col, variants in column_map.items():
        for variant in variants:
            key = variant.lower().replace(" ", "").replace("_", "")
            if key in df_cols:
                col_rename[df_cols[key]] = std_col
                break
    return df.rename(columns=col_rename)

def parse_firewall_log(df):
    return _normalize_columns(df, FW_COLUMN_MAP)

# --- Input Validation ---
def validate_input(uploaded_file, required_columns=None, file_type="csv", job_name="Firewall Log"):
    if uploaded_file is None:
        st.error(f"Please upload a file for {job_name}.")
        st.stop()
    try:
        df = pd.read_csv(uploaded_file)
        df = parse_firewall_log(df)
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()
    if required_columns:
        missing = [col for col in required_columns if col not in df.columns]
        if missing:
            st.error(f"Missing required columns: {missing}")
            st.stop()
    return df

# --- Load Models and Resources ---
@st.cache_resource
def load_resources():
    base_dir = os.path.dirname(__file__)
    model = joblib.load(os.path.join(base_dir, 'dns_tunneling_rf_model.pkl'))
    scaler = joblib.load(os.path.join(base_dir, 'dns_scaler.pkl'))
    le = joblib.load(os.path.join(base_dir, 'country_label_encoder.pkl'))

    with open(os.path.join(base_dir, 'feature_cols.json')) as f:
        feature_cols = json.load(f)
    with open(os.path.join(base_dir, 'whitelist.json')) as f:
        whitelist = json.load(f)
    with open(os.path.join(base_dir, 'expected_countries.json')) as f:
        expected_countries = json.load(f)
    return model, scaler, le, feature_cols, whitelist, expected_countries

# --- Text Cleanup ---
def clean_text(text):
    if not isinstance(text, str):
        text = str(text)
    text = text.replace('\u2013', '-').replace('\u2014', '-').replace('\u2192', '->')
    return text.encode('latin-1', 'replace').decode('latin-1')

# --- PDF Report Generation ---
def generate_pdf_report(events_df, sample_df, analysis_text):
    path = tempfile.mktemp(suffix=".pdf")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, clean_text("DNS Tunneling Detection Report"), ln=1, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, clean_text(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"), ln=1)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, clean_text("Detection Analysis"), ln=1)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 8, clean_text(analysis_text))
    pdf.ln(3)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, clean_text("Detected Tunneling Events (first 10)"), ln=1)
    pdf.set_font("Arial", size=8)
    if not events_df.empty:
        for _, row in events_df.head(10).iterrows():
            row_str = ", ".join([clean_text(str(row[col])) for col in events_df.columns])
            pdf.cell(0, 7, clean_text(row_str), ln=1)
    else:
        pdf.cell(0, 8, clean_text("No tunneling events detected."), ln=1)
    pdf.ln(3)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, clean_text("Packet Samples (first 10)"), ln=1)
    pdf.set_font("Arial", size=8)
    if not sample_df.empty:
        for _, row in sample_df.head(10).iterrows():
            row_str = ", ".join([clean_text(str(row[col])) for col in sample_df.columns])
            pdf.cell(0, 7, clean_text(row_str), ln=1)
    else:
        pdf.cell(0, 8, clean_text("No packet samples available."), ln=1)

    pdf.output(path)
    return path

# --- Streamlit UI ---
st.set_page_config(page_title="DNS Tunneling Detection", layout="wide")
st.title("DNS Tunneling Detection: Firewall Log Analysis")

st.markdown("""
This tool detects suspicious DNS tunneling activity using a trained machine learning model and firewall logs.

**How to use:**
- Upload a firewall log CSV file.
- The app will analyze the data, flag suspicious DNS tunneling, and provide visualizations and a PDF report.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'tunneling_events' not in st.session_state:
    st.session_state['tunneling_events'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

model, scaler, le, feature_cols, whitelist, expected_countries = load_resources()

uploaded_file = st.file_uploader("Upload Firewall Log (.csv)", type="csv")
run_analysis = st.button("Run Detection")

if run_analysis and uploaded_file:
    try:
        df = validate_input(uploaded_file, required_columns=REQUIRED_COLUMNS, job_name="Firewall Log")
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.drop_duplicates()
        df = df.sort_values(['src_ip', 'timestamp']).reset_index(drop=True)

        df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_received'] + 1)
        df['unique_dst_ip_per_src_ip'] = df.groupby('src_ip')['dst_ip'].transform('nunique')
        df['allow_count'] = df.groupby('src_ip')['action'].transform(lambda x: (x == 'ALLOW').sum())
        df['block_count'] = df.groupby('src_ip')['action'].transform(lambda x: (x == 'BLOCK').sum())
        df['dst_ip_in_whitelist'] = df['dst_ip'].isin(whitelist).astype(int)
        df['dst_ip_unexpected_country'] = ~df['country'].isin(expected_countries)

        def get_as(ip):
            return ip.split('.')[0]
        if 'query_name' in df.columns:
            df['unique_dst_ip_per_query_1d'] = df.groupby('query_name')['dst_ip'].transform('nunique')
            df['unique_as_per_query_1d'] = df.groupby('query_name')['dst_ip'].transform(
                lambda ips: len(set(get_as(ip) for ip in ips))
            )

        df['country'] = df['country'].apply(lambda x: x if x in le.classes_ else 'Unknown')
        df['country_enc'] = le.transform(df['country'])

        for col in feature_cols:
            if col not in df.columns:
                df[col] = 0

        X_new = df[feature_cols]
        X_new_scaled = scaler.transform(X_new)
        predictions = model.predict(X_new_scaled)
        risk_scores = model.predict_proba(X_new_scaled)[:, 1]

        df['prediction'] = predictions
        df['risk_score'] = (risk_scores * 100).round(1)
        df['explanation'] = df.apply(
            lambda row: (
                "Suspicious DNS tunneling detected. "
                f"Risk Score: {row['risk_score']}%. "
                "This connection shows patterns typical of DNS tunneling attacks."
                if row['prediction'] == 1 else
                "Normal DNS activity detected."
            ),
            axis=1
        )

        tunneling_events = df[df['prediction'] == 1][
            ['timestamp', 'src_ip', 'dst_ip', 'bytes_sent', 'bytes_received', 'country', 'risk_score', 'explanation']
        ]

        st.session_state['df'] = df
        st.session_state['tunneling_events'] = tunneling_events
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"DNS Tunneling Detection completed at {completion_time}")
        st.write("---")
    except Exception as e:
        st.error(f"Failed to process file: {e}")
        st.stop()

if st.session_state.get('tunneling_events') is not None and st.session_state.get('analysis_done'):
    tunneling_events = st.session_state['tunneling_events']
    df = st.session_state['df']

    st.subheader("Detection Results")
    if not tunneling_events.empty:
        st.warning("DNS tunneling events detected.")
        st.dataframe(tunneling_events, use_container_width=True)

        st.subheader("Trend: DNS Tunneling Events Over Time")
        tunneling_events['date'] = tunneling_events['timestamp'].dt.date
        trend = tunneling_events.groupby('date').size().reset_index(name='detections')
        fig = px.line(trend, x='date', y='detections', title="DNS Tunneling Detections Over Time")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Packet Samples (first 10 events)")
        st.dataframe(tunneling_events.head(10), use_container_width=True)
    else:
        st.success("No DNS tunneling detected in this log.")

    with st.expander("View Full Processed Data"):
        st.dataframe(df[['timestamp', 'src_ip', 'dst_ip', 'risk_score', 'explanation']], use_container_width=True)

    st.header("Generate PDF Report")
    if st.button("Generate PDF Report"):
        analysis_text = (
            f"Total events processed: {len(df)}\n"
            f"DNS tunneling events detected: {len(tunneling_events)}\n"
            "Risk scores represent the model's confidence in tunneling behavior."
        )
        pdf_path = generate_pdf_report(
            tunneling_events,
            tunneling_events,
            analysis_text
        )
        with open(pdf_path, "rb") as f:
            st.download_button("Download PDF Report", f, file_name="dns_tunneling_report.pdf", mime="application/pdf")
        try:
            os.remove(pdf_path)
        except Exception:
            pass

else:
    st.info("Upload a CSV file and click 'Run Detection' to begin analysis.")
