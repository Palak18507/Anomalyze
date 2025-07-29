import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from fpdf import FPDF
import tempfile
import os

# --- Page Setup ---
st.set_page_config(page_title="Shared IMEI Detection Report", layout="wide")
st.title("Shared IMEI Across Multiple MSISDNs Report")
st.markdown("""
Upload a single IPDR file (CSV or Excel). This analysis detects:
- **IMEIs (devices) used by multiple MSISDNs (SIMs) within a short window** (potential device sharing or SIM swapping)
""")

# --- Column normalization logic ---
IPDR_COLUMN_MAP = {
    "imei": ["imei"],
    "msisdn": ["msisdn", "subscriber_id", "calling_number", "user_number"],
    "flow_start_time": ["flow_start_time", "timestamp", "start_time", "date_time"]
}

def normalize_columns(df, column_map):
    col_rename = {}
    df_cols = {col.lower().replace(" ", "").replace("_", ""): col for col in df.columns}
    for std_col, variants in column_map.items():
        for variant in variants:
            key = variant.lower().replace(" ", "").replace("_", "")
            if key in df_cols:
                col_rename[df_cols[key]] = std_col
                break
    return df.rename(columns=col_rename)

def parse_ipdr(df):
    return normalize_columns(df, IPDR_COLUMN_MAP)

REQUIRED_COLUMNS = ["imei", "msisdn", "flow_start_time"]

def validate_input(df, required_columns=REQUIRED_COLUMNS):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def detect_shared_imeis(df, time_window_minutes=10, user_threshold=5):
    df = df.sort_values(['imei', 'flow_start_time'])
    df['flow_start_time'] = pd.to_datetime(df['flow_start_time'], errors='coerce')
    flagged_imeis = []
    for imei, group in df.groupby('imei'):
        group = group.sort_values('flow_start_time')
        times = group['flow_start_time'].tolist()
        msisdns = group['msisdn'].tolist()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(minutes=time_window_minutes)
            unique_msisdns = set()
            for j in range(i, len(times)):
                if pd.isnull(times[j]):
                    continue
                if times[j] <= window_end:
                    unique_msisdns.add(msisdns[j])
                else:
                    break
            if len(unique_msisdns) >= user_threshold:
                flagged_imeis.append({
                    'imei': imei,
                    'window_start': window_start,
                    'window_end': window_end,
                    'unique_msisdns_count': len(unique_msisdns),
                    'msisdns': ', '.join(list(unique_msisdns)[:10]) + ('...' if len(unique_msisdns) > 10 else '')
                })
                break
    alert_df = pd.DataFrame(flagged_imeis)
    return alert_df

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(alert_df, start, end):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Shared IMEI Across MSISDNs Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.cell(0, 10, f"Analysis Window: {start} to {end}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 11)
    headers = ["IMEI", "Start", "End", "MSISDN Count", "MSISDNs"]
    col_widths = [40, 35, 35, 25, 55]
    for h, w in zip(headers, col_widths):
        pdf.cell(w, 8, h, border=1)
    pdf.ln()
    pdf.set_font("Arial", size=10)
    for _, row in alert_df.head(30).iterrows():
        pdf.cell(col_widths[0], 8, str(row['imei']), border=1)
        pdf.cell(col_widths[1], 8, str(row['window_start'])[:19], border=1)
        pdf.cell(col_widths[2], 8, str(row['window_end'])[:19], border=1)
        pdf.cell(col_widths[3], 8, str(row['unique_msisdns_count']), border=1)
        pdf.cell(col_widths[4], 8, str(row['msisdns']), border=1)
        pdf.ln()
    pdf_path = tempfile.mktemp(suffix=".pdf")
    pdf.output(pdf_path)
    return pdf_path

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'alert_df' not in st.session_state:
    st.session_state['alert_df'] = pd.DataFrame()
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

# --- File Upload ---
uploaded_file = st.file_uploader("Upload IPDR file", type=["csv", "xlsx"])
time_window_minutes = st.number_input("Time window (minutes)", min_value=1, max_value=60, value=10)
user_threshold = st.number_input("User threshold (unique MSISDNs per window)", min_value=2, max_value=100, value=5)

if uploaded_file:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        df = parse_ipdr(df)
        df = validate_input(df)
        alert_df = detect_shared_imeis(df, time_window_minutes, user_threshold)
        st.session_state['df'] = df
        st.session_state['alert_df'] = alert_df
        st.session_state['analysis_done'] = True
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {start_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    alert_df = st.session_state['alert_df']
    if alert_df.empty:
        st.info("No suspicious IMEIs detected.")
    else:
        st.subheader("Shared IMEI Events")
        st.dataframe(alert_df)
        if st.button("Generate PDF Report"):
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            pdf_path = generate_pdf_report(alert_df, start_time, end_time)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="shared_imei_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single IPDR file to begin analysis.")