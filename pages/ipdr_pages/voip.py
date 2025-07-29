import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from fpdf import FPDF
import tempfile
import os

# --- Page Setup ---
st.set_page_config(page_title="Shared Destination IP Detection Report", layout="wide")
st.title("Shared Destination IP Detection Report")
st.markdown("""
Upload a single IPDR/VOIP file (CSV). This analysis detects:
- **Destination IPs accessed by many users within a short time window** (potential VOIP abuse or fraud)
""")

# --- Column normalization logic ---
IPDR_COLUMN_MAP = {
    "subscriber_id": ["subscriber_id", "msisdn", "user_number"],
    "user_id": ["user_id", "imei", "device_id"],
    "dest_ip": ["dest_ip", "destination_ip", "ip"],
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

REQUIRED_COLUMNS = ["subscriber_id", "user_id", "dest_ip", "flow_start_time"]

def validate_input(df, required_columns=REQUIRED_COLUMNS):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def detect_shared_ips(df, time_window_minutes=10, user_threshold=5):
    df = df.sort_values(['dest_ip', 'flow_start_time'])
    df['flow_start_time'] = pd.to_datetime(df['flow_start_time'], errors='coerce')
    flagged_ips = []
    for ip, group in df.groupby('dest_ip'):
        group = group.sort_values('flow_start_time')
        times = group['flow_start_time'].tolist()
        msisdns = group['subscriber_id'].tolist()
        imeis = group['user_id'].tolist()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(minutes=time_window_minutes)
            unique_msisdns = set()
            unique_imeis = set()
            for j in range(i, len(times)):
                if pd.isnull(times[j]):
                    continue
                if times[j] <= window_end:
                    unique_msisdns.add(msisdns[j])
                    unique_imeis.add(imeis[j])
                else:
                    break
            criteria = []
            if len(unique_msisdns) >= user_threshold:
                criteria.append("MSISDN")
            if len(unique_imeis) >= user_threshold:
                criteria.append("IMEI")
            if criteria:
                flagged_ips.append({
                    'destination_ip': ip,
                    'window_start': window_start,
                    'window_end': window_end,
                    'unique_msisdns_count': len(unique_msisdns),
                    'unique_imeis_count': len(unique_imeis),
                    'triggered_by': ", ".join(criteria)
                })
                break
    alert_df = pd.DataFrame(flagged_ips)
    return alert_df

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(alert_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Shared Destination IP Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 11)
    headers = ["Destination IP", "Start", "End", "MSISDN Count", "IMEI Count", "Triggered By"]
    col_widths = [33, 33, 33, 33, 33, 33]
    for h, w in zip(headers, col_widths):
        pdf.cell(w, 8, h, border=1)
    pdf.ln()
    pdf.set_font("Arial", size=10)
    for _, row in alert_df.head(30).iterrows():
        pdf.cell(col_widths[0], 8, str(row['destination_ip']), border=1)
        pdf.cell(col_widths[1], 8, str(row['window_start'])[:19], border=1)
        pdf.cell(col_widths[2], 8, str(row['window_end'])[:19], border=1)
        pdf.cell(col_widths[3], 8, str(row['unique_msisdns_count']), border=1)
        pdf.cell(col_widths[4], 8, str(row['unique_imeis_count']), border=1)
        pdf.cell(col_widths[5], 8, row['triggered_by'], border=1)
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
uploaded_file = st.file_uploader("Upload IPDR/VOIP CSV file", type=["csv"])
time_window_minutes = st.number_input("Time window (minutes)", min_value=1, max_value=60, value=10)
user_threshold = st.number_input("User threshold (unique users per window)", min_value=2, max_value=100, value=5)

if uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
        df = parse_ipdr(df)
        df = validate_input(df)
        alert_df = detect_shared_ips(df, time_window_minutes, user_threshold)
        st.session_state['df'] = df
        st.session_state['alert_df'] = alert_df
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    alert_df = st.session_state['alert_df']
    if alert_df.empty:
        st.info("No suspicious shared destination IPs detected.")
    else:
        st.subheader("Shared Destination IPs Detected")
        st.dataframe(alert_df)
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(alert_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="shared_ip_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single IPDR/VOIP file to begin analysis.")