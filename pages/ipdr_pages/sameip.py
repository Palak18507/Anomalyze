import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from fpdf import FPDF
import tempfile
import os

# --- Column Normalization Map ---
IPDR_COLUMN_MAP = {
    "subscriber_id": ["subscriber_id", "msisdn", "user_number"],
    "user_id": ["user_id", "imei", "device_id"],
    "dest_ip": ["dest_ip", "destination_ip", "ip"],
    "flow_start_time": ["flow_start_time", "timestamp", "start_time", "date_time"]
}

REQUIRED_COLUMNS = list(IPDR_COLUMN_MAP.keys())

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

def parse_ipdr(df):
    return _normalize_columns(df, IPDR_COLUMN_MAP)

# --- Input Validation ---
def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Job"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Shared Destination IP Detection Logic ---
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

# --- PDF Report Generation ---
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
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Shared Destination IP Detection", layout="wide")
st.title("Shared Destination IP Detection: Multi-File IPDR/VOIP Analysis")

st.markdown("""
This tool detects suspicious shared destination IPs by identifying IPs accessed by multiple unique MSISDNs or IMEIs within a short time window.

**How to use:**
- Upload one or more IPDR/VOIP CSV or Excel files.
- Click "Run Detection" to analyze and visualize results.
""")

if 'ipdr_df' not in st.session_state:
    st.session_state['ipdr_df'] = None
if 'alert_df' not in st.session_state:
    st.session_state['alert_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_files = st.file_uploader(
    "Upload one or more IPDR/VOIP CSV/Excel files", type=["csv", "xlsx"], accept_multiple_files=True
)
run_analysis = st.button("Run Detection")

if run_analysis and uploaded_files:
    try:
        all_data = pd.DataFrame()
        for uploaded_file in uploaded_files:
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)
            df = parse_ipdr(df)
            df = validate_input(df, REQUIRED_COLUMNS, uploaded_file.name)
            all_data = pd.concat([all_data, df], ignore_index=True)
        all_data['flow_start_time'] = pd.to_datetime(all_data['flow_start_time'], errors='coerce')
        st.session_state['ipdr_df'] = all_data
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process input files: {e}")
        st.stop()

    alert_df = detect_shared_ips(st.session_state['ipdr_df'])
    st.session_state['alert_df'] = alert_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('alert_df') is not None and st.session_state.get('analysis_done'):
    alert_df = st.session_state['alert_df']

    if alert_df.empty:
        st.info("No suspicious shared destination IPs detected.")
    else:
        st.markdown("### Shared Destination IPs Detected")
        st.dataframe(alert_df)

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Table** | Lists destination IPs accessed by multiple unique MSISDNs/IMEIs within a short time window. |
""")

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
    st.info("Please upload one or more IPDR/VOIP files and click 'Run Detection' to begin analysis.")