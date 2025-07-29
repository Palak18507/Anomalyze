import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Column Normalization Map ---
FW_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'src_port': ['src_port', 'source_port', 'sport'],
    'dst_port': ['dst_port', 'destination_port', 'dport'],
    'protocol': ['protocol', 'proto'],
    'action': ['action', 'activity'],
    'rule_name': ['rule_name', 'rule', 'policy'],
    'session_id': ['session_id', 'session', 'fw_session'],
    'bytes': ['bytes', 'bytes_sent', 'sent_bytes', 'data_sent'],
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
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Shared Source IP Detection Logic ---
def detect_shared_src_ip(all_fw_df):
    session_counts = all_fw_df.groupby('src_ip')['session_id'].nunique().reset_index()
    marked_src_ips = session_counts[session_counts['session_id'] > 1]['src_ip']
    marked_logs = all_fw_df[all_fw_df['src_ip'].isin(marked_src_ips)]
    return marked_logs

# --- Visualization ---
def plot_marked_src_ips(result_df):
    if result_df.empty:
        st.info("No data for visualization.")
        return
    fig = px.histogram(
        result_df,
        x="src_ip",
        color="action",
        barmode="group",
        title="Occurrences of Marked Source IPs (Possible Shared Credentials/Lateral Movement)"
    )
    fig.update_layout(xaxis_title="Source IP", yaxis_title="Event Count")
    st.plotly_chart(fig, use_container_width=True)

# --- PDF Report Generation ---
def generate_pdf_report(result_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Shared Source IP Detection Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Marked Source IPs (Multiple Sessions Detected)", ln=1)
    pdf.set_font("Arial", "", 9)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(32, 7, "Timestamp", border=1, fill=True)
    pdf.cell(28, 7, "Src IP", border=1, fill=True)
    pdf.cell(28, 7, "Dest IP", border=1, fill=True)
    pdf.cell(15, 7, "S.Port", border=1, fill=True)
    pdf.cell(15, 7, "D.Port", border=1, fill=True)
    pdf.cell(13, 7, "Proto", border=1, fill=True)
    pdf.cell(15, 7, "Action", border=1, fill=True)
    pdf.cell(20, 7, "Rule", border=1, fill=True)
    pdf.cell(13, 7, "Bytes", border=1, fill=True)
    pdf.cell(18, 7, "Session ID", border=1, fill=True)
    pdf.ln()
    for _, row in result_df.iterrows():
        pdf.cell(32, 7, str(row.get('timestamp', ''))[:19], border=1)
        pdf.cell(28, 7, str(row.get('src_ip', '')), border=1)
        pdf.cell(28, 7, str(row.get('dst_ip', '')), border=1)
        pdf.cell(15, 7, str(row.get('src_port', '')), border=1)
        pdf.cell(15, 7, str(row.get('dst_port', '')), border=1)
        pdf.cell(13, 7, str(row.get('protocol', '')), border=1)
        pdf.cell(15, 7, str(row.get('action', '')), border=1)
        pdf.cell(20, 7, str(row.get('rule_name', ''))[:10], border=1)
        pdf.cell(13, 7, str(row.get('bytes', '')), border=1)
        pdf.cell(18, 7, str(row.get('session_id', '')), border=1)
        pdf.ln()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Shared Source IP Detection Forensic Tool", layout="wide")
st.title("Shared Source IP Detection Forensic Tool: Multi-File Firewall Log Analysis")

st.markdown("""
This tool detects possible lateral movement or shared credentials by identifying source IPs associated with multiple sessions across firewall logs.

**How to use:**
- Upload two or more firewall log CSV files.
- Click "Run Detection" to analyze and visualize results.
""")

if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'result_df' not in st.session_state:
    st.session_state['result_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_files = st.file_uploader(
    "Upload two or more Firewall Log CSV files", type=["csv"], accept_multiple_files=True
)
run_analysis = st.button("Run Detection")

if run_analysis and uploaded_files and len(uploaded_files) >= 2:
    try:
        all_fw_df = pd.DataFrame()
        for uploaded_file in uploaded_files:
            df = pd.read_csv(uploaded_file)
            df = parse_firewall_log(df)
            df = validate_input(df, REQUIRED_COLUMNS, uploaded_file.name)
            all_fw_df = pd.concat([all_fw_df, df], ignore_index=True)
        st.session_state['fw_df'] = all_fw_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process firewall log files: {e}")
        st.stop()

    result_df = detect_shared_src_ip(st.session_state['fw_df'])
    st.session_state['result_df'] = result_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Shared Source IP Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('result_df') is not None and st.session_state.get('analysis_done'):
    result_df = st.session_state['result_df']

    if not result_df.empty:
        st.error(f"Possible Lateral Movement/Shared Credentials Detected! {result_df['src_ip'].nunique()} source IPs affected.")
        st.markdown("### Marked Source IP Records (Multiple Sessions Detected)")
        st.dataframe(result_df)

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Event Distribution** | Shows the distribution of marked source IPs by action type. |
""")

        st.subheader("Marked Source IPs Event Distribution")
        plot_marked_src_ips(result_df)

        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(result_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="shared_src_ip_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass

    else:
        st.success("No shared source IPs detected (no evidence of lateral movement or shared credentials).")
else:
    st.info("Please upload at least two firewall log files and click 'Run Detection' to begin analysis.")