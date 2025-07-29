import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Column Normalization Maps ---
CDR_COLUMN_MAP = {
    'calling_number': ['calling_number', 'caller', 'sim', 'sim_number'],
    'start_time': ['start_time', 'timestamp', 'time', 'date'],
    'end_time': ['end_time', 'finish_time', 'stop_time'],
    'session_id': ['session_id', 'session', 'call_id'],
}
FW_COLUMN_MAP = {
    'start_time': ['start_time', 'timestamp', 'time', 'date'],
    'end_time': ['end_time', 'finish_time', 'stop_time'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'session_id': ['session_id', 'session', 'fw_session'],
}
IPDR_COLUMN_MAP = {
    'subscriber_id': ['subscriber_id', 'subscriber', 'user_id'],
    'flow_start_time': ['flow_start_time', 'start_time', 'timestamp', 'time', 'date'],
    'flow_end_time': ['flow_end_time', 'end_time', 'finish_time', 'stop_time'],
    'session_id': ['session_id', 'session', 'ipdr_session'],
}

CDR_REQUIRED_COLUMNS = list(CDR_COLUMN_MAP.keys())
FW_REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())
IPDR_REQUIRED_COLUMNS = list(IPDR_COLUMN_MAP.keys())

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

def parse_cdr(df):
    return _normalize_columns(df, CDR_COLUMN_MAP)

def parse_firewall_log(df):
    return _normalize_columns(df, FW_COLUMN_MAP)

def parse_ipdr(df):
    return _normalize_columns(df, IPDR_COLUMN_MAP)

# --- Input Validation ---
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Helper: check if two time ranges overlap ---
def check_overlap(start1, end1, start2, end2):
    return start1 <= end2 and start2 <= end1

# --- Overlap Detection Logic ---
def detect_session_overlaps(cdr_df, fw_df, ipdr_df):
    cdr_df['start_time'] = pd.to_datetime(cdr_df['start_time'], errors='coerce')
    cdr_df['end_time'] = pd.to_datetime(cdr_df['end_time'], errors='coerce')
    fw_df['start_time'] = pd.to_datetime(fw_df['start_time'], errors='coerce')
    fw_df['end_time'] = pd.to_datetime(fw_df['end_time'], errors='coerce')
    ipdr_df['flow_start_time'] = pd.to_datetime(ipdr_df['flow_start_time'], errors='coerce')
    ipdr_df['flow_end_time'] = pd.to_datetime(ipdr_df['flow_end_time'], errors='coerce')

    results = []

    # CDR vs Firewall overlaps
    for _, cdr_row in cdr_df.iterrows():
        for _, fw_row in fw_df.iterrows():
            if check_overlap(cdr_row['start_time'], cdr_row['end_time'], fw_row['start_time'], fw_row['end_time']):
                results.append({
                    'Timestamp': f"{max(cdr_row['start_time'], fw_row['start_time'])} - {min(cdr_row['end_time'], fw_row['end_time'])}",
                    'CDR Activity': f"Session: {cdr_row['session_id']} | Number: {cdr_row['calling_number']}",
                    'IPDR Activity': "",
                    'Firewall Activity': f"Session: {fw_row['session_id']} | Src IP: {fw_row['src_ip']}",
                    'Overlap Evidence': 'CDR-Firewall overlap'
                })

    # CDR vs IPDR overlaps
    for _, cdr_row in cdr_df.iterrows():
        for _, ipdr_row in ipdr_df.iterrows():
            if check_overlap(cdr_row['start_time'], cdr_row['end_time'], ipdr_row['flow_start_time'], ipdr_row['flow_end_time']):
                results.append({
                    'Timestamp': f"{max(cdr_row['start_time'], ipdr_row['flow_start_time'])} - {min(cdr_row['end_time'], ipdr_row['flow_end_time'])}",
                    'CDR Activity': f"Session: {cdr_row['session_id']} | Number: {cdr_row['calling_number']}",
                    'IPDR Activity': f"Session: {ipdr_row['session_id']} | Subscriber: {ipdr_row['subscriber_id']}",
                    'Firewall Activity': "",
                    'Overlap Evidence': 'CDR-IPDR overlap'
                })

    # Firewall vs IPDR overlaps
    for _, fw_row in fw_df.iterrows():
        for _, ipdr_row in ipdr_df.iterrows():
            if check_overlap(fw_row['start_time'], fw_row['end_time'], ipdr_row['flow_start_time'], ipdr_row['flow_end_time']):
                results.append({
                    'Timestamp': f"{max(fw_row['start_time'], ipdr_row['flow_start_time'])} - {min(fw_row['end_time'], ipdr_row['flow_end_time'])}",
                    'CDR Activity': "",
                    'IPDR Activity': f"Session: {ipdr_row['session_id']} | Subscriber: {ipdr_row['subscriber_id']}",
                    'Firewall Activity': f"Session: {fw_row['session_id']} | Src IP: {fw_row['src_ip']}",
                    'Overlap Evidence': 'Firewall-IPDR overlap'
                })

    # CDR vs Firewall vs IPDR (triple overlap)
    for _, cdr_row in cdr_df.iterrows():
        for _, fw_row in fw_df.iterrows():
            if check_overlap(cdr_row['start_time'], cdr_row['end_time'], fw_row['start_time'], fw_row['end_time']):
                for _, ipdr_row in ipdr_df.iterrows():
                    latest_start = max(cdr_row['start_time'], fw_row['start_time'], ipdr_row['flow_start_time'])
                    earliest_end = min(cdr_row['end_time'], fw_row['end_time'], ipdr_row['flow_end_time'])
                    if latest_start <= earliest_end:
                        results.append({
                            'Timestamp': f"{latest_start} - {earliest_end}",
                            'CDR Activity': f"Session: {cdr_row['session_id']} | Number: {cdr_row['calling_number']}",
                            'IPDR Activity': f"Session: {ipdr_row['session_id']} | Subscriber: {ipdr_row['subscriber_id']}",
                            'Firewall Activity': f"Session: {fw_row['session_id']} | Src IP: {fw_row['src_ip']}",
                            'Overlap Evidence': 'CDR-Firewall-IPDR triple overlap'
                        })

    overlap_df = pd.DataFrame(results)
    return overlap_df

# --- Visualization: Session Comparison Chart ---
def plot_session_comparison(overlap_df):
    if overlap_df.empty:
        st.info("No data for session comparison chart.")
        return
    overlap_df['Start'] = overlap_df['Timestamp'].apply(lambda x: pd.to_datetime(x.split(' - ')[0]))
    overlap_df['Type'] = overlap_df['Overlap Evidence']
    trend = overlap_df.groupby([pd.Grouper(key='Start', freq='10T'), 'Type']).size().reset_index(name='Count')
    fig = px.line(trend, x='Start', y='Count', color='Type', markers=True, title='Session Overlap Comparison Across Logs')
    st.plotly_chart(fig, use_container_width=True)

# --- PDF Report Generation ---
def generate_pdf_report(overlap_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Session Overlap Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Detected Overlapping Sessions", ln=1)
    pdf.set_font("Arial", "", 9)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(40, 7, "Timestamp", border=1, fill=True)
    pdf.cell(40, 7, "CDR Activity", border=1, fill=True)
    pdf.cell(40, 7, "IPDR Activity", border=1, fill=True)
    pdf.cell(40, 7, "Firewall Activity", border=1, fill=True)
    pdf.cell(60, 7, "Overlap Evidence", border=1, fill=True)
    pdf.ln()
    for _, row in overlap_df.iterrows():
        pdf.cell(40, 7, str(row['Timestamp'])[:19], border=1)
        pdf.cell(40, 7, str(row['CDR Activity'])[:30], border=1)
        pdf.cell(40, 7, str(row['IPDR Activity'])[:30], border=1)
        pdf.cell(40, 7, str(row['Firewall Activity'])[:30], border=1)
        pdf.cell(60, 7, str(row['Overlap Evidence'])[:45], border=1)
        pdf.ln()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Session Overlap Detector", layout="wide")
st.title("Session Overlap Detector: CDR, Firewall, IPDR (Multi-File)")

st.markdown("""
This tool detects overlapping sessions across CDR, firewall, and IPDR logs.

**How to use:**
- Upload one or more CDR, firewall, and IPDR log CSV files.
- Click "Run Detection" to analyze and visualize overlapping sessions.
""")

if 'cdr_df' not in st.session_state:
    st.session_state['cdr_df'] = None
if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'ipdr_df' not in st.session_state:
    st.session_state['ipdr_df'] = None
if 'overlap_df' not in st.session_state:
    st.session_state['overlap_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

cdr_files = st.file_uploader(
    "Upload CDR CSV files", type=["csv"], accept_multiple_files=True
)
fw_files = st.file_uploader(
    "Upload Firewall Log CSV files", type=["csv"], accept_multiple_files=True
)
ipdr_files = st.file_uploader(
    "Upload IPDR CSV files", type=["csv"], accept_multiple_files=True
)
run_analysis = st.button("Run Detection")

if run_analysis and cdr_files and fw_files and ipdr_files:
    try:
        cdr_dfs = []
        for file in cdr_files:
            df = pd.read_csv(file)
            df = parse_cdr(df)
            df = validate_input(df, CDR_REQUIRED_COLUMNS, file.name)
            cdr_dfs.append(df)
        cdr_df = pd.concat(cdr_dfs, ignore_index=True)
        st.session_state['cdr_df'] = cdr_df

        fw_dfs = []
        for file in fw_files:
            df = pd.read_csv(file)
            df = parse_firewall_log(df)
            df = validate_input(df, FW_REQUIRED_COLUMNS, file.name)
            fw_dfs.append(df)
        fw_df = pd.concat(fw_dfs, ignore_index=True)
        st.session_state['fw_df'] = fw_df

        ipdr_dfs = []
        for file in ipdr_files:
            df = pd.read_csv(file)
            df = parse_ipdr(df)
            df = validate_input(df, IPDR_REQUIRED_COLUMNS, file.name)
            ipdr_dfs.append(df)
        ipdr_df = pd.concat(ipdr_dfs, ignore_index=True)
        st.session_state['ipdr_df'] = ipdr_df

        overlap_df = detect_session_overlaps(
            st.session_state['cdr_df'],
            st.session_state['fw_df'],
            st.session_state['ipdr_df']
        )
        st.session_state['overlap_df'] = overlap_df
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Session Overlap Analysis completed at {completion_time}")
        st.write("---")
    except Exception as e:
        st.error(f"Failed to process files: {e}")
        st.stop()

if st.session_state.get('overlap_df') is not None and st.session_state.get('analysis_done'):
    overlap_df = st.session_state['overlap_df']

    if not overlap_df.empty:
        st.error(f"Overlapping Sessions Detected! {overlap_df.shape[0]} events flagged.")
        st.markdown("### Overlapping Session Records")
        st.dataframe(overlap_df)

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Session Comparison Chart** | Shows flagged session overlaps over time, grouped by overlap type. |
""")

        st.subheader("Session Overlap Comparison Chart")
        plot_session_comparison(overlap_df)

        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(overlap_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="session_overlap_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass

    else:
        st.success("No overlapping sessions detected.")
else:
    st.info("Please upload CDR, firewall, and IPDR log files and click 'Run Detection' to begin analysis.")