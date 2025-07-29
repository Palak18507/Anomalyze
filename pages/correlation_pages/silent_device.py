import streamlit as st
import pandas as pd
import plotly.express as px
import tempfile
import os
from datetime import datetime

# --- Column Normalization Maps ---
IPDR_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
}
FW_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
}
CDR_COLUMN_MAP = {
    "calling_number": ["calling_number", "caller", "number"],
}

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

def parse_firewall_log(df):
    return _normalize_columns(df, FW_COLUMN_MAP)

def parse_cdr(df):
    return _normalize_columns(df, CDR_COLUMN_MAP)

# --- Input Validation ---
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Silent Device Detection Logic ---
class SilentDeviceDetector:
    def __init__(self, ipdr_df, firewall_df, cdr_df=None, ip_col='src_ip', threshold=100):
        self.ipdr_df = ipdr_df
        self.firewall_df = firewall_df
        self.cdr_df = cdr_df
        self.ip_col = ip_col
        self.threshold = threshold

    def detect(self):
        ipdr_counts = self.ipdr_df[self.ip_col].value_counts()
        fw_counts = self.firewall_df[self.ip_col].value_counts()
        total_counts = ipdr_counts.add(fw_counts, fill_value=0)
        if self.cdr_df is not None:
            cdr_ips = set(self.cdr_df['calling_number'])
            total_counts = total_counts[~total_counts.index.isin(cdr_ips)]
        suspicious = total_counts[total_counts < self.threshold].reset_index()
        suspicious.columns = ['ip', 'event_count']
        return suspicious, total_counts

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

def plot_bar(data, x, y, title, xlabel, ylabel, color):
    if data is None or (hasattr(data, "empty") and data.empty):
        st.info("No data for visualization.")
        return
    df = pd.DataFrame(data)
    fig = px.bar(
        df,
        x=x,
        y=y,
        color_discrete_sequence=[color],
        labels={x: xlabel, y: ylabel},
        title=title
    )
    st.plotly_chart(fig, use_container_width=True)

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Silent Device Detector", layout="wide")
st.title("Silent Device Detector: IPDR, Firewall, and CDR Log Analysis")

st.markdown("""
This tool detects silent devices (with low event counts) by correlating IPDR and firewall logs, optionally excluding devices seen in CDR logs.

**How to use:**
- Upload IPDR and firewall log CSV files.
- Optionally upload a CDR log CSV file.
- Adjust the event count threshold in the sidebar.
- Click "Run Detection" to analyze and visualize results.
""")

if 'ipdr_df' not in st.session_state:
    st.session_state['ipdr_df'] = None
if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'cdr_df' not in st.session_state:
    st.session_state['cdr_df'] = None
if 'suspicious_df' not in st.session_state:
    st.session_state['suspicious_df'] = None
if 'total_counts' not in st.session_state:
    st.session_state['total_counts'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

ipdr_file = st.file_uploader("Upload IPDR Log (CSV)", type=["csv"])
firewall_file = st.file_uploader("Upload Firewall Log (CSV)", type=["csv"])
cdr_file = st.file_uploader("Upload CDR Log (CSV, optional)", type=["csv"])
st.sidebar.header("Detection Parameters")
threshold = st.sidebar.number_input("Event Count Threshold", min_value=1, value=100)
run_analysis = st.button("Run Detection")

if run_analysis and ipdr_file and firewall_file:
    try:
        ipdr_df = pd.read_csv(ipdr_file)
        ipdr_df = parse_ipdr(ipdr_df)
        ipdr_df = validate_input(ipdr_df, ["src_ip"], "IPDR Log")
        fw_df = pd.read_csv(firewall_file)
        fw_df = parse_firewall_log(fw_df)
        fw_df = validate_input(fw_df, ["src_ip"], "Firewall Log")
        cdr_df = None
        if cdr_file is not None:
            cdr_df = pd.read_csv(cdr_file)
            cdr_df = parse_cdr(cdr_df)
            cdr_df = validate_input(cdr_df, ["calling_number"], "CDR Log")
        detector = SilentDeviceDetector(
            ipdr_df=ipdr_df,
            firewall_df=fw_df,
            cdr_df=cdr_df,
            ip_col='src_ip',
            threshold=threshold
        )
        suspicious, total_counts = detector.detect()
        st.session_state['ipdr_df'] = ipdr_df
        st.session_state['fw_df'] = fw_df
        st.session_state['cdr_df'] = cdr_df
        st.session_state['suspicious_df'] = suspicious
        st.session_state['total_counts'] = total_counts
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("---")
    except Exception as e:
        st.error(f"Failed to process files: {e}")
        st.stop()

if st.session_state.get('suspicious_df') is not None and st.session_state.get('analysis_done'):
    suspicious = st.session_state['suspicious_df']
    total_counts = st.session_state['total_counts']

    if not suspicious.empty:
        st.warning(f"ALERT: {len(suspicious)} suspicious silent device(s) detected!")
        st.dataframe(suspicious)
    else:
        st.info("No suspicious silent devices detected.")

    st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Top 20 IPs by Combined Event Count** | Shows which IPs have the most combined events in IPDR and firewall logs. |
""")

    st.subheader("Top 20 IPs by Combined Event Count")
    usage_df = total_counts.reset_index()
    usage_df.columns = ['ip', 'event_count']
    usage_df = usage_df.sort_values('event_count', ascending=False).head(20)
    plot_bar(usage_df, "ip", "event_count", "Top 20 IPs by Combined Event Count", "IP Address", "Combined Event Count", "steelblue")

    # --- CSV Export ---
    csv_path = generate_csv_report(suspicious)
    with open(csv_path, "rb") as f:
        st.download_button(
            label="Download CSV Report",
            data=f.read(),
            file_name="silent_device_report.csv",
            mime="text/csv"
        )
    try:
        os.remove(csv_path)
    except Exception:
        pass

else:
    st.info("Please upload IPDR and firewall log files and click 'Run Detection' to begin analysis.")