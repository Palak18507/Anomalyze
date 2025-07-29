import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import tempfile
import os

# --- Column Normalization Map ---
FW_COLUMN_MAP = {
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'dst_port': ['dst_port', 'destination_port', 'dport'],
    'action': ['action', 'activity'],
    'timestamp': ['timestamp', 'time', 'date'],
}
REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())

SERVER_PORTS = {80, 443, 22, 25, 3389, 3306}  # HTTP, HTTPS, SSH, SMTP, RDP, MySQL

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
def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Main Logic Function ---
def flag_non_server_traffic(df, server_ips):
    def is_non_server_traffic(row):
        dst_ip = row['dst_ip']
        dst_port = row['dst_port']
        action = str(row['action']).lower()
        try:
            port = int(dst_port)
        except Exception:
            return False
        if dst_ip not in server_ips and port in SERVER_PORTS and action in ('allow', 'accepted'):
            return True
        return False
    df['NonServerTrafficFlag'] = df.apply(is_non_server_traffic, axis=1)
    return df

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Non-Server Traffic Detection", layout="wide")
st.title("Non-Server Traffic Detection: Firewall Log Analysis")

st.markdown("""
This tool detects non-server traffic by flagging connections to server ports (e.g., HTTP, HTTPS, SSH, SMTP, RDP, MySQL) that are not destined for known server IPs.

**How to use:**
- Upload a firewall log CSV file.
- Enter a comma-separated list of known server IPs.
- Click "Run Detection" to analyze and visualize results.
""")

if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'result_df' not in st.session_state:
    st.session_state['result_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_file = st.file_uploader("Upload Firewall Log CSV", type=['csv'])
server_ips_input = st.text_input("Known Server IPs (comma-separated)", value="192.168.1.10,192.168.1.20")
run_analysis = st.button("Run Detection")

if run_analysis and uploaded_file:
    try:
        df = pd.read_csv(uploaded_file)
        df = parse_firewall_log(df)
        df = validate_input(df, REQUIRED_COLUMNS, uploaded_file.name)
        server_ips = set(ip.strip() for ip in server_ips_input.split(",") if ip.strip())
        result_df = flag_non_server_traffic(df, server_ips)
        st.session_state['fw_df'] = df
        st.session_state['result_df'] = result_df
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Non-Server Traffic Analysis completed at {completion_time}")
        st.write("---")
    except Exception as e:
        st.error(f"Failed to process firewall log: {e}")
        st.stop()

if st.session_state.get('result_df') is not None and st.session_state.get('analysis_done'):
    result_df = st.session_state['result_df']

    st.markdown("### Result Preview")
    st.dataframe(result_df.head())

    # --- Pie Chart: Server vs Non-Server Traffic ---
    server_traffic_count = len(result_df) - result_df['NonServerTrafficFlag'].sum()
    non_server_traffic_count = result_df['NonServerTrafficFlag'].sum()
    pie_df = pd.DataFrame({
        'Traffic Type': ['Server Traffic', 'Non-Server Traffic'],
        'Count': [server_traffic_count, non_server_traffic_count]
    })
    fig = px.pie(
        pie_df,
        names='Traffic Type',
        values='Count',
        color='Traffic Type',
        color_discrete_map={'Server Traffic': '#CCCCFF', 'Non-Server Traffic': '#D5FFFF'},
        title="Server vs Non-Server Traffic"
    )
    st.plotly_chart(fig, use_container_width=True)

    # --- CSV Export ---
    csv_path = generate_csv_report(result_df)
    with open(csv_path, "rb") as f:
        st.download_button(
            label="Download CSV Report",
            data=f.read(),
            file_name="non_server_traffic_report.csv",
            mime="text/csv"
        )
    try:
        os.remove(csv_path)
    except Exception:
        pass

    st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Pie Chart: Server vs Non-Server Traffic** | Shows the proportion of flagged non-server traffic vs. expected server traffic. |
| **Result Table** | Preview of the analyzed firewall log with non-server traffic flags. |
""")

else:
    st.info("Please upload a firewall log file and click 'Run Detection' to begin analysis.")