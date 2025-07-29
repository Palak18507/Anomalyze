import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import tempfile
import os

# --- Column Normalization Map ---
FIREWALL_COLUMN_MAP = {
    "timestamp": ["receive time", "generated time", "starttime", "timestamp"],
    "src_ip": ["source address", "srcip", "src_ip"],
    "dst_ip": ["destination address", "dstip", "dst_ip"],
    "src_port": ["source port", "srcport", "src_port"],
    "dst_port": ["destination port", "dstport", "dst_port"],
    "protocol": ["protocol", "ip protocol"],
    "action": ["action"],
    "application": ["application", "app"],
    "bytes_sent": ["bytes sent", "outbytes", "bytes_sent", "bytes"],
    "bytes_received": ["bytes received", "inbytes", "bytes_received"],
    "bytes": ["bytes", "outbytes"],
    "duration": ["duration"],
    "user_id": ["userid", "user_id"],
    "device_id": ["deviceid", "device_id"],
    "country": ["country"],
    "session_id": ["session id", "sessionid", "session_id"],
    "threat_type": ["threattype", "threat_type"],
    "rule_name": ["rule name", "rule_name"],
    "src_mac": [
        "source mac", "srcmac", "src_mac", "source mac address", "mac address",
        "client mac", "hardware address", "source hw address"
    ],
}

REQUIRED_COLUMNS = ["timestamp", "src_ip", "dst_ip", "dst_port"]

DEFAULT_FLAGGED_IPS = set([
    "185.220.101.1", "104.244.77.2",
])
TOR_PORTS = {9001, 9030, 9050, 443}

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
    return _normalize_columns(df, FIREWALL_COLUMN_MAP)

# --- Utility Functions ---
def load_flagged_ips(file_obj):
    ips = set()
    file_obj.seek(0)
    for line in file_obj:
        try:
            line = line.decode("utf-8").strip()
        except AttributeError:
            line = line.strip()
        if line:
            ips.add(line)
    return ips

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

def analyze_logs(df, flagged_ips, tor_ports):
    findings = []
    for _, entry in df.iterrows():
        src_ip = entry.get("src_ip")
        dst_ip = entry.get("dst_ip")
        try:
            dst_port = int(entry.get("dst_port", 0))
        except Exception:
            dst_port = 0
        timestamp = entry.get("timestamp")
        match_flagged_ip = dst_ip in flagged_ips
        match_tor_port = dst_port in tor_ports
        if match_flagged_ip or match_tor_port:
            findings.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "flagged_ip": match_flagged_ip,
                "tor_port": match_tor_port,
            })
    return pd.DataFrame(findings)

def generate_csv_report(findings_df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    findings_df.to_csv(tmp_file.name, index=False)
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

def plot_heatmap_by_hour(findings_df):
    if findings_df.empty or "timestamp" not in findings_df.columns:
        st.info("No timestamp data for heatmap.")
        return
    df = findings_df.copy()
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['hour'] = df['timestamp'].dt.hour
    hour_counts = df.groupby('hour').size().reindex(range(24), fill_value=0)
    heatmap_df = pd.DataFrame({'hour': range(24), 'count': hour_counts.values})
    fig = px.density_heatmap(
        heatmap_df,
        x='hour',
        y=['Incidents'] * 24,
        z='count',
        color_continuous_scale='YlOrRd',
        title='Heatmap of Suspicious Accesses by Hour'
    )
    st.plotly_chart(fig, use_container_width=True)

def correlate_findings(findings_df):
    from collections import defaultdict
    correlation = defaultdict(list)
    for _, inc in findings_df.iterrows():
        correlation[inc["src_ip"]].append(inc)
    return [
        {
            "src_ip": ip,
            "num_events": len(incs),
            "flagged_ip_events": sum(inc["flagged_ip"] for inc in incs),
            "tor_port_events": sum(inc["tor_port"] for inc in incs)
        }
        for ip, incs in correlation.items() if len(incs) > 1
    ]

# --- Streamlit UI with Session State Preservation ---
st.set_page_config(page_title="Dark Web Access Detector", layout="wide")
st.title("Dark Web Access Detector: Firewall Log Analysis")

st.markdown("""
This tool detects suspicious access to flagged IPs and TOR ports from firewall logs.

**How to use:**
- Upload one or more firewall log CSV files.
- Optionally upload a custom flagged IPs list (one IP per line).
- Click "Run Analysis" to see results and download reports.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'findings_df' not in st.session_state:
    st.session_state['findings_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_files = st.file_uploader("Upload Firewall Log CSV files", type=["csv"], accept_multiple_files=True)
flagged_ips_file = st.file_uploader("Upload custom flagged IPs file (optional, .txt, one IP per line)")

run_analysis = st.button("Run Analysis")

if run_analysis and uploaded_files:
    try:
        dfs = []
        for file in uploaded_files:
            df = pd.read_csv(file)
            df = parse_firewall_log(df)
            df = validate_input(df, REQUIRED_COLUMNS, file.name)
            dfs.append(df)
        combined_df = pd.concat(dfs, ignore_index=True)
        st.session_state['df'] = combined_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to read log files: {e}")
        st.stop()

    flagged_ips = DEFAULT_FLAGGED_IPS
    if flagged_ips_file is not None:
        try:
            flagged_ips = load_flagged_ips(flagged_ips_file)
        except Exception as e:
            st.error(f"Failed to load flagged IPs: {e}")
            st.stop()

    findings_df = analyze_logs(st.session_state['df'], flagged_ips, TOR_PORTS)
    st.session_state['findings_df'] = findings_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('findings_df') is not None and st.session_state.get('analysis_done'):
    findings_df = st.session_state['findings_df']

    if findings_df.empty:
        st.info("No suspicious access detected.")
    else:
        st.markdown("### 🚩 Suspicious Accesses")
        st.dataframe(findings_df)

        st.warning(f"Total suspicious events: {len(findings_df)}")

        # --- CSV Export ---
        csv_path = generate_csv_report(findings_df)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f.read(),
                file_name="dark_web_access_report.csv",
                mime="text/csv"
            )
        try:
            os.remove(csv_path)
        except Exception:
            pass

        # --- Visualizations Overview ---
        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Incident Counts by Source IP** | Shows which source IPs are most frequently involved in suspicious access. |
| **Incident Counts by Destination IP** | Highlights which destination IPs are most often contacted. |
| **Incident Counts by Destination Port** | Reveals which ports are most commonly used in detected events. |
| **Heatmap of Suspicious Accesses by Hour** | Displays the distribution of events across each hour of the day. |
| **Correlated Events Table** | Lists source IPs involved in multiple suspicious events. |
""")

        # --- Bar Chart: Source IPs ---
        st.subheader("Bar Chart: Incident Counts by Source IP")
        src_ip_counts = findings_df["src_ip"].value_counts().reset_index().rename(
            columns={"index": "src_ip", "src_ip": "count"}
        )
        plot_bar(src_ip_counts, "src_ip", "count", "Incident Counts by Source IP", "Source IP", "Number of Events", "orchid")

        # --- Bar Chart: Destination IPs ---
        st.subheader("Bar Chart: Incident Counts by Destination IP")
        dst_ip_counts = findings_df["dst_ip"].value_counts().reset_index().rename(
            columns={"index": "dst_ip", "dst_ip": "count"}
        )
        plot_bar(dst_ip_counts, "dst_ip", "count", "Incident Counts by Destination IP", "Destination IP", "Number of Events", "skyblue")

        # --- Bar Chart: Destination Ports ---
        st.subheader("Bar Chart: Incident Counts by Destination Port")
        dst_port_counts = findings_df["dst_port"].value_counts().reset_index().rename(
            columns={"index": "dst_port", "dst_port": "count"}
        )
        plot_bar(dst_port_counts, "dst_port", "count", "Incident Counts by Destination Port", "Destination Port", "Number of Events", "salmon")

        # --- Heatmap by Hour ---
        st.subheader("Heatmap: Suspicious Accesses by Hour")
        plot_heatmap_by_hour(findings_df)

        # --- Correlated Events ---
        st.subheader("Correlated Events (Source IPs with Multiple Events)")
        correlated = correlate_findings(findings_df)
        if correlated:
            correlated_df = pd.DataFrame(correlated)
            st.markdown("""
| Source IP | Number of Events | Flagged IP Events | TOR Port Events |
|-----------|-----------------|-------------------|-----------------|
""" + "\n".join(
    f"| {row['src_ip']} | {row['num_events']} | {row['flagged_ip_events']} | {row['tor_port_events']} |"
    for _, row in correlated_df.iterrows()
))
        else:
            st.info("No correlated events found.")

else:
    st.info("Please upload log files and click 'Run Analysis' to begin.")