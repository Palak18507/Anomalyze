import streamlit as st
import pandas as pd
import plotly.express as px
import json
import tempfile
import os
from collections import Counter, defaultdict
from datetime import datetime

# --- Column Normalization Map ---
LOG_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
    "dest_ip": ["dest_ip", "destination_ip", "dest", "destination"],
    "dest_port": ["dest_port", "destination_port", "port"],
    "protocol": ["protocol", "proto", "application_protocol"],
    "action": ["action", "activity"],
    "application": ["application", "app", "service"],
    "reason": ["reason", "block_reason", "deny_reason"],
    "timestamp": ["timestamp", "time", "date"]
}
REQUIRED_COLUMNS = ["src_ip", "dest_ip", "dest_port", "protocol", "action", "timestamp"]

# --- WebRTC/SIP Protocol Definitions ---
WEBRTC_PORTS = {3478, 3479, 5349, 19302}
SIP_PORTS = {5060, 5061, 5062, 5064, 5070, 5080, 5090}
WEBRTC_KEYWORDS = ["webrtc", "stun", "turn", "ice"]
SIP_KEYWORDS = ["sip", "session initiation", "voip"]

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

def parse_log(df):
    return _normalize_columns(df, LOG_COLUMN_MAP)

# --- Input Validation ---
def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Detection Logic ---
def detect_webrtc_sip_and_blocks(df):
    incidents = []
    for _, entry in df.iterrows():
        src_ip = entry.get("src_ip")
        dest_ip = entry.get("dest_ip", "")
        dest_port = entry.get("dest_port", "")
        protocol = str(entry.get("protocol", "")).lower()
        app_field = str(entry.get("application", "")).lower()
        action = str(entry.get("action", "")).lower()
        reason = str(entry.get("reason", "")).lower()
        timestamp = entry.get("timestamp")

        # WebRTC/SIP protocol detection
        try:
            port = int(dest_port)
        except (TypeError, ValueError):
            port = None
        is_webrtc = (
            (port in WEBRTC_PORTS) or
            any(kw in protocol or kw in app_field for kw in WEBRTC_KEYWORDS)
        )
        is_sip = (
            (port in SIP_PORTS) or
            any(kw in protocol or kw in app_field for kw in SIP_KEYWORDS)
        )

        # Block detection
        is_blocked = action in ["block", "deny", "reject", "dropped"] or "block" in reason or "deny" in reason

        if is_webrtc:
            incidents.append({
                "type": "WebRTC Protocol Use",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "action": action,
                "timestamp": timestamp,
                "details": entry.to_dict()
            })
        if is_sip:
            incidents.append({
                "type": "SIP Protocol Use",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "action": action,
                "timestamp": timestamp,
                "details": entry.to_dict()
            })
        if (is_webrtc or is_sip) and is_blocked:
            incidents.append({
                "type": "WebRTC/SIP Blocked",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "protocol": protocol,
                "action": action,
                "reason": reason,
                "timestamp": timestamp,
                "details": entry.to_dict()
            })
    return incidents

def correlate_incidents(incidents):
    correlation = defaultdict(list)
    for inc in incidents:
        correlation[inc["src_ip"]].append(inc)
    return [
        {
            "src_ip": ip,
            "num_incidents": len(incs),
            "incident_types": ", ".join(sorted(set(i["type"] for i in incs)))
        }
        for ip, incs in correlation.items() if len(incs) > 1
    ]

def generate_csv_report(incidents):
    df = pd.DataFrame(incidents)
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

def plot_heatmap_by_hour(incidents):
    if not incidents:
        st.info("No incidents to display in heatmap.")
        return
    df = pd.DataFrame(incidents)
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
        title='Heatmap of Incidents by Hour'
    )
    st.plotly_chart(fig, use_container_width=True)

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="WebRTC/SIP Protocol Use & Block Detection", layout="wide")
st.title("WebRTC/SIP Protocol Use & Block Detection: Firewall Log Analysis")

st.markdown("""
This tool detects WebRTC and SIP protocol usage and related block events from firewall logs.

**How to use:**
- Upload two or more firewall log CSV files.
- Click "Run Detection" to analyze and visualize results.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'incidents' not in st.session_state:
    st.session_state['incidents'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

log_files = st.file_uploader("Upload Firewall Log CSV files", type=["csv"], accept_multiple_files=True)
run_analysis = st.button("Run Detection")

if run_analysis and log_files and len(log_files) >= 2:
    try:
        dfs = []
        for file in log_files:
            df = pd.read_csv(file)
            df = parse_log(df)
            df = validate_input(df, REQUIRED_COLUMNS, file.name)
            dfs.append(df)
        combined_df = pd.concat(dfs, ignore_index=True)
        st.session_state['df'] = combined_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to read log files: {e}")
        st.stop()

    incidents = detect_webrtc_sip_and_blocks(st.session_state['df'])
    st.session_state['incidents'] = incidents
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('incidents') is not None and st.session_state.get('analysis_done'):
    incidents = st.session_state['incidents']

    st.subheader("Alert Summary")
    alert_summary = Counter([inc["type"] for inc in incidents])
    if alert_summary:
        for alert_type, count in alert_summary.items():
            st.write(f"{alert_type}: {count}")
    else:
        st.info("No WebRTC/SIP protocol use or blocks detected.")

    if incidents:
        st.markdown("### Detected Incidents")
        df_events = pd.DataFrame([{
            "Type": inc["type"],
            "Source IP": inc["src_ip"],
            "Destination IP": inc["dest_ip"],
            "Destination Port": inc["dest_port"],
            "Protocol": inc.get("protocol", ""),
            "Action": inc.get("action", ""),
            "Reason": inc.get("reason", ""),
            "Timestamp": inc.get("timestamp", ""),
            "Details": json.dumps(inc["details"])
        } for inc in incidents])
        st.dataframe(df_events)

        # --- CSV Export ---
        csv_path = generate_csv_report(incidents)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f.read(),
                file_name="webrtc_sip_incidents_report.csv",
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
| **Incident Counts by Source IP** | Shows which IPs are most frequently involved in WebRTC/SIP protocol or block activity. |
| **Incident Counts by Protocol Type** | Highlights the distribution of incident types (WebRTC, SIP, Blocked). |
| **Incident Counts by Block Reason** | Reveals which reasons are most commonly associated with blocks. |
| **Heatmap of Incidents by Hour** | Displays the distribution of incidents across each hour of the day. |
| **Correlated Incidents Table** | Lists source IPs involved in multiple types of incidents. |
""")

        st.subheader("Bar Chart: Incident Counts by Source IP")
        src_ip_counts = pd.Series([inc["src_ip"] for inc in incidents]).value_counts().reset_index().rename(
            columns={"index": "src_ip", 0: "count"}
        )
        plot_bar(src_ip_counts, "src_ip", "count", "Incident Counts by Source IP", "Source IP", "Number of Incidents", "orchid")

        st.subheader("Bar Chart: Incident Counts by Protocol Type")
        proto_counts = pd.Series([inc["type"] for inc in incidents]).value_counts().reset_index().rename(
            columns={"index": "type", 0: "count"}
        )
        plot_bar(proto_counts, "type", "count", "Incident Counts by Protocol Type", "Incident Type", "Number of Incidents", "skyblue")

        st.subheader("Bar Chart: Incident Counts by Block Reason")
        reasons = [inc.get("reason", "") for inc in incidents if inc.get("type") == "WebRTC/SIP Blocked" and inc.get("reason")]
        if reasons:
            reason_counts = pd.Series(reasons).value_counts().reset_index().rename(
                columns={"index": "reason", 0: "count"}
            )
            plot_bar(reason_counts, "reason", "count", "Incident Counts by Block Reason", "Block Reason", "Number of Incidents", "salmon")
        else:
            st.info("No block reason data for bar chart.")

        st.subheader("Heatmap: Incidents by Hour")
        plot_heatmap_by_hour(incidents)

        st.subheader("Correlated Incidents (IPs with Multiple Incident Types)")
        correlated = correlate_incidents(incidents)
        if correlated:
            correlated_df = pd.DataFrame(correlated)
            st.markdown("""
| Source IP | Number of Incidents | Incident Types |
|-----------|--------------------|---------------|
""" + "\n".join(
    f"| {row['src_ip']} | {row['num_incidents']} | {row['incident_types']} |"
    for _, row in correlated_df.iterrows()
))
        else:
            st.info("No correlated incidents found.")
    else:
        st.info("No incidents detected.")
else:
    st.info("Please upload at least two firewall log files and click 'Run Detection' to begin analysis.")