import streamlit as st
import pandas as pd
import plotly.express as px
import json
import tempfile
import os
import re
from collections import Counter

# --- Column Normalization Map ---
LOG_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
    "dest_url": ["dest_url", "destination_url", "url", "site", "hostname", "fqdn"],
    "dest_port": ["dest_port", "destination_port", "port"],
    "timestamp": ["timestamp", "time", "date"]
}

REQUIRED_COLUMNS = list(LOG_COLUMN_MAP.keys())

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
    return _normalize_columns(df, LOG_COLUMN_MAP)

# --- Utility Functions ---
def extract_ip(line):
    match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
    return match.group(1) if match else None

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

def detect_incidents(df, proxy_vpn_ips, forbidden_resources):
    incidents = []
    for _, entry in df.iterrows():
        src_ip = entry.get("src_ip")
        dest_url = str(entry.get("dest_url", "")).lower()
        dest_port = str(entry.get("dest_port", ""))
        proxy_vpn_flag = src_ip in proxy_vpn_ips
        forbidden_flag = dest_url in forbidden_resources or dest_port in forbidden_resources
        if proxy_vpn_flag:
            incidents.append({
                "type": "Proxy/VPN Use",
                "src_ip": src_ip,
                "dest_url": dest_url,
                "dest_port": dest_port,
                "timestamp": entry.get("timestamp"),
                "details": entry.to_dict()
            })
        if forbidden_flag:
            incidents.append({
                "type": "Forbidden Resource Access",
                "src_ip": src_ip,
                "dest_url": dest_url,
                "dest_port": dest_port,
                "timestamp": entry.get("timestamp"),
                "details": entry.to_dict()
            })
    return incidents

def correlate_incidents(incidents):
    from collections import defaultdict
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

# --- Streamlit UI with Session State Preservation ---
st.set_page_config(page_title="Forbidden Resource Access Detector", layout="wide")
st.title("Forbidden Resource Access Detector: Firewall Log Analysis")

st.markdown("""
This tool detects proxy/VPN use and forbidden resource access from firewall logs.

**How to use:**
- Upload one or more firewall log CSV files.
- Upload a Proxy/VPN IPs text file (one IP per line).
- Upload a Forbidden Resources text file (one entry per line, can be URL or port).
- Click "Run Detection" to analyze and visualize results.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'incidents' not in st.session_state:
    st.session_state['incidents'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

log_files = st.file_uploader("Upload Firewall Log CSV files", type=["csv"], accept_multiple_files=True)
proxy_vpn_file = st.file_uploader("Upload Proxy/VPN IPs list (one IP per line, .txt)", type=["txt"])
forbidden_file = st.file_uploader("Upload Forbidden Resources list (one entry per line, .txt)", type=["txt"])

run_analysis = st.button("Run Detection")

if run_analysis and log_files and proxy_vpn_file and forbidden_file:
    try:
        # Load Proxy/VPN IPs
        proxy_vpn_file.seek(0)
        proxy_vpn_ips = set()
        for line in proxy_vpn_file.readlines():
            try:
                line = line.decode("utf-8").strip()
            except AttributeError:
                line = line.strip()
            ip = extract_ip(line)
            if ip:
                proxy_vpn_ips.add(ip)
        # Load Forbidden Resources (URLs or ports)
        forbidden_file.seek(0)
        forbidden_resources = set()
        for line in forbidden_file.readlines():
            try:
                line = line.decode("utf-8").strip().lower()
            except AttributeError:
                line = line.strip().lower()
            if line:
                forbidden_resources.add(line)
        # Load and parse all firewall logs
        dfs = []
        for file in log_files:
            df = pd.read_csv(file)
            df = parse_firewall_log(df)
            df = validate_input(df, REQUIRED_COLUMNS, file.name)
            dfs.append(df)
        combined_df = pd.concat(dfs, ignore_index=True)
        st.session_state['df'] = combined_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process uploaded files: {e}")
        st.stop()

    incidents = detect_incidents(st.session_state['df'], proxy_vpn_ips, forbidden_resources)
    st.session_state['incidents'] = incidents
    st.session_state['analysis_done'] = True
    completion_time = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('incidents') is not None and st.session_state.get('analysis_done'):
    incidents = st.session_state['incidents']

    if not incidents:
        st.info("No proxy/VPN or forbidden resource incidents detected.")
    else:
        st.markdown("### Detected Incidents")
        df_events = pd.DataFrame([{
            "Type": inc["type"],
            "Source IP": inc["src_ip"],
            "Destination URL": inc.get("dest_url", ""),
            "Destination Port": inc.get("dest_port", ""),
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
                file_name="forbidden_resource_access_report.csv",
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
| **Incident Counts by Source IP** | Shows which IPs are most frequently involved in proxy/VPN or forbidden resource activity. |
| **Incident Counts by Destination URL** | Highlights which URLs are most often accessed in incidents. |
| **Incident Counts by Destination Port** | Reveals which ports are most commonly used in detected events. |
| **Heatmap of Incidents by Hour** | Displays the distribution of incidents across each hour of the day. |
| **Correlated Incidents Table** | Lists source IPs involved in multiple types of incidents. |
""")

        # --- Bar Chart: Source IPs ---
        st.subheader("Bar Chart: Incident Counts by Source IP")
        src_ip_counts = pd.Series([inc["src_ip"] for inc in incidents]).value_counts().reset_index().rename(
            columns={"index": "src_ip", 0: "count"}
        )
        plot_bar(src_ip_counts, "src_ip", "count", "Incident Counts by Source IP", "Source IP", "Number of Incidents", "orchid")

        # --- Bar Chart: Destination URLs ---
        st.subheader("Bar Chart: Incident Counts by Destination URL")
        dest_url_counts = pd.Series([inc.get("dest_url", "") for inc in incidents]).value_counts().reset_index().rename(
            columns={"index": "dest_url", 0: "count"}
        )
        plot_bar(dest_url_counts, "dest_url", "count", "Incident Counts by Destination URL", "Destination URL", "Number of Incidents", "skyblue")

        # --- Bar Chart: Destination Ports ---
        st.subheader("Bar Chart: Incident Counts by Destination Port")
        dest_port_counts = pd.Series([inc.get("dest_port", "") for inc in incidents]).value_counts().reset_index().rename(
            columns={"index": "dest_port", 0: "count"}
        )
        plot_bar(dest_port_counts, "dest_port", "count", "Incident Counts by Destination Port", "Destination Port", "Number of Incidents", "salmon")

        # --- Heatmap by Hour ---
        st.subheader("Heatmap: Incidents by Hour")
        plot_heatmap_by_hour(incidents)

        # --- Correlated Incidents ---
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
    st.info("Please upload all required files and click 'Run Detection' to begin analysis.")