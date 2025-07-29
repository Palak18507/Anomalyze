import streamlit as st
import pandas as pd
import plotly.express as px
import ipaddress
import json
import tempfile
import os

# --- Column Normalization Map ---
LOG_COLUMN_MAP = {
    "timestamp": ["timestamp", "time", "date"],
    "src_ip": ["src_ip", "source_ip", "src", "source"],
    "dst_ip": ["dst_ip", "destination_ip", "dest", "destination"],
    "bytes_sent": ["bytes_sent", "bytes", "sent_bytes", "data_sent"],
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

def parse_log(df):
    return _normalize_columns(df, LOG_COLUMN_MAP)

# --- Utility Functions ---
def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

def detect_massive_data_exfiltration(df, foreign_ip_range, data_threshold_bytes):
    incidents = []
    for _, row in df.iterrows():
        try:
            dst_ip = row.get('dst_ip')
            bytes_sent = int(row.get('bytes_sent', 0))
            if ipaddress.ip_address(dst_ip) in foreign_ip_range and bytes_sent > data_threshold_bytes:
                incidents.append({
                    'type': 'Massive Data Exfiltration',
                    'src_ip': row.get('src_ip'),
                    'dst_ip': dst_ip,
                    'bytes_sent': bytes_sent,
                    'timestamp': row.get('timestamp'),
                    'details': row.to_dict()
                })
        except Exception:
            continue
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
st.set_page_config(page_title="Massive Data Exfiltration Detection", layout="wide")
st.title("Massive Data Exfiltration Detection: IPDR/Firewall Log Analysis")

st.markdown("""
This tool detects massive data exfiltration to foreign IP ranges from IPDR or firewall logs.

**How to use:**
- Upload one or more IPDR or firewall log CSV files.
- Specify the foreign IP range (CIDR).
- Set the data volume threshold (in MB).
- Click "Run Detection" to analyze and visualize results.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'incidents' not in st.session_state:
    st.session_state['incidents'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_files = st.file_uploader("Upload IPDR/Firewall Log CSV files", type=["csv"], accept_multiple_files=True)
foreign_ip_range_str = st.text_input("Foreign IP Range (CIDR)", value="203.0.113.0/24")
data_threshold_mb = st.number_input("Data Volume Threshold (MB)", min_value=1, value=100)

run_analysis = st.button("Run Detection")

if run_analysis and uploaded_files:
    try:
        dfs = []
        for file in uploaded_files:
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

    try:
        foreign_ip_range = ipaddress.ip_network(foreign_ip_range_str)
        data_threshold_bytes = data_threshold_mb * 1024 * 1024
    except Exception as e:
        st.error(f"Invalid foreign IP range or data threshold: {e}")
        st.stop()

    incidents = detect_massive_data_exfiltration(st.session_state['df'], foreign_ip_range, data_threshold_bytes)
    st.session_state['incidents'] = incidents
    st.session_state['analysis_done'] = True
    completion_time = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('incidents') is not None and st.session_state.get('analysis_done'):
    incidents = st.session_state['incidents']

    if not incidents:
        st.info("No massive data exfiltration incidents detected.")
    else:
        st.markdown("### Detected Incidents")
        df_events = pd.DataFrame([{
            "Type": inc["type"],
            "Source IP": inc["src_ip"],
            "Destination IP": inc["dst_ip"],
            "Bytes Sent": inc["bytes_sent"],
            "Timestamp": inc["timestamp"],
            "Details": json.dumps(inc["details"])
        } for inc in incidents])
        st.dataframe(df_events)

        # --- CSV Export ---
        csv_path = generate_csv_report(incidents)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f.read(),
                file_name="massive_data_exfiltration_report.csv",
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
| **Incident Counts by Source IP** | Shows which source IPs are most frequently involved in exfiltration. |
| **Incident Counts by Destination IP** | Highlights which foreign IPs are most often targeted. |
| **Incident Counts by Data Volume** | Reveals which IPs sent the most data in detected events. |
| **Heatmap of Incidents by Hour** | Displays the distribution of incidents across each hour of the day. |
| **Correlated Incidents Table** | Lists source IPs involved in multiple exfiltration incidents. |
""")

        # --- Bar Chart: Source IPs ---
        st.subheader("Bar Chart: Incident Counts by Source IP")
        src_ip_counts = pd.Series([inc["src_ip"] for inc in incidents]).value_counts().reset_index().rename(
            columns={"index": "src_ip", 0: "count"}
        )
        plot_bar(src_ip_counts, "src_ip", "count", "Incident Counts by Source IP", "Source IP", "Number of Incidents", "orchid")

        # --- Bar Chart: Destination IPs ---
        st.subheader("Bar Chart: Incident Counts by Destination IP")
        dst_ip_counts = pd.Series([inc["dst_ip"] for inc in incidents]).value_counts().reset_index().rename(
            columns={"index": "dst_ip", 0: "count"}
        )
        plot_bar(dst_ip_counts, "dst_ip", "count", "Incident Counts by Destination IP", "Destination IP", "Number of Incidents", "skyblue")

        # --- Bar Chart: Data Volume by Source IP ---
        st.subheader("Bar Chart: Data Volume by Source IP")
        data_volume = pd.DataFrame([{"src_ip": inc["src_ip"], "bytes_sent": inc["bytes_sent"]} for inc in incidents])
        data_volume = data_volume.groupby("src_ip")["bytes_sent"].sum().reset_index()
        plot_bar(data_volume, "src_ip", "bytes_sent", "Data Volume by Source IP", "Source IP", "Total Bytes Sent", "salmon")

        # --- Heatmap by Hour ---
        st.subheader("Heatmap: Incidents by Hour")
        plot_heatmap_by_hour(incidents)

        # --- Correlated Incidents ---
        st.subheader("Correlated Incidents (IPs with Multiple Incidents)")
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
    st.info("Please upload log files and click 'Run Detection' to begin analysis.")