import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime
import tempfile
import os

# --- Column Normalization Map ---
FW_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'bytes': ['bytes', 'bytes_sent', 'bytes_received', 'data_bytes'],
}
REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())

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

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

def aggregate_metric(df, group_by, time_window, metric):
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df.index):
        df.index = pd.to_datetime(df.index)
    agg = (
        df.groupby([pd.Grouper(freq=time_window), group_by])[metric]
        .sum()
        .reset_index()
    )
    agg = agg.sort_values(['timestamp', group_by])
    return agg

def compute_rolling_stats(agg, group_by, metric, baseline_windows):
    agg['rolling_mean'] = (
        agg.groupby(group_by)[metric]
        .transform(lambda x: x.rolling(baseline_windows, min_periods=1).mean())
    )
    agg['rolling_std'] = (
        agg.groupby(group_by)[metric]
        .transform(lambda x: x.rolling(baseline_windows, min_periods=1).std(ddof=0).fillna(0))
    )
    return agg

def detect_spikes(agg, metric, z_threshold, group_by):
    agg['z_score'] = (agg[metric] - agg['rolling_mean']) / (agg['rolling_std'] + 1e-9)
    anomalies = agg[agg['z_score'] > z_threshold].copy()
    anomalies['Anomaly Reason'] = (
        f"{group_by} {metric} spike: z-score > {z_threshold}"
    )
    return anomalies

def plot_spikes(agg, group_by, metric, anomalies, selected_ip=None):
    if selected_ip:
        agg = agg[agg[group_by] == selected_ip]
        anomalies = anomalies[anomalies[group_by] == selected_ip]
        title = f"{metric} over Time for {group_by} {selected_ip}"
    else:
        title = f"{metric} over Time by {group_by}"
    fig = px.line(
        agg,
        x="timestamp",
        y=metric,
        color=group_by if not selected_ip else None,
        title=title,
        labels={"timestamp": "Timestamp", metric: metric, group_by: group_by}
    )
    if not anomalies.empty:
        fig.add_scatter(
            x=anomalies["timestamp"],
            y=anomalies[metric],
            mode="markers",
            marker=dict(color="red", size=8),
            name="Spikes"
        )
    st.plotly_chart(fig, use_container_width=True)

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Port-IP Activity Spikes Detection", layout="wide")
st.title("Port-IP Activity Spikes Detection: Firewall Log Analysis")

st.markdown("""
This tool detects sudden spikes in activity (e.g., bytes transferred) per destination IP over time in firewall logs.

**How to use:**
- Upload one or more firewall log CSV files.
- The app will aggregate bytes per destination IP per minute, compute rolling baselines, and flag significant spikes.
""")

if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'agg_df' not in st.session_state:
    st.session_state['agg_df'] = None
if 'anomalies_df' not in st.session_state:
    st.session_state['anomalies_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_files = st.file_uploader("Upload Firewall Log CSV files", type=["csv"], accept_multiple_files=True)
run_analysis = st.button("Run Detection")

if run_analysis and uploaded_files:
    try:
        dfs = []
        for file in uploaded_files:
            df = pd.read_csv(file)
            df = parse_firewall_log(df)
            df = validate_input(df, REQUIRED_COLUMNS, file.name)
            dfs.append(df)
        fw_df = pd.concat(dfs, ignore_index=True)
        fw_df['timestamp'] = pd.to_datetime(fw_df['timestamp'], errors='coerce')
        fw_df = fw_df.set_index('timestamp')
        st.session_state['fw_df'] = fw_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process firewall log files: {e}")
        st.stop()

    group_by = 'dst_ip'
    time_window = '1min'
    metric = 'bytes'
    z_threshold = 3.0
    baseline_windows = 60

    agg_df = aggregate_metric(st.session_state['fw_df'], group_by, time_window, metric)
    agg_df = compute_rolling_stats(agg_df, group_by, metric, baseline_windows)
    anomalies_df = detect_spikes(agg_df, metric, z_threshold, group_by)

    st.session_state['agg_df'] = agg_df
    st.session_state['anomalies_df'] = anomalies_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Spike detection analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('agg_df') is not None and st.session_state.get('analysis_done'):
    agg_df = st.session_state['agg_df']
    anomalies_df = st.session_state['anomalies_df']

    st.subheader("Aggregated Data")
    st.dataframe(agg_df)

    st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Time Series by Destination IP** | Shows bytes transferred per minute per destination IP. |
| **Red Markers** | Highlight detected spike anomalies. |
""")

    st.subheader("Detected Spikes Visualization")

    # Interactive IP selection for focused visualization
    ip_options = agg_df['dst_ip'].dropna().unique()
    selected_ip = None
    if len(ip_options) > 1:
        selected_ip = st.selectbox(
            "Select a destination IP to visualize (or show all):",
            options=["Show all"] + list(ip_options),
            index=0
        )
        if selected_ip == "Show all":
            selected_ip = None
    elif len(ip_options) == 1:
        selected_ip = ip_options[0]

    plot_spikes(agg_df, 'dst_ip', 'bytes', anomalies_df, selected_ip=selected_ip)

    st.subheader("Detected Anomalies")
    if anomalies_df.empty:
        st.success("No spike anomalies detected.")
    else:
        st.dataframe(anomalies_df)
        st.warning(f"Flagged {len(anomalies_df)} spike anomalies.")

    # --- CSV Export ---
    csv_path = generate_csv_report(anomalies_df)
    with open(csv_path, "rb") as f:
        st.download_button(
            label="Download Anomalies Report",
            data=f.read(),
            file_name="port_ip_activity_spikes_report.csv",
            mime="text/csv"
        )
    try:
        os.remove(csv_path)
    except Exception:
        pass

else:
    st.info("Please upload firewall log files and click 'Run Detection' to begin analysis.")