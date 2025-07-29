import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import tempfile
import os

# --- Column Normalization Map ---
FW_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'bytes_sent': ['bytes_sent', 'bytes', 'sent_bytes', 'data_sent'],
    'bytes_received': ['bytes_received', 'received_bytes', 'data_received'],
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
def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Unusual Bandwidth Usage Detection ---
def detect_unusual_bandwidth_usage(
    df,
    ip_column='src_ip',
    bytes_sent_col='bytes_sent',
    bytes_received_col='bytes_received',
    threshold_std=3
):
    agg = df.groupby(ip_column).agg({bytes_sent_col: 'sum', bytes_received_col: 'sum'}).reset_index()
    sent_mean = agg[bytes_sent_col].mean()
    sent_std = agg[bytes_sent_col].std()
    recv_mean = agg[bytes_received_col].mean()
    recv_std = agg[bytes_received_col].std()
    agg['unusual_upload'] = agg[bytes_sent_col] > (sent_mean + threshold_std * sent_std)
    agg['unusual_download'] = agg[bytes_received_col] > (recv_mean + threshold_std * recv_std)
    flagged = agg[(agg['unusual_upload']) | (agg['unusual_download'])]
    return flagged

# --- Sudden Connection Spikes Detection ---
def detect_sudden_connection_spikes(
    df,
    ip_column='src_ip',
    timestamp_col='timestamp',
    connection_threshold=10,
    dormant_days=7,
    spike_window_minutes=10
):
    df = df.copy()
    df = df.sort_values(timestamp_col)
    last_activity = df.groupby(ip_column)[timestamp_col].max().reset_index()
    current_time = df[timestamp_col].max()
    dormant_cutoff = current_time - pd.Timedelta(days=dormant_days)
    dormant_devices = last_activity[last_activity[timestamp_col] < dormant_cutoff][ip_column].tolist()
    dormant_df = df[df[ip_column].isin(dormant_devices)]
    spikes = []
    for device in dormant_devices:
        device_logs = dormant_df[dormant_df[ip_column] == device]
        times = device_logs[timestamp_col].tolist()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + pd.Timedelta(minutes=spike_window_minutes)
            count = device_logs[(device_logs[timestamp_col] >= window_start) & (device_logs[timestamp_col] <= window_end)].shape[0]
            if count >= connection_threshold:
                spikes.append({
                    ip_column: device,
                    'spike_start': window_start,
                    'spike_end': window_end,
                    'connection_count': count
                })
                break  # Flag once per device
    spikes_df = pd.DataFrame(spikes)
    return spikes_df

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Firewall Log Bandwidth & Spike Detection", layout="wide")
st.title("Firewall Log Bandwidth & Sudden Connection Spike Detection")

st.markdown("""
This tool analyzes firewall logs to detect:
- **Unusual bandwidth usage** (high upload/download volume)
- **Sudden connection spikes** from dormant devices

**How to use:**
- Upload one or more firewall log CSV files.
- Review flagged results and download reports.
""")

if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'bandwidth_df' not in st.session_state:
    st.session_state['bandwidth_df'] = None
if 'spikes_df' not in st.session_state:
    st.session_state['spikes_df'] = None
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
        st.session_state['fw_df'] = fw_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process firewall log files: {e}")
        st.stop()

    # Unusual Bandwidth Usage
    bandwidth_df = detect_unusual_bandwidth_usage(st.session_state['fw_df'])
    st.session_state['bandwidth_df'] = bandwidth_df

    # Sudden Connection Spikes
    spikes_df = detect_sudden_connection_spikes(st.session_state['fw_df'])
    st.session_state['spikes_df'] = spikes_df

    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('bandwidth_df') is not None and st.session_state.get('analysis_done'):
    bandwidth_df = st.session_state['bandwidth_df']
    st.subheader("Unusual Bandwidth Usage Detection")
    if not bandwidth_df.empty:
        st.warning(f"Unusual bandwidth usage detected for {bandwidth_df.shape[0]} IP(s).")
        st.dataframe(bandwidth_df)
        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Bar Chart: Upload Volume by IP** | Shows upload volume for each source IP. |
| **Bar Chart: Download Volume by IP** | Shows download volume for each source IP. |
""")

        st.subheader("Bar Chart: Upload Volume by IP")
        fig_upload = px.bar(
            bandwidth_df,
            x="src_ip",
            y="bytes_sent",
            color_discrete_sequence=["orchid"],
            labels={"src_ip": "Source IP", "bytes_sent": "Total Upload Bytes"},
            title="Upload Volume by Source IP"
        )
        st.plotly_chart(fig_upload, use_container_width=True)

        st.subheader("Bar Chart: Download Volume by IP")
        fig_download = px.bar(
            bandwidth_df,
            x="src_ip",
            y="bytes_received",
            color_discrete_sequence=["skyblue"],
            labels={"src_ip": "Source IP", "bytes_received": "Total Download Bytes"},
            title="Download Volume by Source IP"
        )
        st.plotly_chart(fig_download, use_container_width=True)

        # --- CSV Export ---
        csv_path = generate_csv_report(bandwidth_df)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download Bandwidth Usage Report",
                data=f.read(),
                file_name="unusual_bandwidth_usage_report.csv",
                mime="text/csv"
            )
        try:
            os.remove(csv_path)
        except Exception:
            pass
    else:
        st.success("No unusual bandwidth usage detected.")

if st.session_state.get('spikes_df') is not None and st.session_state.get('analysis_done'):
    spikes_df = st.session_state['spikes_df']
    st.subheader("Sudden Connection Spikes Detection")
    if not spikes_df.empty:
        st.warning(f"Sudden connection spikes detected for {spikes_df.shape[0]} dormant device(s).")
        st.dataframe(spikes_df)
        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Bar Chart: Connection Spikes by IP** | Shows number of connections in spike windows for each dormant device. |
""")

        st.subheader("Bar Chart: Connection Spikes by IP")
        fig_spike = px.bar(
            spikes_df,
            x="src_ip",
            y="connection_count",
            color_discrete_sequence=["salmon"],
            labels={"src_ip": "Source IP", "connection_count": "Connections in Spike Window"},
            title="Connection Spikes by Dormant Device"
        )
        st.plotly_chart(fig_spike, use_container_width=True)

        # --- CSV Export ---
        csv_path = generate_csv_report(spikes_df)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download Connection Spikes Report",
                data=f.read(),
                file_name="sudden_connection_spikes_report.csv",
                mime="text/csv"
            )
        try:
            os.remove(csv_path)
        except Exception:
            pass
    else:
        st.success("No sudden connection spikes detected.")

else:
    st.info("Please upload firewall log files and click 'Run Detection' to begin analysis.")