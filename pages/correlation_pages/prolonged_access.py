import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import tempfile
import os

# --- Column Normalization Maps ---
IPDR_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
    "dst_ip": ["dst_ip", "destination_ip", "dest", "destination"],
    "start_time": ["start_time", "start", "start_timestamp", "timestamp"],
    "end_time": ["end_time", "end", "end_timestamp", "finish_time"],
    "bytes_sent": ["bytes_sent", "bytes", "sent_bytes", "data_sent"],
    "bytes_received": ["bytes_received", "received_bytes", "data_received", "recv_bytes"],
}
FW_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
    "dst_ip": ["dst_ip", "destination_ip", "dest", "destination"],
    "timestamp": ["timestamp", "time", "date"],
    "bytes_sent": ["bytes_sent", "bytes", "sent_bytes", "data_sent"],
    "bytes_received": ["bytes_received", "received_bytes", "data_received", "recv_bytes"],
}

IPDR_REQUIRED_COLUMNS = list(IPDR_COLUMN_MAP.keys())
FW_REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())

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

# --- Input Validation ---
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Suspicious Connection Detector ---
class SuspiciousConnectionDetector:
    def __init__(self, suspicious_hours=(0, 5), min_duration_minutes=60, min_data_mb=500):
        self.suspicious_hours = suspicious_hours
        self.min_duration_minutes = min_duration_minutes
        self.min_data_mb = min_data_mb
        self.ipdr_df = None
        self.fw_df = None
        self.suspicious_connections = pd.DataFrame()

    def load_ipdr_logs(self, df):
        df = parse_ipdr(df)
        df = validate_input(df, IPDR_REQUIRED_COLUMNS, "IPDR Log")
        df["start_time"] = pd.to_datetime(df["start_time"], errors="coerce")
        df["end_time"] = pd.to_datetime(df["end_time"], errors="coerce")
        df["duration_minutes"] = (df["end_time"] - df["start_time"]).dt.total_seconds() / 60
        df["total_bytes"] = df["bytes_sent"] + df["bytes_received"]
        self.ipdr_df = df

    def load_firewall_logs(self, df):
        df = parse_firewall_log(df)
        missing = [col for col in FW_REQUIRED_COLUMNS if col not in df.columns]
        if missing:
            st.warning(f"Firewall log missing columns: {missing} (correlation skipped)")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        self.fw_df = df

    def is_suspicious_hour(self, dt):
        if pd.isnull(dt):
            return False
        start, end = self.suspicious_hours
        hour = dt.hour
        if start < end:
            return start <= hour < end
        else:
            return hour >= start or hour < end

    def detect(self):
        if self.ipdr_df is None:
            raise ValueError("IPDR logs not loaded.")
        filtered = self.ipdr_df[
            (self.ipdr_df["duration_minutes"] >= self.min_duration_minutes) &
            (self.ipdr_df["total_bytes"] >= self.min_data_mb * 1024 * 1024)
        ].copy()
        filtered["suspicious_hour"] = filtered["start_time"].apply(self.is_suspicious_hour)
        filtered = filtered[filtered["suspicious_hour"]]
        self.suspicious_connections = filtered
        return filtered

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

def plot_bandwidth_over_time(df):
    if df.empty:
        st.info("No data for visualization.")
        return
    chart_df = df.copy().sort_values("start_time")
    chart_df["total_mb"] = chart_df["total_bytes"] / (1024 * 1024)
    fig = px.line(
        chart_df,
        x="start_time",
        y="total_mb",
        markers=True,
        labels={"start_time": "Start Time", "total_mb": "Total Data (MB)"},
        title="Suspicious Connection Bandwidth Over Time"
    )
    st.plotly_chart(fig, use_container_width=True)

def plot_heatmap_by_hour(df):
    if df.empty:
        st.info("No data for heatmap.")
        return
    df['hour'] = pd.to_datetime(df['start_time'], errors='coerce').dt.hour
    hour_counts = df.groupby('hour').size().reindex(range(24), fill_value=0)
    heatmap_df = pd.DataFrame({'hour': range(24), 'count': hour_counts.values})
    fig = px.density_heatmap(
        heatmap_df,
        x='hour',
        y=['Incidents'] * 24,
        z='count',
        color_continuous_scale='YlOrRd',
        title='Heatmap of Suspicious Connections by Hour'
    )
    st.plotly_chart(fig, use_container_width=True)

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Prolonged High-Volume Connection Detector", layout="wide")
st.title("Prolonged High-Volume Connection Detector: IPDR & Firewall Log Analysis")

st.markdown("""
This tool detects suspicious prolonged, high-volume connections from IPDR and firewall logs.

**How to use:**
- Upload one IPDR log and one firewall log (CSV format).
- Adjust detection parameters in the sidebar.
- Click "Run Detection" to analyze and visualize results.
""")

if 'ipdr_df' not in st.session_state:
    st.session_state['ipdr_df'] = None
if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'suspicious_df' not in st.session_state:
    st.session_state['suspicious_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

ipdr_file = st.file_uploader("Upload IPDR Log (CSV)", type=["csv"])
fw_file = st.file_uploader("Upload Firewall Log (CSV)", type=["csv"])
st.sidebar.header("Detection Parameters")
suspicious_hours = st.sidebar.slider("Suspicious Hours (start-end)", 0, 23, (0, 5))
min_duration = st.sidebar.number_input("Minimum Duration (minutes)", min_value=1, value=60)
min_data_mb = st.sidebar.number_input("Minimum Data (MB)", min_value=1, value=500)
run_analysis = st.button("Run Detection")

if run_analysis and ipdr_file and fw_file:
    try:
        ipdr_df = pd.read_csv(ipdr_file)
        fw_df = pd.read_csv(fw_file)
        detector = SuspiciousConnectionDetector(
            suspicious_hours=suspicious_hours,
            min_duration_minutes=min_duration,
            min_data_mb=min_data_mb
        )
        detector.load_ipdr_logs(ipdr_df)
        detector.load_firewall_logs(fw_df)
        suspicious_df = detector.detect()
        st.session_state['ipdr_df'] = ipdr_df
        st.session_state['fw_df'] = fw_df
        st.session_state['suspicious_df'] = suspicious_df
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("---")
    except Exception as e:
        st.error(f"Failed to process files: {e}")
        st.stop()

if st.session_state.get('suspicious_df') is not None and st.session_state.get('analysis_done'):
    suspicious = st.session_state['suspicious_df']

    if suspicious.empty:
        st.success("✅ No suspicious prolonged high-volume connections detected.")
    else:
        st.success(f"Suspicious connections detected! ({len(suspicious)})")
        st.markdown("### Suspicious Connections (Preview)")
        st.dataframe(suspicious.head(20))

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Bandwidth Over Time** | Shows the data volume of suspicious connections over time. |
| **Heatmap by Hour** | Displays the distribution of suspicious connections by hour of day. |
""")

        st.subheader("Bandwidth Usage Over Time")
        plot_bandwidth_over_time(suspicious)

        st.subheader("Heatmap: Suspicious Connections by Hour")
        plot_heatmap_by_hour(suspicious)

        # --- CSV Export ---
        csv_path = generate_csv_report(suspicious)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f.read(),
                file_name="suspicious_connections_report.csv",
                mime="text/csv"
            )
        try:
            os.remove(csv_path)
        except Exception:
            pass

else:
    st.info("Please upload both IPDR and firewall log files and click 'Run Detection' to begin analysis.")