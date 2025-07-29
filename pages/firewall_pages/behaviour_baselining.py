import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import KernelDensity
from sklearn.preprocessing import StandardScaler
import tempfile
import os
from datetime import datetime

# --- Column Normalization Map ---
FW_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'protocol': ['protocol', 'proto'],
    'action': ['action', 'activity'],
    'firewall_policy_name': ['firewall_policy_name', 'policy', 'policy_name'],
    'segment_name': ['segment_name', 'segment', 'zone'],
    'src_port': ['src_port', 'source_port', 'sport'],
    'dst_port': ['dst_port', 'destination_port', 'dport'],
    'reason': ['reason', 'block_reason', 'deny_reason'],
    'bytes_sent': ['bytes_sent', 'bytes', 'sent_bytes', 'data_sent'],
    'bytes_received': ['bytes_received', 'received_bytes', 'data_received'],
    'duration_secs': ['duration_secs', 'duration', 'session_duration'],
}

REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())
BASELINE_STATS = {
    'bytes_sent': {'mean': 5000, 'std': 2000},
    'duration_secs': {'mean': 300, 'std': 100}
}
KNOWN_BENIGN_OUTLIERS = set()
NEW_ASN_SET = set()
RARE_PROTOCOLS = set()
RARE_PORTS = set()

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

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

def validate_and_parse_file(uploaded_file, required_columns, job_name="Analysis Job"):
    if uploaded_file is None:
        st.error(f"Please upload a file for {job_name}.")
        st.stop()
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()
    df = parse_firewall_log(df)
    df = validate_input(df, required_columns, job_name)
    return df

def phase1_if_kde_sensitive(df_agg_metrics, if_contamination=0.2, kde_bandwidth=0.4, kde_percentile=20):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_agg_metrics)
    if_model = IsolationForest(contamination=if_contamination, random_state=42)
    if_model.fit(X_scaled)
    if_scores = -if_model.decision_function(X_scaled)
    if_anomaly_flags = np.where(if_model.predict(X_scaled) == -1, 1, 0)
    kde_model = KernelDensity(kernel='gaussian', bandwidth=kde_bandwidth)
    kde_model.fit(X_scaled)
    kde_scores = np.exp(kde_model.score_samples(X_scaled))
    kde_threshold = np.percentile(kde_scores, kde_percentile)
    kde_anomaly_flags = (kde_scores <= kde_threshold).astype(int)
    return {
        'if_scores': if_scores,
        'kde_scores': kde_scores,
        'if_anomaly_flags': if_anomaly_flags,
        'kde_anomaly_flags': kde_anomaly_flags,
        'scaler': scaler,
        'if_model': if_model,
        'kde_model': kde_model
    }

def phase2_rule_engine(df, baseline_stats, known_benign_outliers=None,
                       drift_std_threshold=3, new_asn_set=None,
                       rare_protocols=None, rare_ports=None,
                       deny_rate_threshold=0.2, large_transfer_threshold=None):
    df = df.copy()
    for col in baseline_stats:
        mean, std = baseline_stats[col]['mean'], baseline_stats[col]['std']
        drift_col = f'{col}_drift'
        df[drift_col] = np.abs(df[col] - mean) / (std + 1e-6)
        df[f'{col}_drift_flag'] = (df[drift_col] > drift_std_threshold).astype(int)
    df['profile_drift'] = df[[f'{col}_drift_flag' for col in baseline_stats]].max(axis=1)
    df['new_asn_flag'] = ~df['asn'].isin(new_asn_set) if 'asn' in df.columns and new_asn_set else 0
    df['rare_protocol_flag'] = df['protocol'].isin(rare_protocols).astype(int) if rare_protocols and 'protocol' in df.columns else 0
    df['rare_port_flag'] = df['dst_port'].isin(rare_ports).astype(int) if rare_ports and 'dst_port' in df.columns else 0
    df['deny_flag'] = (df['action'] == 'Deny').astype(int) if 'action' in df.columns else 0
    if large_transfer_threshold is None and 'bytes_sent' in df.columns:
        large_transfer_threshold = df['bytes_sent'].quantile(0.99)
    df['large_transfer_flag'] = (df['bytes_sent'] > large_transfer_threshold).astype(int) if 'bytes_sent' in df.columns else 0
    if known_benign_outliers:
        df['known_benign_flag'] = df.apply(
            lambda row: (row['src_ip'], row['dst_ip'], row['protocol'], row['dst_port']) in known_benign_outliers,
            axis=1
        ).astype(int)
    else:
        df['known_benign_flag'] = 0
    df['phase2_alert'] = (
        (df['profile_drift'] == 1) |
        (df['new_asn_flag'] == 1) |
        (df['rare_protocol_flag'] == 1) |
        (df['rare_port_flag'] == 1) |
        (df['deny_flag'] == 1) |
        (df['large_transfer_flag'] == 1)
    ) & (df['known_benign_flag'] == 0)
    df['phase2_severity'] = np.where(
        df['profile_drift'] == 1, 'Critical',
        np.where(
            (df['new_asn_flag'] == 1) | (df['deny_flag'] == 1) | (df['large_transfer_flag'] == 1),
            'Medium',
            'Low'
        )
    )
    return df

def full_pipeline(df, baseline_stats, known_benign_outliers, new_asn_set, rare_protocols, rare_ports):
    categorical_cols = [
        'protocol', 'action', 'firewall_policy_name',
        'segment_name', 'reason'
    ]
    df_encoded = pd.get_dummies(df, columns=categorical_cols, drop_first=False)
    df_numeric = df_encoded.select_dtypes(include=[np.number])
    features = df_numeric
    features_clean = features.dropna()
    phase1_results = phase1_if_kde_sensitive(features_clean)
    df_phase1 = df.loc[features_clean.index].copy()
    df_phase1['if_scores'] = phase1_results['if_scores']
    df_phase1['kde_scores'] = phase1_results['kde_scores']
    df_phase1['if_anomaly_flags'] = phase1_results['if_anomaly_flags']
    df_phase1['kde_anomaly_flags'] = phase1_results['kde_anomaly_flags']
    df_phase2 = phase2_rule_engine(
        df_phase1,
        baseline_stats,
        known_benign_outliers,
        3,
        new_asn_set,
        rare_protocols,
        rare_ports
    )
    return df_phase2

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Streamlit UI ---
st.set_page_config(page_title="Firewall Behavioral Baselining", layout="wide")
st.title("Firewall Behavioral Baselining: Investigator Dashboard")

st.markdown("""
This tool analyzes firewall logs for behavioral anomalies using unsupervised machine learning and rule-based logic.

**How to use:**
- Upload a firewall log CSV file.
- The app will run anomaly detection and rule-based analysis.
- Visualizations and a downloadable CSV report are provided for results.
""")

if 'df_analyzed' not in st.session_state:
    st.session_state['df_analyzed'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

st.header("Upload Firewall Log Data")
log_file = st.file_uploader("Upload your firewall log CSV file", type=["csv"], key="log")

run_analysis = st.button("Run Analysis")

if run_analysis and log_file:
    try:
        df = validate_and_parse_file(log_file, REQUIRED_COLUMNS, job_name="Firewall Log Data")
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process file: {e}")
        st.stop()

    df_analyzed = full_pipeline(
        df,
        BASELINE_STATS,
        KNOWN_BENIGN_OUTLIERS,
        NEW_ASN_SET,
        RARE_PROTOCOLS,
        RARE_PORTS
    )
    st.session_state['df_analyzed'] = df_analyzed
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('df_analyzed') is not None and st.session_state.get('analysis_done'):
    df_analyzed = st.session_state['df_analyzed']

    st.subheader("Anomaly Detection Results")
    st.dataframe(df_analyzed, use_container_width=True)

    # --- CSV Export ---
    csv_path = generate_csv_report(df_analyzed)
    with open(csv_path, "rb") as f:
        st.download_button(
            label="Download CSV Report",
            data=f.read(),
            file_name="firewall_baselining_results.csv",
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
| **Baseline vs. Observed Comparison** | Compares baseline mean and observed mean for key metrics. |
| **Incident Counts by Source IP** | Shows which source IPs are most frequently involved in flagged events. |
| **Incident Counts by Protocol** | Highlights protocol usage in flagged events. |
| **Incident Severity Distribution** | Displays the distribution of severity levels. |
| **Anomaly Scores Distribution** | Shows the spread of anomaly scores. |
| **Time Series of Anomalies** | Visualizes when anomalies occur over time. |
""")

    st.subheader("Baseline vs. Observed Comparison")
    for col in BASELINE_STATS:
        chart_df = pd.DataFrame({
            "Baseline Mean": [BASELINE_STATS[col]['mean']],
            "Observed Mean": [df_analyzed[col].mean()]
        }, index=[col])
        st.bar_chart(chart_df)

    st.subheader("Incident Counts by Source IP")
    src_ip_counts = df_analyzed["src_ip"].value_counts().reset_index().rename(
        columns={"index": "src_ip", 0: "count"}
    )
    fig_ip = px.bar(
        src_ip_counts.head(20),
        x="src_ip",
        y="count",
        color_discrete_sequence=["orchid"],
        labels={"src_ip": "Source IP", "count": "Number of Events"},
        title="Top 20 Source IPs by Event Count"
    )
    st.plotly_chart(fig_ip, use_container_width=True)

    st.subheader("Incident Counts by Protocol")
    proto_counts = df_analyzed["protocol"].value_counts().reset_index().rename(
        columns={"index": "protocol", 0: "count"}
    )
    fig_proto = px.bar(
        proto_counts,
        x="protocol",
        y="count",
        color_discrete_sequence=["skyblue"],
        labels={"protocol": "Protocol", "count": "Number of Events"},
        title="Incident Counts by Protocol"
    )
    st.plotly_chart(fig_proto, use_container_width=True)

    st.subheader("Incident Severity Distribution")
    if "phase2_severity" in df_analyzed.columns:
        sev_counts = df_analyzed["phase2_severity"].value_counts().reset_index().rename(
            columns={"index": "Severity", 0: "count"}
        )
        fig_sev = px.pie(
            sev_counts,
            names="Severity",
            values="count",
            title="Incident Severity Distribution"
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No severity data for visualization.")

    st.subheader("Anomaly Scores Distribution")
    if "if_scores" in df_analyzed.columns and "kde_scores" in df_analyzed.columns:
        fig_scores = px.histogram(
            df_analyzed,
            x="if_scores",
            nbins=50,
            title="Isolation Forest Anomaly Scores"
        )
        st.plotly_chart(fig_scores, use_container_width=True)
        fig_kde = px.histogram(
            df_analyzed,
            x="kde_scores",
            nbins=50,
            title="KDE Anomaly Scores"
        )
        st.plotly_chart(fig_kde, use_container_width=True)

    st.subheader("Time Series of Anomalies")
    if "timestamp" in df_analyzed.columns and "phase2_alert" in df_analyzed.columns:
        df_analyzed["timestamp"] = pd.to_datetime(df_analyzed["timestamp"], errors="coerce")
        time_alerts = df_analyzed[df_analyzed["phase2_alert"] == 1].copy()
        time_alerts = time_alerts.dropna(subset=["timestamp"])
        if not time_alerts.empty:
            time_alerts = time_alerts.set_index("timestamp").resample("1H").size().reset_index(name="Anomaly Count")
            fig_time = px.line(
                time_alerts,
                x="timestamp",
                y="Anomaly Count",
                title="Hourly Anomaly Events"
            )
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("No anomalies detected for time series visualization.")
    else:
        st.info("No timestamp or alert data for time series visualization.")

else:
    st.info("Please upload a firewall log CSV file and click 'Run Analysis' to begin.")
