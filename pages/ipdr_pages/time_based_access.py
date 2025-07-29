import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import KernelDensity
from sklearn.preprocessing import StandardScaler
import plotly.express as px
from datetime import datetime

# --- Configuration ---
st.set_page_config(
    page_title="IPDR Log Anomaly Analysis Dashboard",
    layout="wide"
)

IPDR_COLUMN_MAP = {
    "timestamp": ["timestamp", "time", "datetime"],
    "session_id": ["session_id"],
    "src_ip": ["src_ip", "source_ip"],
    "dst_ip": ["dst_ip", "destination_ip"],
    "protocol": ["protocol"],
    "src_port": ["src_port", "source_port"],
    "dst_port": ["dst_port", "destination_port"],
    "asn": ["asn"],
    "bytes_sent": ["bytes_sent", "sent_bytes"],
    "bytes_received": ["bytes_received", "received_bytes"],
    "duration_secs": ["duration_secs", "duration"],
}

REQUIRED_COLUMNS = list(IPDR_COLUMN_MAP.keys())

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

def validate_and_parse_file(uploaded_file, required_columns, job_name="IPDR Log Analysis"):
    if uploaded_file is None:
        st.error(f"Please upload a file for {job_name}.")
        st.stop()
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()
    df = parse_ipdr(df)
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def ml_anomaly_detection(df, if_contamination=0.1, kde_bandwidth=0.5, kde_percentile=10):
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['protocol_original'] = df['protocol']  # Preserve original protocol for display
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
    agg = df.groupby(['src_ip', 'hour']).size().reset_index(name='sessions_per_hour')
    df = pd.merge(df, agg, on=['src_ip', 'hour'], how='left')
    df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_received'] + 1)
    df['duration_per_byte'] = df['duration_secs'] / (df['bytes_sent'] + 1)
    df = pd.get_dummies(df, columns=['protocol'], prefix='proto')
    df['src_port'] = df['src_port'].fillna(-1)
    df['dst_port'] = df['dst_port'].fillna(-1)

    feature_cols = [
        'hour', 'day_of_week', 'is_weekend', 'sessions_per_hour',
        'src_port', 'dst_port', 'asn', 'bytes_sent', 'bytes_received',
        'duration_secs', 'bytes_ratio', 'duration_per_byte'
    ] + [c for c in df.columns if c.startswith('proto_')]

    features = df[feature_cols].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)

    if_model = IsolationForest(contamination=if_contamination, random_state=42)
    if_model.fit(X_scaled)
    if_scores = -if_model.decision_function(X_scaled)
    if_anomaly_flags = np.where(if_model.predict(X_scaled) == -1, 1, 0)

    kde_model = KernelDensity(kernel='gaussian', bandwidth=kde_bandwidth)
    kde_model.fit(X_scaled)
    kde_scores = kde_model.score_samples(X_scaled)
    kde_threshold = np.percentile(kde_scores, kde_percentile)
    kde_anomaly_flags = (kde_scores <= kde_threshold).astype(int)

    df_out = df.copy()
    df_out['if_scores'] = if_scores
    df_out['kde_scores'] = kde_scores
    df_out['if_anomaly_flags'] = if_anomaly_flags
    df_out['kde_anomaly_flags'] = kde_anomaly_flags
    df_out['ml_anomaly'] = np.where(
        (df_out['if_anomaly_flags'] == 1) | (df_out['kde_anomaly_flags'] == 1), 1, 0
    )
    df_out['ml_severity'] = np.where(
        (df_out['if_anomaly_flags'] == 1) & (df_out['kde_anomaly_flags'] == 1), 'High',
        np.where(
            (df_out['if_anomaly_flags'] == 1) | (df_out['kde_anomaly_flags'] == 1), 'Medium', 'Low'
        )
    )
    return df_out

# --- Streamlit UI with Session State Preservation ---

st.title("IPDR Log Anomaly Analysis Dashboard")

st.markdown("""
- **Purpose:** Analyze your IPDR logs to detect time-based and protocol-based anomalies, and investigate potential threats or misuses.
- **How it works:** Uses machine learning (Isolation Forest & Kernel Density) to flag sessions with unusual temporal or protocol behavior.
- **What you get:** Actionable tables, anomaly breakdowns, time trends, and interactive visualizations for investigation.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'results_df' not in st.session_state:
    st.session_state['results_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False
if 'completion_time' not in st.session_state:
    st.session_state['completion_time'] = None

uploaded_file = st.file_uploader("Upload IPDR Log CSV File", type=["csv"])

if uploaded_file:
    df = validate_and_parse_file(uploaded_file, REQUIRED_COLUMNS, job_name="IPDR Log Analysis")
    st.session_state['df'] = df

    results_df = ml_anomaly_detection(df)
    st.session_state['results_df'] = results_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state['completion_time'] = completion_time

    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state['results_df'] is not None and st.session_state['analysis_done']:
    results_df = st.session_state['results_df']

    # Only display columns that exist (robust to missing columns)
    display_cols = [
        'timestamp', 'session_id', 'src_ip', 'dst_ip', 'protocol_original',
        'src_port', 'dst_port', 'asn', 'bytes_sent', 'bytes_received',
        'duration_secs', 'hour', 'sessions_per_hour',
        'if_anomaly_flags', 'kde_anomaly_flags', 'ml_anomaly', 'ml_severity'
    ]
    display_cols = [col for col in display_cols if col in results_df.columns]

    st.subheader("Session-Level Actionable Results")
    st.dataframe(
        results_df[display_cols],
        use_container_width=True
    )

    st.subheader("Anomaly and Severity Counts")
    anomaly_count = results_df['ml_anomaly'].sum()
    severity_counts = results_df['ml_severity'].value_counts()
    st.metric("Detected Anomalies", int(anomaly_count))
    st.write("Severity Breakdown:")
    st.table(severity_counts)

    st.subheader("Anomalies Over Time")
    if 'timestamp' in results_df.columns:
        results_df['timestamp'] = pd.to_datetime(results_df['timestamp'], errors='coerce')
        time_trend = results_df[results_df['ml_anomaly'] == 1].groupby(
            results_df['timestamp'].dt.date
        ).size()
        st.line_chart(time_trend)

    st.subheader("Hourly Distribution of Anomalies")
    hourly = results_df.groupby(['hour', 'ml_anomaly']).size().unstack(fill_value=0)
    fig_hour = px.bar(
        hourly,
        barmode="stack",
        title="Hourly Anomaly Counts",
        labels={"value": "Count", "hour": "Hour of Day"}
    )
    st.plotly_chart(fig_hour, use_container_width=True)

    st.subheader("Top Source IPs with Anomalies")
    top_ips = results_df[results_df['ml_anomaly'] == 1]['src_ip'].value_counts().head(10)
    fig_ips = px.bar(
        top_ips, x=top_ips.index, y=top_ips.values,
        labels={"x": "Source IP", "y": "Anomaly Count"},
        title="Top 10 Source IPs Triggering Anomalies"
    )
    st.plotly_chart(fig_ips, use_container_width=True)

    st.subheader("Bytes Sent vs. Sessions per Hour (Scatter)")
    fig_bytes = px.scatter(
        results_df, x="sessions_per_hour", y="bytes_sent", color="ml_severity",
        hover_data=["src_ip", "dst_ip", "session_id"],
        title="Bytes Sent vs. Sessions per Hour (Colored by Severity)",
        labels={"bytes_sent": "Bytes Sent", "sessions_per_hour": "Sessions per Hour"}
    )
    st.plotly_chart(fig_bytes, use_container_width=True)

    st.subheader("Export Results")
    csv = results_df.to_csv(index=False)
    st.download_button(
        label="Download Results as CSV",
        data=csv,
        file_name="ipdr_anomaly_results.csv",
        mime="text/csv"
    )

    st.subheader("Drill-Down: Anomalous Sessions")
    anomalies = results_df[results_df['ml_anomaly'] == 1]
    if not anomalies.empty:
        selected_idx = st.selectbox(
            "Select an anomaly to view details",
            anomalies.index
        )
        st.write(anomalies.loc[selected_idx])
    else:
        st.info("No anomalies detected in this file.")

    st.success(
        f"Analysis complete at {st.session_state['completion_time']}. "
        "Use the dashboard to review, filter, and export anomaly findings."
    )
else:
    st.info("Please upload an IPDR log CSV file to begin analysis.")