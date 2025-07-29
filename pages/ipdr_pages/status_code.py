import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import KernelDensity
from sklearn.preprocessing import StandardScaler
import plotly.express as px
from datetime import datetime

# --- Column normalization map ---
WEBLOG_COLUMN_MAP = {
    "timestamp": ["timestamp", "time", "datetime"],
    "session_id": ["session_id"],
    "src_ip": ["src_ip", "source_ip"],
    "http_method": ["http_method", "method"],
    "url": ["url", "uri"],
    "http_status": ["http_status", "status_code", "status"],
    "user_agent": ["user_agent", "agent"],
    "bytes_sent": ["bytes_sent", "sent_bytes"],
    "bytes_received": ["bytes_received", "received_bytes"],
    "is_anomaly": ["is_anomaly", "anomaly"]
}

REQUIRED_COLUMNS = list(WEBLOG_COLUMN_MAP.keys())

BASELINE_STATS = {
    'bytes_sent': {'mean': 5000, 'std': 2000},
    'http_status': {'mean': 200, 'std': 50}
}

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

def parse_weblog(df):
    return _normalize_columns(df, WEBLOG_COLUMN_MAP)

def validate_and_parse_file(uploaded_file, required_columns, job_name="Web Log Analysis"):
    if uploaded_file is None:
        st.error(f"Please upload a file for {job_name}.")
        st.stop()
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()
    df = parse_weblog(df)
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def ml_anomaly_detection(df, if_contamination=0.2, kde_bandwidth=0.4, kde_percentile=20):
    categorical_cols = ['http_method', 'user_agent', 'url']
    for col in categorical_cols:
        if col not in df.columns:
            df[col] = "unknown"
    df_encoded = pd.get_dummies(df, columns=categorical_cols, drop_first=False)
    df_numeric = df_encoded.select_dtypes(include=[np.number])
    features = df_numeric.drop(columns=['is_anomaly'], errors='ignore')
    features_clean = features.dropna()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features_clean)
    if_model = IsolationForest(contamination=if_contamination, random_state=42)
    if_model.fit(X_scaled)
    if_scores = -if_model.decision_function(X_scaled)
    if_anomaly_flags = np.where(if_model.predict(X_scaled) == -1, 1, 0)
    kde_model = KernelDensity(kernel='gaussian', bandwidth=kde_bandwidth)
    kde_model.fit(X_scaled)
    kde_scores = np.exp(kde_model.score_samples(X_scaled))
    kde_threshold = np.percentile(kde_scores, kde_percentile)
    kde_anomaly_flags = (kde_scores <= kde_threshold).astype(int)
    df_out = df.loc[features_clean.index].copy()
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
st.set_page_config(page_title="HTTP Status Code Analysis Dashboard", layout="wide")
st.title("HTTP Status Code Analysis Dashboard")

st.markdown("""
**What does this dashboard do?**

- **Purpose:** This dashboard analyzes your web server logs to help you understand HTTP status code patterns, detect anomalies, and investigate potential issues or attacks.
- **How it works:** It uses machine learning (Isolation Forest and Kernel Density) to flag sessions with unusual behavior, such as rare status codes, abnormal data transfer, or suspicious request patterns.
- **What you get:** Actionable tables, error breakdowns, time trends, and interactive visualizations to help you quickly identify and drill down into problematic sessions.

**Instructions:**
1. Upload a single web log file (CSV) with columns like timestamp, session_id, src_ip, http_method, url, http_status, user_agent, bytes_sent, bytes_received.
2. Review the results, visualizations, and download the findings for further investigation.
""")

# Session State Initialization
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'results_df' not in st.session_state:
    st.session_state['results_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False
if 'completion_time' not in st.session_state:
    st.session_state['completion_time'] = None

uploaded_file = st.file_uploader("Upload Web Log CSV File", type=["csv"])

if uploaded_file:
    df = validate_and_parse_file(uploaded_file, REQUIRED_COLUMNS, job_name="Web Log Analysis")
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

    st.subheader("Session-Level Actionable Results")
    st.dataframe(
        results_df[
            [
                'timestamp', 'session_id', 'src_ip', 'http_method', 'url',
                'http_status', 'user_agent', 'bytes_sent', 'bytes_received',
                'if_anomaly_flags', 'kde_anomaly_flags', 'ml_anomaly', 'ml_severity'
            ]
        ],
        use_container_width=True
    )

    st.subheader("Baseline vs. Current Metrics")
    for col in BASELINE_STATS:
        if col in results_df.columns:
            chart_df = pd.DataFrame({
                "Baseline Mean": [BASELINE_STATS[col]['mean']],
                "Current Mean": [results_df[col].mean()]
            }, index=[col])
            st.bar_chart(chart_df)

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

    # --- Additional Visualizations ---
    st.subheader("HTTP Status Code Distribution")
    fig_status = px.histogram(
        results_df, x="http_status", color="ml_severity",
        nbins=30, barmode="group",
        labels={"http_status": "HTTP Status Code", "ml_severity": "ML Severity"},
        title="Distribution of HTTP Status Codes by Severity"
    )
    st.plotly_chart(fig_status, use_container_width=True)

    st.subheader("Top URLs with Anomalies")
    top_urls = results_df[results_df['ml_anomaly'] == 1]['url'].value_counts().head(10)
    fig_urls = px.bar(
        top_urls, x=top_urls.index, y=top_urls.values,
        labels={"x": "URL", "y": "Anomaly Count"},
        title="Top 10 URLs Triggering Anomalies"
    )
    st.plotly_chart(fig_urls, use_container_width=True)

    st.subheader("User Agent Distribution (Anomalous Sessions)")
    ua_counts = results_df[results_df['ml_anomaly'] == 1]['user_agent'].value_counts().head(10)
    fig_ua = px.pie(
        names=ua_counts.index, values=ua_counts.values,
        title="Top 10 User Agents in Anomalous Sessions"
    )
    st.plotly_chart(fig_ua, use_container_width=True)

    st.subheader("Bytes Sent vs. HTTP Status (Scatter)")
    fig_bytes = px.scatter(
        results_df, x="bytes_sent", y="http_status", color="ml_severity",
        hover_data=["session_id", "url"],
        title="Bytes Sent vs. HTTP Status Code (Colored by Severity)",
        labels={"bytes_sent": "Bytes Sent", "http_status": "HTTP Status"}
    )
    st.plotly_chart(fig_bytes, use_container_width=True)

    st.subheader("Export Results")
    csv = results_df.to_csv(index=False)
    st.download_button(
        label="Download Results as CSV",
        data=csv,
        file_name="http_status_analysis_results.csv",
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
    st.info("Please upload a web log CSV file to begin analysis.")