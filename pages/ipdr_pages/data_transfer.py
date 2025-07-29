import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import KernelDensity
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
import plotly.express as px
from datetime import datetime

# --- Column normalization map ---
IPDR_COLUMN_MAP = {
    "timestamp": ["timestamp", "time", "datetime"],
    "src_ip": ["src_ip", "source_ip"],
    "dst_ip": ["dst_ip", "destination_ip"],
    "protocol": ["protocol"],
    "action": ["action"],
    "firewall_policy_name": ["firewall_policy_name", "policy_name"],
    "segment_name": ["segment_name", "segment"],
    "src_port": ["src_port", "source_port"],
    "dst_port": ["dst_port", "destination_port"],
    "reason": ["reason"],
    "bytes_sent": ["bytes_sent", "sent_bytes"],
    "bytes_received": ["bytes_received", "received_bytes"],
    "duration_secs": ["duration_secs", "duration"],
    "is_anomaly": ["is_anomaly", "anomaly"]
}

REQUIRED_COLUMNS = list(IPDR_COLUMN_MAP.keys())

BASELINE_STATS = {
    'bytes_sent': {'mean': 5000, 'std': 2000},
    'duration_secs': {'mean': 300, 'std': 100}
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

def parse_ipdr(df):
    return _normalize_columns(df, IPDR_COLUMN_MAP)

def validate_and_parse_file(uploaded_file, required_columns, job_name="Data Transfer Pattern Tracking"):
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

def phase1_if_kde_sensitive(df_agg_metrics, if_contamination=0.1, kde_bandwidth=0.2, kde_percentile=20):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_agg_metrics)
    if_model = IsolationForest(n_estimators=200, contamination=if_contamination, max_features=0.7, random_state=42)
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
        'kde_model': kde_model,
        'kde_threshold': kde_threshold
    }

def encode_and_clean(df, categorical_cols):
    df_encoded = pd.get_dummies(df, columns=categorical_cols, drop_first=False)
    df_numeric = df_encoded.select_dtypes(include=[np.number])
    features = df_numeric.drop(columns=['is_anomaly'], errors='ignore')
    features_clean = features.dropna()
    return df_encoded, features, features_clean

def full_pipeline(df):
    categorical_cols = [
        'protocol', 'action', 'firewall_policy_name',
        'segment_name', 'reason'
    ]
    df_encoded, features, features_clean = encode_and_clean(df, categorical_cols)
    phase1_results = phase1_if_kde_sensitive(features_clean)
    df_phase1 = df.loc[features_clean.index].copy()
    df_phase1['if_scores'] = phase1_results['if_scores']
    df_phase1['kde_scores'] = phase1_results['kde_scores']
    df_phase1['if_anomaly_flags'] = phase1_results['if_anomaly_flags']
    df_phase1['kde_anomaly_flags'] = phase1_results['kde_anomaly_flags']
    return df_phase1, features_clean, phase1_results

def train_xgb(df_ml, feature_cols):
    X = df_ml[feature_cols].dropna().values
    y = df_ml.loc[df_ml[feature_cols].dropna().index, 'is_anomaly'].astype(int).values
    pos_weight = (len(y) - sum(y)) / sum(y) if sum(y) > 0 else 1
    xgb_model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=pos_weight,
        objective='binary:logistic',
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42
    )
    xgb_model.fit(X, y)
    return xgb_model

def predict_xgb(xgb_model, df_ml, feature_cols):
    X = df_ml[feature_cols].dropna().values
    preds = xgb_model.predict(X)
    return preds, df_ml[feature_cols].dropna().index

def anomaly_summary_table(df):
    summary = df.groupby('xgb_pred').agg(
        Count=('xgb_pred', 'size'),
        Mean_Bytes_Sent=('bytes_sent', 'mean'),
        Mean_Duration=('duration_secs', 'mean')
    ).rename(index={0: "Normal", 1: "Anomaly"})
    st.table(summary)

# --- Streamlit UI with Session State Preservation ---
st.set_page_config(page_title="Data Transfer Pattern Tracking", layout="wide")
st.title("Data Transfer Pattern Tracking Dashboard")

st.markdown("""
**What does this dashboard do?**

- **Purpose:** Analyze firewall/IPDR logs to uncover unusual data transfer patterns, detect anomalies, and investigate potential security or operational issues.
- **How it works:** Uses machine learning (Isolation Forest, Kernel Density, and XGBoost) to flag sessions with abnormal data transfer, protocol, or session patterns.
- **What you get:** Actionable tables, anomaly breakdowns, time trends, and interactive visualizations to help you quickly identify and drill down into problematic sessions.

**Instructions:**
1. Upload a single IPDR/firewall log file (CSV) with columns like timestamp, src_ip, dst_ip, protocol, action, firewall_policy_name, segment_name, ports, reason, bytes_sent, bytes_received, duration_secs.
2. Review the results, visualizations, and download the findings for further investigation.
""")

# Session State Initialization
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'df_ml' not in st.session_state:
    st.session_state['df_ml'] = None
if 'features_clean' not in st.session_state:
    st.session_state['features_clean'] = None
if 'phase1_results' not in st.session_state:
    st.session_state['phase1_results'] = None
if 'xgb_model' not in st.session_state:
    st.session_state['xgb_model'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False
if 'completion_time' not in st.session_state:
    st.session_state['completion_time'] = None

uploaded_file = st.file_uploader("Upload IPDR/Firewall Log CSV File", type=["csv"])

if uploaded_file:
    df = validate_and_parse_file(uploaded_file, REQUIRED_COLUMNS, job_name="Data Transfer Pattern Tracking")
    st.session_state['df'] = df
    df_ml, features_clean, phase1_results = full_pipeline(df)
    st.session_state['df_ml'] = df_ml
    st.session_state['features_clean'] = features_clean
    st.session_state['phase1_results'] = phase1_results
    st.session_state['analysis_done'] = False

if st.session_state['df_ml'] is not None and not st.session_state['analysis_done']:
    df_ml = st.session_state['df_ml']
    features_clean = st.session_state['features_clean']

    feature_cols = [
        'bytes_sent', 'duration_secs',
        'if_scores', 'kde_scores', 'if_anomaly_flags', 'kde_anomaly_flags'
    ]
    xgb_model = train_xgb(df_ml, feature_cols)
    xgb_preds, pred_indices = predict_xgb(xgb_model, df_ml, feature_cols)
    df_ml['xgb_pred'] = np.nan
    df_ml.loc[pred_indices, 'xgb_pred'] = xgb_preds

    st.session_state['xgb_model'] = xgb_model
    st.session_state['df_ml'] = df_ml
    st.session_state['analysis_done'] = True

    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state['completion_time'] = completion_time

if st.session_state['df_ml'] is not None and st.session_state['analysis_done']:
    df_ml = st.session_state['df_ml']

    n_anomalies = int((df_ml['xgb_pred'] == 1).sum())
    n_total = len(df_ml)
    st.metric("Detected Anomalies", n_anomalies)
    st.metric("Total Records Analyzed", n_total)
    st.metric("Anomaly Rate (%)", round(100 * n_anomalies / n_total, 2) if n_total else 0)

    st.subheader("Anomaly Summary")
    anomaly_summary_table(df_ml)

    st.subheader("Flagged Anomalies (Top 100)")
    anomalies = df_ml[df_ml['xgb_pred'] == 1].copy()
    if not anomalies.empty:
        st.dataframe(anomalies.sort_values('if_scores', ascending=False).head(100), use_container_width=True)
        csv = anomalies.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download All Anomalies as CSV",
            data=csv,
            file_name="ipdr_anomalies.csv",
            mime="text/csv"
        )
    else:
        st.info("No anomalies detected in this file.")

    st.subheader("Visual Analytics")
    st.markdown("**Bytes Sent Distribution (Anomaly vs. Normal)**")
    fig_bytes = px.histogram(
        df_ml, x="bytes_sent", color="xgb_pred",
        nbins=50, barmode="overlay",
        color_discrete_map={0: "green", 1: "red"},
        labels={"xgb_pred": "Prediction"},
        title="Distribution of Bytes Sent"
    )
    st.plotly_chart(fig_bytes, use_container_width=True)

    st.markdown("**Session Duration Distribution (Anomaly vs. Normal)**")
    fig_dur = px.histogram(
        df_ml, x="duration_secs", color="xgb_pred",
        nbins=50, barmode="overlay",
        color_discrete_map={0: "blue", 1: "orange"},
        labels={"xgb_pred": "Prediction"},
        title="Distribution of Session Duration"
    )
    st.plotly_chart(fig_dur, use_container_width=True)

    st.markdown("**Anomaly Timeline**")
    df_ml['timestamp'] = pd.to_datetime(df_ml['timestamp'], errors='coerce')
    timeline = df_ml.groupby([pd.Grouper(key='timestamp', freq='H'), 'xgb_pred']).size().reset_index(name='count')
    fig_time = px.line(
        timeline, x="timestamp", y="count", color="xgb_pred",
        labels={"xgb_pred": "Prediction", "count": "Event Count"},
        title="Anomaly & Normal Event Timeline"
    )
    st.plotly_chart(fig_time, use_container_width=True)

    st.markdown("**Anomalies by Protocol and Action**")
    heatmap_data = df_ml[df_ml['xgb_pred'] == 1].groupby(['protocol', 'action']).size().reset_index(name='count')
    if not heatmap_data.empty:
        fig_heat = px.density_heatmap(
            heatmap_data, x='protocol', y='action', z='count',
            color_continuous_scale='Reds', title='Anomalies by Protocol and Action'
        )
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("No anomaly heatmap to display (no anomalies detected).")

    st.subheader("Baseline Comparison")
    for col in BASELINE_STATS:
        chart_df = pd.DataFrame({
            "Baseline Mean": [BASELINE_STATS[col]['mean']],
            "Current Mean": [df_ml[col].mean()]
        }, index=[col])
        st.bar_chart(chart_df)

    with st.expander("Show Raw Data (first 100 rows)"):
        st.dataframe(df_ml.head(100), use_container_width=True)

    st.success(
        f"Analysis complete at {st.session_state['completion_time']}. "
        "Use the dashboard to review, filter, and export anomaly findings."
    )
else:
    st.info("Upload a single IPDR/Firewall CSV file to begin your investigation.")