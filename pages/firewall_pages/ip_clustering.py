import streamlit as st
import pandas as pd
import numpy as np
from scipy.stats import entropy
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import plotly.express as px
import tempfile
import os
from datetime import datetime

# --- Column Normalization Map ---
FW_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'src_port': ['src_port', 'source_port', 'sport'],
    'dst_port': ['dst_port', 'destination_port', 'dport'],
    'protocol': ['protocol', 'proto'],
    'action': ['action', 'activity'],
    'application': ['application', 'app', 'service'],
    'bytes_sent': ['bytes_sent', 'bytes', 'sent_bytes', 'data_sent'],
    'bytes_received': ['bytes_received', 'received_bytes', 'data_received'],
}

REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())

# --- Column Normalization ---
def _normalize_columns(df, column_map):
    # Create a lookup: normalized column name -> actual column name in df
    df_cols = {col.lower().replace(" ", "").replace("_", ""): col for col in df.columns}
    col_rename = {}
    for std_col, variants in column_map.items():
        found = False
        for variant in variants:
            key = variant.lower().replace(" ", "").replace("_", "")
            if key in df_cols:
                col_rename[df_cols[key]] = std_col
                found = True
                break
        if not found:
            # Column not found, will be handled in validation
            pass
    return df.rename(columns=col_rename)

def parse_firewall_log(df):
    return _normalize_columns(df, FW_COLUMN_MAP)

# --- Input Validation and Loading ---
def validate_and_load(uploaded_file):
    if uploaded_file is None:
        st.error("Please upload a firewall log CSV.")
        st.stop()
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()
    df = parse_firewall_log(df)
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    for col in ['src_port', 'dst_port', 'bytes_sent', 'bytes_received']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    return df

# --- Feature Extraction ---
def compute_ip_behavior_features(df, time_window='1H'):
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.sort_values(['src_ip', 'timestamp'])
    df['time_bin'] = df['timestamp'].dt.floor(time_window)
    grouped = df.groupby(['src_ip', 'time_bin'])
    features = []
    for (src_ip, time_bin), group in grouped:
        num_connections = len(group)
        avg_bytes_sent = group['bytes_sent'].mean()
        avg_bytes_received = group['bytes_received'].mean()
        unique_dst_ports = group['dst_port'].nunique()
        dst_ip_counts = group['dst_ip'].value_counts(normalize=True)
        entropy_dst_ip = entropy(dst_ip_counts)
        dst_port_counts = group['dst_port'].value_counts(normalize=True)
        entropy_dst_port = entropy(dst_port_counts)
        if len(group) > 1:
            time_diffs = group['timestamp'].sort_values().diff().dt.total_seconds().dropna()
            mean_time_between = time_diffs.mean()
        else:
            mean_time_between = np.nan
        features.append({
            'src_ip': src_ip,
            'time_bin': time_bin,
            'num_connections': num_connections,
            'avg_bytes_sent': avg_bytes_sent,
            'avg_bytes_received': avg_bytes_received,
            'unique_dst_ports': unique_dst_ports,
            'entropy_dst_ip': entropy_dst_ip,
            'entropy_dst_port': entropy_dst_port,
            'mean_time_between_connections': mean_time_between
        })
    return pd.DataFrame(features)

# --- DBSCAN Clustering Pipeline ---
def dbscan_firewall_pipeline_refined(df, time_window='1H'):
    features_df = compute_ip_behavior_features(df, time_window=time_window)
    feature_cols = [
        'num_connections', 'avg_bytes_sent', 'avg_bytes_received',
        'unique_dst_ports', 'entropy_dst_ip', 'entropy_dst_port',
        'mean_time_between_connections'
    ]
    X = features_df[feature_cols].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    n_features = X.shape[1]
    min_samples = max(2 * n_features, n_features + 1)
    neighbors = NearestNeighbors(n_neighbors=min_samples)
    neighbors_fit = neighbors.fit(X_scaled)
    distances, indices = neighbors_fit.kneighbors(X_scaled)
    k_distances = np.sort(distances[:, min_samples - 1])
    diff = np.diff(k_distances)
    eps = k_distances[np.argmax(diff)] if len(diff) > 0 else 0.5
    dbscan = DBSCAN(eps=eps, min_samples=min_samples)
    labels = dbscan.fit_predict(X_scaled)
    features_df['cluster'] = labels
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)
    features_df['pca_x'] = X_pca[:, 0]
    features_df['pca_y'] = X_pca[:, 1]
    outlier_ips = features_df.loc[features_df['cluster'] == -1, 'src_ip'].unique().tolist()
    return features_df, outlier_ips, eps, min_samples, n_clusters, n_noise

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Firewall Log Behavioral Clustering", layout="wide")
st.title("Firewall Log Behavioral Clustering (DBSCAN): Outlier and Group Detection")

st.markdown("""
This tool analyzes firewall logs to find behavioral outliers and clusters among source IPs using DBSCAN clustering.

**How to use:**
- Upload a firewall log CSV file.
- Select the behavioral aggregation window.
- The app will extract behavioral features, auto-tune clustering, and visualize results.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'features_df' not in st.session_state:
    st.session_state['features_df'] = None
if 'outlier_ips' not in st.session_state:
    st.session_state['outlier_ips'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_file = st.file_uploader("Upload Firewall Log CSV", type=['csv'])
time_window = st.selectbox(
    "Behavioral aggregation window",
    options=['15min', '30min', '1H', '3H', '6H', '12H', '1D'],
    index=2
)
run_analysis = st.button("Run Detection")

if run_analysis and uploaded_file:
    try:
        df = validate_and_load(uploaded_file)
        st.session_state['df'] = df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process firewall log: {e}")
        st.stop()

    features_df, outlier_ips, eps, min_samples, n_clusters, n_noise = dbscan_firewall_pipeline_refined(
        st.session_state['df'],
        time_window=time_window
    )
    st.session_state['features_df'] = features_df
    st.session_state['outlier_ips'] = outlier_ips
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Clustering analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('features_df') is not None and st.session_state.get('analysis_done'):
    features_df = st.session_state['features_df']
    outlier_ips = st.session_state['outlier_ips']

    st.header("Clustering Summary")
    st.write(f"**Auto-selected eps:** {features_df['cluster'].attrs.get('eps', 'N/A') if hasattr(features_df['cluster'], 'attrs') else 'Auto'}")
    st.write(f"**min_samples:** {features_df['cluster'].attrs.get('min_samples', 'N/A') if hasattr(features_df['cluster'], 'attrs') else 'Auto'}")
    st.write(f"**Clusters found:** {len(set(features_df['cluster'])) - (1 if -1 in features_df['cluster'].values else 0)}")
    st.write(f"**Outlier IPs:** {len(outlier_ips)}")

    st.subheader("Outlier IPs")
    if outlier_ips:
        st.dataframe(pd.DataFrame({'Outlier IP': outlier_ips}))
    else:
        st.success("No outlier IPs detected.")

    st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **PCA Scatter** | Shows clusters and outlier IPs in reduced dimensions. |
| **Feature Table** | Lists behavioral features for each src_ip and time window. |
""")

    st.subheader("IP Behavior Groups and Outliers (PCA Visualization)")
    fig = px.scatter(
        features_df, x='pca_x', y='pca_y', color=features_df['cluster'].astype(str),
        hover_data=['src_ip', 'time_bin'],
        title="IP Behavior Groups and Outliers (DBSCAN)",
        labels={'pca_x': 'Main Pattern of IP Behavior', 'pca_y': 'Second Main Pattern of IP Behavior', 'color': 'Group/Outlier'}
    )
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Behavioral Feature Table")
    st.dataframe(features_df)

    # --- CSV Export ---
    csv_path = generate_csv_report(features_df)
    with open(csv_path, "rb") as f:
        st.download_button(
            label="Download CSV Report",
            data=f.read(),
            file_name="firewall_behavioral_clustering_report.csv",
            mime="text/csv"
        )
    try:
        os.remove(csv_path)
    except Exception:
        pass

    st.markdown("""
**Interpretation:**  
- Most IPs are grouped together, showing similar network behavior.  
- Outlier IPs behave differently and may need further investigation.
""")

else:
    st.info("Please upload a firewall log file and click 'Run Detection' to begin analysis.")