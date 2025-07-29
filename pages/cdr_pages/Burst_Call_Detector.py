import streamlit as st
import pandas as pd
import numpy as np
from scipy.stats import entropy
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import plotly.express as px
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Column normalization map ---
CDR_COLUMN_MAP = {
    "calling_number": ["calling_number", "caller"],
    "called_number": ["called_number", "callee"],
    "call_direction": ["call_direction", "direction"],
    "duration_seconds": ["duration_seconds", "duration", "callduration"],
    "start_time": ["start_time", "timestamp"],
    "end_time": ["end_time"],
    "call_status": ["call_status", "status"],
    "charge_amount": ["charge_amount", "charge", "amount"]
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

def parse_cdr(df):
    return _normalize_columns(df, CDR_COLUMN_MAP)

REQUIRED_COLUMNS = [
    "calling_number", "called_number", "start_time", "duration_seconds",
    "call_direction", "call_status", "charge_amount"
]

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="CDR"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def compute_number_behavior_features(df, time_window='1D'):
    df['start_time'] = pd.to_datetime(df['start_time'])
    df = df.sort_values(['calling_number', 'start_time'])
    df['time_bin'] = df['start_time'].dt.floor(time_window)
    features = []
    grouped = df.groupby(['calling_number', 'time_bin'])

    for (calling_number, time_bin), group in grouped:
        total_calls = len(group)
        total_duration = group['duration_seconds'].sum()
        avg_duration = group['duration_seconds'].mean()
        unique_contacts = group['called_number'].nunique()
        outgoing_calls = (group['call_direction'] == 'outgoing').sum()
        incoming_calls = (group['call_direction'] == 'incoming').sum()
        call_ratio = outgoing_calls / (incoming_calls + 1)
        contact_counts = group['called_number'].value_counts(normalize=True)
        entropy_contacts = entropy(contact_counts)
        if len(group) > 1:
            time_diffs = group['start_time'].sort_values().diff().dt.total_seconds().dropna()
            mean_time_between = time_diffs.mean()
        else:
            mean_time_between = np.nan
        failed_calls = (group['call_status'] != 'answered').sum()
        charge_total = group['charge_amount'].sum()
        features.append({
            'calling_number': calling_number,
            'time_bin': time_bin,
            'total_calls': total_calls,
            'total_duration': total_duration,
            'avg_duration': avg_duration,
            'unique_contacts': unique_contacts,
            'outgoing_calls': outgoing_calls,
            'incoming_calls': incoming_calls,
            'call_ratio': call_ratio,
            'entropy_contacts': entropy_contacts,
            'mean_time_between_calls': mean_time_between,
            'failed_calls': failed_calls,
            'charge_total': charge_total
        })

    return pd.DataFrame(features)

def detect_eps(X_scaled, min_samples):
    neighbors = NearestNeighbors(n_neighbors=min_samples)
    neighbors_fit = neighbors.fit(X_scaled)
    distances, indices = neighbors_fit.kneighbors(X_scaled)
    k_distances = np.sort(distances[:, min_samples - 1])
    diff = np.diff(k_distances)
    eps = k_distances[np.argmax(diff)] if len(diff) > 0 else 0.5
    return eps

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(features_df, outlier_numbers):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "CDR Behavioral Clustering Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Outlier Phone Numbers", ln=1)
    pdf.set_font("Arial", size=10)
    if outlier_numbers:
        for num in outlier_numbers:
            pdf.cell(0, 8, str(num), ln=1)
    else:
        pdf.cell(0, 8, "No outliers detected.", ln=1)
    pdf.ln(3)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Behavioral Feature Table (first 10 rows)", ln=1)
    pdf.set_font("Arial", size=8)
    cols = ['calling_number', 'time_bin', 'total_calls', 'total_duration', 'avg_duration',
            'unique_contacts', 'outgoing_calls', 'incoming_calls', 'call_ratio',
            'entropy_contacts', 'mean_time_between_calls', 'failed_calls', 'charge_total', 'cluster']
    for _, row in features_df[cols].head(10).iterrows():
        row_str = ", ".join([str(row[col]) for col in cols])
        pdf.cell(0, 7, safe(row_str), ln=1)
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State Preservation ---
st.set_page_config(page_title="CDR Behavioral Clustering (DBSCAN)", layout="wide")
st.title("CDR Behavioral Clustering (DBSCAN)")

st.markdown("""
Upload a single CDR file (CSV or Excel). This tool:
- Extracts behavioral features for each calling number per time window
- Clusters numbers by similar behavior and flags outliers
- Visualizes clusters and outliers
- Lists outlier numbers and their detailed records
- Generates a PDF report
""")

# Initialize session state for data and results
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'features_df' not in st.session_state:
    st.session_state['features_df'] = None
if 'result' not in st.session_state:
    st.session_state['result'] = None
if 'outlier_numbers' not in st.session_state:
    st.session_state['outlier_numbers'] = []
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_file = st.file_uploader("Upload a CDR CSV or Excel File", type=["csv", "xlsx"])
time_window = st.selectbox("Behavioral aggregation window", options=['1D', '12H', '6H', '3H'], index=0)

if uploaded_file:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        df = parse_cdr(df)
        df = validate_input(df, REQUIRED_COLUMNS, "CDR Behavioral Clustering")
        st.session_state['df'] = df
        st.session_state['analysis_done'] = False  # Reset analysis flag on new upload
    except Exception as e:
        st.error(f"Failed to read file: {e}")
        st.stop()

if st.session_state['df'] is not None and not st.session_state['analysis_done']:
    features_df = compute_number_behavior_features(st.session_state['df'], time_window=time_window)
    feature_cols = [
        'total_calls', 'total_duration', 'avg_duration', 'unique_contacts',
        'outgoing_calls', 'incoming_calls', 'call_ratio', 'entropy_contacts',
        'mean_time_between_calls', 'failed_calls', 'charge_total'
    ]
    X = features_df[feature_cols].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    n_features = X.shape[1]
    n_samples = X.shape[0]
    min_samples = min(max(2 * n_features, n_features + 1), n_samples)
    if min_samples < 2:
        min_samples = 2

    if n_samples < 2:
        st.error(f"Not enough samples ({n_samples}) for clustering. Please upload a larger dataset.")
        st.stop()

    eps = detect_eps(X_scaled, min_samples)
    dbscan = DBSCAN(eps=eps, min_samples=min_samples)
    labels = dbscan.fit_predict(X_scaled)
    features_df['cluster'] = labels
    outlier_numbers = features_df.loc[features_df['cluster'] == -1, 'calling_number'].unique().tolist()

    # PCA for visualization
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)
    features_df['pca_x'] = X_pca[:, 0]
    features_df['pca_y'] = X_pca[:, 1]

    st.session_state['features_df'] = features_df
    st.session_state['result'] = labels
    st.session_state['outlier_numbers'] = outlier_numbers
    st.session_state['analysis_done'] = True

    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state['features_df'] is not None:
    features_df = st.session_state['features_df']
    outlier_numbers = st.session_state['outlier_numbers']

    st.subheader("Cluster Map Visualization (PCA)")
    fig = px.scatter(
        features_df, x='pca_x', y='pca_y', color=features_df['cluster'].astype(str),
        hover_data=['calling_number', 'time_bin'],
        title="Phone Number Behavior Groups and Outliers (DBSCAN)",
        labels={'pca_x': 'Main Pattern', 'pca_y': 'Second Pattern', 'color': 'Cluster'}
    )
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Table of Clusters, Member Numbers, Behavioral Summary")
    st.dataframe(features_df, use_container_width=True)

    st.subheader("Outlier Phone Numbers")
    if outlier_numbers:
        st.dataframe(pd.DataFrame({'Outlier Phone Number': outlier_numbers}))
    else:
        st.success("No outlier phone numbers detected.")

    st.subheader("Details of Outlier Phone Numbers")
    outlier_details = st.session_state['df'][st.session_state['df']['calling_number'].isin(outlier_numbers)]
    if not outlier_details.empty:
        st.dataframe(outlier_details, use_container_width=True)
    else:
        st.info("No outlier details to display.")

    st.subheader("Generate PDF Report")
    if st.button("Generate PDF Report"):
        pdf_path = generate_pdf_report(features_df, outlier_numbers)
        with open(pdf_path, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f.read(),
                file_name="cdr_clustering_report.pdf",
                mime="application/pdf"
            )
        try:
            os.remove(pdf_path)
        except Exception:
            pass
else:
    st.info("Please upload a CDR file to begin analysis.")