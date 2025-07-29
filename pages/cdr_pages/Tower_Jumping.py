import streamlit as st
import pandas as pd
import math
from datetime import datetime
from fpdf import FPDF
import tempfile
import os

# --- Page Setup ---
st.set_page_config(page_title="Tower Jumping Detection Report", layout="wide")
st.title("Tower Jumping Detection Report")
st.markdown("""
Upload a single CDR file (CSV or Excel). This analysis detects:
- **Tower jumping events**: Same IMSI seen at distant towers within a short time frame (e.g., >10 km in ≤5 minutes)
""")

# --- Column normalization logic ---
CDR_COLUMN_MAP = {
    "imsi": ["imsi"],
    "start_time": ["start_time", "timestamp", "date_time"],
    "cell_id": ["cell_id", "cellid"],
    "tower_id": ["tower_id", "towerid"],
    "latitude": ["latitude", "lat"],
    "longitude": ["longitude", "lon", "lng"]
}

def normalize_columns(df, column_map):
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
    return normalize_columns(df, CDR_COLUMN_MAP)

REQUIRED_COLUMNS = list(CDR_COLUMN_MAP.keys())

def validate_input(df, required_columns=REQUIRED_COLUMNS):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def haversine(lat1, lon1, lat2, lon2):
    R = 6371  # Earth radius in kilometers
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(d_lambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

DISTANCE_THRESHOLD_KM = 10
TIME_THRESHOLD_MINUTES = 5

def detect_tower_jumping(df, distance_km=DISTANCE_THRESHOLD_KM, time_min=TIME_THRESHOLD_MINUTES):
    df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
    df['latitude'] = pd.to_numeric(df['latitude'], errors='coerce')
    df['longitude'] = pd.to_numeric(df['longitude'], errors='coerce')
    df = df.dropna(subset=['imsi', 'start_time', 'latitude', 'longitude', 'cell_id'])
    anomalies = []
    for imsi, group in df.groupby('imsi'):
        group = group.sort_values('start_time')
        prev_row = None
        for idx, row in group.iterrows():
            if prev_row is not None:
                try:
                    time_diff = (row['start_time'] - prev_row['start_time']).total_seconds() / 60
                    dist_km = haversine(prev_row['latitude'], prev_row['longitude'], row['latitude'], row['longitude'])
                    if time_diff <= time_min and dist_km >= distance_km:
                        anomalies.append({
                            'imsi': imsi,
                            'start_time': row['start_time'],
                            'from_cell': prev_row['cell_id'],
                            'to_cell': row['cell_id'],
                            'distance_km': round(dist_km, 2),
                            'time_diff_min': round(time_diff, 2)
                        })
                except Exception:
                    continue
            prev_row = row
    return pd.DataFrame(anomalies)

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(anomalies_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Tower Jumping Detection Report", ln=True, align='C')
    pdf.ln(10)
    if anomalies_df.empty:
        pdf.cell(200, 10, txt="No tower jumping anomalies detected.", ln=True)
    else:
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt="Tower Jumping Events", ln=True)
        pdf.set_font("Arial", size=11)
        for _, row in anomalies_df.iterrows():
            pdf.multi_cell(0, 8, txt=safe(f"""
IMSI: {row['imsi']}
Time: {row['start_time']}
From Cell: {row['from_cell']} -> To Cell: {row['to_cell']}
Distance: {row['distance_km']} km
Time Diff: {row['time_diff_min']} mins
"""))
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'anomalies_df' not in st.session_state:
    st.session_state['anomalies_df'] = pd.DataFrame()
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

# --- File Upload ---
uploaded_file = st.file_uploader("Upload CDR file", type=["csv", "xlsx"])

distance_km = st.number_input("Distance threshold (km)", min_value=1, max_value=100, value=10)
time_min = st.number_input("Time threshold (minutes)", min_value=1, max_value=60, value=5)

if uploaded_file:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        df = parse_cdr(df)
        df = validate_input(df)
        anomalies_df = detect_tower_jumping(df, distance_km, time_min)
        st.session_state['df'] = df
        st.session_state['anomalies_df'] = anomalies_df
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    anomalies_df = st.session_state['anomalies_df']
    if anomalies_df.empty:
        st.info("No tower jumping anomalies detected.")
    else:
        st.subheader("Tower Jumping Events")
        st.dataframe(anomalies_df)
    if not anomalies_df.empty:
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(anomalies_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="tower_jumping_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single CDR file to begin analysis.")