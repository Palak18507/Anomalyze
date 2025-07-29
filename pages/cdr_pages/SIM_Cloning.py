import streamlit as st
import pandas as pd
from geopy.distance import geodesic
from datetime import datetime, timedelta
from fpdf import FPDF
import tempfile
import os

# --- Page Setup ---
st.set_page_config(page_title="SIM Cloning Detection Report", layout="wide")
st.title("SIM Cloning Detection Report")
st.markdown("""
Upload a single CDR file (CSV or Excel). This analysis detects:
- IMSIs with activity in **geographically distant locations within a short time frame** (possible SIM cloning)
""")

# --- Column normalization logic ---
CDR_COLUMN_MAP = {
    "imsi": ["imsi"],
    "start_time": ["start_time", "timestamp", "date_time"],
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

def detect_sim_cloning(df, max_time_diff=timedelta(hours=1), min_distance_km=50):
    df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
    df['latitude'] = pd.to_numeric(df['latitude'], errors='coerce')
    df['longitude'] = pd.to_numeric(df['longitude'], errors='coerce')
    df = df.dropna(subset=['imsi', 'start_time', 'latitude', 'longitude'])
    suspicious_imsi = []
    for imsi, group in df.groupby('imsi'):
        group = group.sort_values('start_time')
        records = group[['start_time', 'latitude', 'longitude']].values
        for i in range(len(records)):
            for j in range(i + 1, len(records)):
                time_i, lat_i, lon_i = records[i]
                time_j, lat_j, lon_j = records[j]
                time_diff = abs(time_j - time_i)
                distance = geodesic((lat_i, lon_i), (lat_j, lon_j)).kilometers
                if time_diff <= max_time_diff and distance >= min_distance_km:
                    suspicious_imsi.append(imsi)
                    break
            if imsi in suspicious_imsi:
                break
    result_df = df[df['imsi'].isin(suspicious_imsi)].copy()
    return result_df

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(result_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="SIM Cloning Detection Report", ln=True, align='C')
    pdf.ln(10)
    if not result_df.empty:
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt="Suspicious SIM Activity", ln=True)
        pdf.set_font("Arial", size=11)
        for _, row in result_df.iterrows():
            pdf.multi_cell(0, 8, txt=safe(f"""
IMSI: {row.get('imsi', 'NA')}
Time: {row.get('start_time', 'NA')}
Latitude: {row.get('latitude', 'NA')}
Longitude: {row.get('longitude', 'NA')}
"""))
    else:
        pdf.cell(200, 10, txt="No suspicious SIM cloning activity detected.", ln=True)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'result_df' not in st.session_state:
    st.session_state['result_df'] = pd.DataFrame()
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

# --- File Upload ---
uploaded_file = st.file_uploader("Upload CDR file", type=["csv", "xlsx"])

if uploaded_file:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        df = parse_cdr(df)
        df = validate_input(df)
        result_df = detect_sim_cloning(df)
        st.session_state['df'] = df
        st.session_state['result_df'] = result_df
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    result_df = st.session_state['result_df']
    if result_df.empty:
        st.success("No suspicious SIM cloning activity detected.")
    else:
        st.warning("Suspicious SIM cloning activity detected.")
        st.subheader("Suspicious SIM Activity")
        st.dataframe(result_df[['imsi', 'start_time', 'latitude', 'longitude']])
    if not result_df.empty:
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(result_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="sim_cloning_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single CDR file to begin analysis.")