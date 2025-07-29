import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
from geopy.geocoders import Nominatim
import tempfile
import os
from datetime import datetime

# --- Column Normalization Map ---
CDR_COLUMN_MAP = {
    'calling_number': ['calling_number', 'caller', 'sim', 'sim_number'],
    'start_time': ['start_time', 'timestamp', 'time', 'date'],
    'latitude': ['latitude', 'lat'],
    'longitude': ['longitude', 'lon', 'lng'],
}

REQUIRED_COLUMNS = list(CDR_COLUMN_MAP.keys())

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

def parse_cdr(df):
    return _normalize_columns(df, CDR_COLUMN_MAP)

# --- Input Validation ---
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Helper: Reverse geocode latitude/longitude to region/city using geopy ---
def get_region_from_latlon(lat, lon, geolocator, geocode_cache):
    key = (round(float(lat), 3), round(float(lon), 3))
    if key in geocode_cache:
        return geocode_cache[key]
    try:
        location = geolocator.reverse((lat, lon), language='en', exactly_one=True, timeout=10)
        region = location.raw['address'].get('city', None) or \
                 location.raw['address'].get('town', None) or \
                 location.raw['address'].get('state', None) or \
                 location.raw['address'].get('country', 'Unknown')
        geocode_cache[key] = region
        return region
    except Exception:
        geocode_cache[key] = 'Unknown'
        return 'Unknown'

# --- SIM Reuse Geo-based Anomaly Detection Logic ---
def detect_sim_reuse_anomaly(all_cdr_df, time_window_minutes=60):
    all_cdr_df['start_time'] = pd.to_datetime(all_cdr_df['start_time'], errors='coerce')
    all_cdr_df = all_cdr_df.sort_values(['calling_number', 'start_time'])
    geolocator = Nominatim(user_agent="cdr_geoip")
    geocode_cache = {}
    all_cdr_df['region'] = all_cdr_df.apply(
        lambda row: get_region_from_latlon(row['latitude'], row['longitude'], geolocator, geocode_cache)
        if not pd.isnull(row['latitude']) and not pd.isnull(row['longitude']) else 'Unknown', axis=1
    )
    anomalies = []
    for sim, sim_df in all_cdr_df.groupby('calling_number'):
        sim_df = sim_df.sort_values('start_time')
        prev_row = None
        for idx, row in sim_df.iterrows():
            if prev_row is not None:
                time_diff = (row['start_time'] - prev_row['start_time']).total_seconds() / 60.0
                if (row['region'] != prev_row['region'] and
                    time_diff <= time_window_minutes and
                    row['region'] != 'Unknown' and prev_row['region'] != 'Unknown'):
                    anomalies.append({
                        'SIM': sim,
                        'Region1': prev_row['region'],
                        'Time1': prev_row['start_time'],
                        'Region2': row['region'],
                        'Time2': row['start_time'],
                        'AnomalyEvidence': f"SIM used in {prev_row['region']} at {prev_row['start_time']} and in {row['region']} at {row['start_time']} within {int(time_diff)} min"
                    })
            prev_row = row
    result_df = pd.DataFrame(anomalies)
    return result_df

# --- Visualization: Map (symbolic, since we don't have region coordinates) ---
def plot_anomalies_on_map(anomaly_df):
    if anomaly_df.empty:
        st.info("No data for map visualization.")
        return
    map_data = []
    for _, row in anomaly_df.iterrows():
        map_data.append({'SIM': row['SIM'], 'Region': row['Region1'], 'Time': row['Time1'], 'AnomalyEvidence': row['AnomalyEvidence']})
        map_data.append({'SIM': row['SIM'], 'Region': row['Region2'], 'Time': row['Time2'], 'AnomalyEvidence': row['AnomalyEvidence']})
    map_df = pd.DataFrame(map_data)
    fig = px.scatter(
        map_df,
        x="Region",
        y="SIM",
        color="Region",
        hover_data=["Time", "AnomalyEvidence"],
        symbol="Region",
        title="SIM Reuse Anomalies Across Regions"
    )
    st.plotly_chart(fig, use_container_width=True)

# --- Visualization: Timeline (Gantt-style) ---
def plot_anomalies_timeline(anomaly_df):
    if anomaly_df.empty:
        st.info("No data for timeline visualization.")
        return
    timeline_data = []
    for _, row in anomaly_df.iterrows():
        timeline_data.append({
            "SIM": row['SIM'],
            "Region": row['Region1'],
            "Start": row['Time1'],
            "Finish": row['Time2'],
            "AnomalyEvidence": row['AnomalyEvidence']
        })
    timeline_df = pd.DataFrame(timeline_data)
    fig = px.timeline(
        timeline_df,
        x_start="Start",
        x_end="Finish",
        y="SIM",
        color="Region",
        hover_data=["AnomalyEvidence"]
    )
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(title="Timeline of SIM Reuse Across Regions")
    st.plotly_chart(fig, use_container_width=True)

# --- PDF Report Generation ---
def generate_pdf_report(anomaly_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "SIM Reuse Geo-based Anomaly Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Detected SIM Reuse Anomalies", ln=1)
    pdf.set_font("Arial", "", 9)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(25, 7, "SIM", border=1, fill=True)
    pdf.cell(25, 7, "Region1", border=1, fill=True)
    pdf.cell(30, 7, "Time1", border=1, fill=True)
    pdf.cell(25, 7, "Region2", border=1, fill=True)
    pdf.cell(30, 7, "Time2", border=1, fill=True)
    pdf.cell(55, 7, "Anomaly Evidence", border=1, fill=True)
    pdf.ln()
    for _, row in anomaly_df.iterrows():
        pdf.cell(25, 7, str(row['SIM']), border=1)
        pdf.cell(25, 7, str(row['Region1']), border=1)
        pdf.cell(30, 7, str(row['Time1']), border=1)
        pdf.cell(25, 7, str(row['Region2']), border=1)
        pdf.cell(30, 7, str(row['Time2']), border=1)
        pdf.cell(55, 7, str(row['AnomalyEvidence'])[:45], border=1)
        pdf.ln()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="SIM Reuse Geo-based Anomaly Detector", layout="wide")
st.title("SIM Reuse Geo-based Anomaly Detector: Multi-File CDR Analysis")

st.markdown("""
This tool detects SIM reuse anomalies across different regions in a short time window using CDR data.

**How to use:**
- Upload two or more CDR log CSV files.
- Click "Run Detection" to analyze and visualize results.
""")

if 'cdr_df' not in st.session_state:
    st.session_state['cdr_df'] = None
if 'result_df' not in st.session_state:
    st.session_state['result_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_files = st.file_uploader(
    "Upload two or more CDR CSV files", type=["csv"], accept_multiple_files=True
)
run_analysis = st.button("Run Detection")

if run_analysis and uploaded_files and len(uploaded_files) >= 2:
    try:
        all_cdr = pd.DataFrame()
        for uploaded_file in uploaded_files:
            df = pd.read_csv(uploaded_file)
            df = parse_cdr(df)
            df = validate_input(df, REQUIRED_COLUMNS, uploaded_file.name)
            all_cdr = pd.concat([all_cdr, df], ignore_index=True)
        st.session_state['cdr_df'] = all_cdr
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process CDR files: {e}")
        st.stop()

    result_df = detect_sim_reuse_anomaly(
        st.session_state['cdr_df'],
        time_window_minutes=60
    )
    st.session_state['result_df'] = result_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Geo-based SIM Reuse Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('result_df') is not None and st.session_state.get('analysis_done'):
    result_df = st.session_state['result_df']

    if not result_df.empty:
        st.error(f"SIM Reuse Anomalies Detected! {result_df.shape[0]} events flagged.")
        st.markdown("### SIM Reuse Anomaly Records")
        st.dataframe(result_df)

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Map** | Shows flagged SIM reuse anomalies across regions. |
| **Timeline** | Displays the sequence of SIM reuse anomalies over time. |
""")

        st.subheader("SIM Reuse Anomalies Map")
        plot_anomalies_on_map(result_df)

        st.subheader("Timeline of SIM Reuse Anomalies")
        plot_anomalies_timeline(result_df)

        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(result_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="sim_reuse_geoanomaly_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass

    else:
        st.success("No SIM reuse anomalies detected.")
else:
    st.info("Please upload at least two CDR files and click 'Run Detection' to begin analysis.")