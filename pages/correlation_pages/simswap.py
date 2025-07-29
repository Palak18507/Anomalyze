import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Column Normalization Map ---
CDR_COLUMN_MAP = {
    'calling_number': ['calling_number', 'caller', 'msisdn', 'sim', 'sim_number'],
    'imei': ['imei', 'device_id', 'device_imei'],
    'start_time': ['start_time', 'timestamp', 'time', 'date'],
    'end_time': ['end_time', 'finish_time', 'stop_time'],
    'city': ['city', 'location', 'area'],
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

# --- SIM Swap Detection Logic ---
def detect_sim_swap(cdr_df):
    imei_changes = cdr_df.groupby('calling_number')['imei'].nunique().reset_index()
    swapped_numbers = imei_changes[imei_changes['imei'] > 1]['calling_number']
    swapped_cdrs = cdr_df[cdr_df['calling_number'].isin(swapped_numbers)]
    return swapped_cdrs

# --- Map Visualization ---
def plot_swaps_on_map(result_df):
    if result_df.empty:
        st.info("No data for map visualization.")
        return
    fig = px.scatter_mapbox(
        result_df,
        lat="latitude",
        lon="longitude",
        hover_name="calling_number",
        hover_data=["imei", "city", "start_time", "end_time"],
        color="city",
        zoom=3,
        height=500
    )
    fig.update_layout(mapbox_style="open-street-map")
    fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
    st.plotly_chart(fig, use_container_width=True)

# --- PDF Report Generation ---
def generate_pdf_report(result_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "SIM Swap Detection Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Detected SIM Swaps", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(35, 8, "MSISDN", border=1, fill=True)
    pdf.cell(35, 8, "IMEI", border=1, fill=True)
    pdf.cell(40, 8, "Start Time", border=1, fill=True)
    pdf.cell(40, 8, "End Time", border=1, fill=True)
    pdf.cell(30, 8, "City", border=1, fill=True)
    pdf.ln()
    for _, row in result_df.iterrows():
        pdf.cell(35, 8, str(row['calling_number']), border=1)
        pdf.cell(35, 8, str(row['imei']), border=1)
        pdf.cell(40, 8, str(row['start_time']), border=1)
        pdf.cell(40, 8, str(row['end_time']), border=1)
        pdf.cell(30, 8, str(row['city']), border=1)
        pdf.ln()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="SIM Swap Detection Forensic Tool", layout="wide")
st.title("SIM Swap Detection Forensic Tool: Multi-File CDR Analysis")

st.markdown("""
This tool detects SIM swap events by identifying multiple IMEIs associated with the same MSISDN (SIM) across CDR logs.

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
        all_data = pd.DataFrame()
        for uploaded_file in uploaded_files:
            df = pd.read_csv(uploaded_file)
            df = parse_cdr(df)
            df = validate_input(df, REQUIRED_COLUMNS, uploaded_file.name)
            all_data = pd.concat([all_data, df], ignore_index=True)
        st.session_state['cdr_df'] = all_data
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process CDR files: {e}")
        st.stop()

    result_df = detect_sim_swap(st.session_state['cdr_df'])
    st.session_state['result_df'] = result_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"SIM Swap Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('result_df') is not None and st.session_state.get('analysis_done'):
    result_df = st.session_state['result_df']

    if not result_df.empty:
        st.error(f"SIM Swap Detected! {result_df['calling_number'].nunique()} numbers affected.")
        st.markdown("### Detected SIM Swap Records")
        st.dataframe(result_df)

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Map** | Shows flagged SIM swap events on a map by city and coordinates. |
""")

        st.subheader("SIM Swap Locations Map")
        plot_swaps_on_map(result_df)

        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(result_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="sim_swap_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass

    else:
        st.success("No SIM swap detected.")
else:
    st.info("Please upload at least two CDR files and click 'Run Detection' to begin analysis.")