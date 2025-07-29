import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Column Normalization Maps ---
CDR_COLUMN_MAP = {
    'calling_number': ['calling_number', 'caller', 'number'],
    'city': ['city', 'location', 'area'],
    'start_time': ['start_time', 'timestamp', 'time', 'date'],
    'call_type': ['call_type', 'type'],
    'call_direction': ['call_direction', 'direction']
}
FW_COLUMN_MAP = {
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'timestamp': ['timestamp', 'time', 'date'],
    'protocol': ['protocol', 'proto'],
    'action': ['action', 'activity']
}
CDR_REQUIRED_COLUMNS = list(CDR_COLUMN_MAP.keys())
FW_REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())

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

def parse_firewall_log(df):
    return _normalize_columns(df, FW_COLUMN_MAP)

# --- Input Validation ---
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Helper: Off-hour Detection ---
def is_off_hour(dt, off_hour_start=0, off_hour_end=5):
    hour = dt.hour
    if off_hour_start < off_hour_end:
        return off_hour_start <= hour < off_hour_end
    else:
        # Handles wrap-around (e.g., 22-4)
        return hour >= off_hour_start or hour < off_hour_end

# --- Off-hour Access Detection ---
def detect_off_hour_access(all_cdr_df, all_fw_df, off_hour_start=0, off_hour_end=5):
    all_cdr_df['start_time'] = pd.to_datetime(all_cdr_df['start_time'], errors='coerce')
    all_fw_df['timestamp'] = pd.to_datetime(all_fw_df['timestamp'], errors='coerce')

    cdr_off = all_cdr_df[all_cdr_df['start_time'].apply(lambda x: is_off_hour(x, off_hour_start, off_hour_end))].copy()
    cdr_off['event_type'] = 'CDR Call'
    cdr_off['event_time'] = cdr_off['start_time']
    cdr_off['context'] = cdr_off['city']

    fw_off = all_fw_df[all_fw_df['timestamp'].apply(lambda x: is_off_hour(x, off_hour_start, off_hour_end))].copy()
    fw_off['event_type'] = 'Firewall Log'
    fw_off['event_time'] = fw_off['timestamp']
    fw_off['context'] = fw_off['src_ip']

    cdr_events = cdr_off[['event_type', 'event_time', 'calling_number', 'context', 'city', 'start_time', 'call_type', 'call_direction']]
    fw_events = fw_off[['event_type', 'event_time', 'src_ip', 'context', 'dst_ip', 'timestamp', 'protocol', 'action']]
    cdr_events.columns = ['event_type', 'event_time', 'entity', 'context', 'location', 'time', 'type', 'direction']
    fw_events.columns = ['event_type', 'event_time', 'entity', 'context', 'location', 'time', 'type', 'direction']

    combined = pd.concat([cdr_events, fw_events], ignore_index=True)
    combined = combined.sort_values('event_time')
    return combined

# --- Heatmap Visualization ---
def plot_off_hour_heatmap(events_df):
    if events_df.empty:
        st.info("No data for heatmap.")
        return
    events_df['hour'] = pd.to_datetime(events_df['event_time'], errors='coerce').dt.hour
    heatmap_data = events_df.groupby(['hour', 'event_type']).size().reset_index(name='count')
    fig = px.density_heatmap(
        heatmap_data,
        x='hour',
        y='event_type',
        z='count',
        color_continuous_scale='Reds',
        title='Off-hour Access Patterns Heatmap'
    )
    st.plotly_chart(fig, use_container_width=True)

# --- PDF Report Generation ---
def generate_pdf_report(events_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Off-hour Access Patterns Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Detected Off-hour Events", ln=1)
    pdf.set_font("Arial", "", 9)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(25, 7, "Event Type", border=1, fill=True)
    pdf.cell(30, 7, "Entity", border=1, fill=True)
    pdf.cell(32, 7, "Time", border=1, fill=True)
    pdf.cell(30, 7, "Context", border=1, fill=True)
    pdf.cell(30, 7, "Location", border=1, fill=True)
    pdf.cell(30, 7, "Type/Proto", border=1, fill=True)
    pdf.cell(20, 7, "Dir/Action", border=1, fill=True)
    pdf.ln()
    for _, row in events_df.iterrows():
        pdf.cell(25, 7, str(row['event_type']), border=1)
        pdf.cell(30, 7, str(row['entity']), border=1)
        pdf.cell(32, 7, str(row['event_time']), border=1)
        pdf.cell(30, 7, str(row['context']), border=1)
        pdf.cell(30, 7, str(row['location']), border=1)
        pdf.cell(30, 7, str(row['type']), border=1)
        pdf.cell(20, 7, str(row['direction']), border=1)
        pdf.ln()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Off-hour Access Pattern Detector", layout="wide")
st.title("Off-hour Access Pattern Detector: CDR & Firewall Log Analysis")

st.markdown("""
This tool detects off-hour (late-night) access patterns from CDR and firewall logs.

**How to use:**
- Upload one or more CDR and firewall log CSV files.
- Adjust off-hour range in the sidebar.
- Click "Run Detection" to analyze and visualize results.
""")

if 'cdr_df' not in st.session_state:
    st.session_state['cdr_df'] = None
if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'events_df' not in st.session_state:
    st.session_state['events_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

cdr_files = st.file_uploader(
    "Upload CDR CSV files", type=["csv"], accept_multiple_files=True
)
fw_files = st.file_uploader(
    "Upload Firewall Log CSV files", type=["csv"], accept_multiple_files=True
)
st.sidebar.header("Detection Parameters")
off_hour_start = st.sidebar.number_input("Off-hour Start (hour)", min_value=0, max_value=23, value=0)
off_hour_end = st.sidebar.number_input("Off-hour End (hour)", min_value=1, max_value=24, value=5)
run_analysis = st.button("Run Detection")

if run_analysis and cdr_files and fw_files:
    try:
        cdr_dfs = []
        for file in cdr_files:
            df = pd.read_csv(file)
            df = parse_cdr(df)
            df = validate_input(df, CDR_REQUIRED_COLUMNS, file.name)
            cdr_dfs.append(df)
        cdr_df = pd.concat(cdr_dfs, ignore_index=True)
        st.session_state['cdr_df'] = cdr_df

        fw_dfs = []
        for file in fw_files:
            df = pd.read_csv(file)
            df = parse_firewall_log(df)
            df = validate_input(df, FW_REQUIRED_COLUMNS, file.name)
            fw_dfs.append(df)
        fw_df = pd.concat(fw_dfs, ignore_index=True)
        st.session_state['fw_df'] = fw_df

        events_df = detect_off_hour_access(
            st.session_state['cdr_df'],
            st.session_state['fw_df'],
            off_hour_start=off_hour_start,
            off_hour_end=off_hour_end
        )
        st.session_state['events_df'] = events_df
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("---")
    except Exception as e:
        st.error(f"Failed to process files: {e}")
        st.stop()

if st.session_state.get('events_df') is not None and st.session_state.get('analysis_done'):
    events_df = st.session_state['events_df']

    if events_df.empty:
        st.success("No off-hour access patterns detected.")
    else:
        st.error(f"Off-hour Events Detected! {events_df.shape[0]} events flagged.")
        st.markdown("### Off-hour Events Table")
        st.dataframe(events_df)

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Off-hour Access Heatmap** | Shows the distribution of off-hour events by hour and event type. |
""")

        st.subheader("Off-hour Access Heatmap")
        plot_off_hour_heatmap(events_df)

        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(events_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="off_hour_access_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass

else:
    st.info("Please upload CDR and firewall log files and click 'Run Detection' to begin analysis.")