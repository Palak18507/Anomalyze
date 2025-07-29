import streamlit as st
import pandas as pd
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Page Setup ---
st.set_page_config(page_title="Unusual Call Hours Report", layout="wide")
st.title("Unusual Call Hours Report")
st.markdown("""
Upload a single CDR file (CSV or Excel). This analysis detects:
- Calls made **between 12:00 AM and 6:00 AM**
""")

# --- Column normalization logic ---
CDR_COLUMN_MAP = {
    "calling_number": ["calling_number", "caller"],
    "city": ["city", "location"],
    "start_time": ["start_time", "timestamp", "date_time"],
    "call_type": ["call_type", "type"],
    "call_direction": ["call_direction", "direction"]
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

def is_off_hour(dt, off_hour_start=0, off_hour_end=6):
    if pd.isnull(dt):
        return False
    hour = dt.hour
    return off_hour_start <= hour < off_hour_end

def detect_off_hour_calls(cdr_df, off_hour_start=0, off_hour_end=6):
    cdr_df['start_time'] = pd.to_datetime(cdr_df['start_time'], errors='coerce')
    off_hour_calls = cdr_df[cdr_df['start_time'].apply(lambda x: is_off_hour(x, off_hour_start, off_hour_end))].copy()
    if 'city' not in off_hour_calls.columns:
        off_hour_calls['city'] = 'NA'
    return off_hour_calls

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(off_hour_calls):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Unusual Call Hours Report", ln=True, align='C')
    pdf.ln(10)

    if not off_hour_calls.empty:
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt="Calls Between 12:00 AM and 6:00 AM", ln=True)
        pdf.set_font("Arial", size=11)
        for _, row in off_hour_calls.iterrows():
            pdf.multi_cell(0, 8, txt=safe(f"""
Caller: {row.get('calling_number', 'NA')}
City: {row.get('city', 'NA')}
Time: {row.get('start_time', 'NA')}
Type: {row.get('call_type', 'NA')}
Direction: {row.get('call_direction', 'NA')}
"""))
    else:
        pdf.cell(200, 10, txt="No off-hour calls detected.", ln=True)

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'off_hour_calls' not in st.session_state:
    st.session_state['off_hour_calls'] = pd.DataFrame()
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
        off_hour_calls = detect_off_hour_calls(df)
        st.session_state['df'] = df
        st.session_state['off_hour_calls'] = off_hour_calls
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    off_hour_calls = st.session_state['off_hour_calls']

    if off_hour_calls.empty:
        st.info("No off-hour calls detected.")
    else:
        st.subheader("Calls Between 12:00 AM and 6:00 AM")
        st.dataframe(off_hour_calls)

    if not off_hour_calls.empty:
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(off_hour_calls)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="unusual_call_hours_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single CDR file to begin analysis.")