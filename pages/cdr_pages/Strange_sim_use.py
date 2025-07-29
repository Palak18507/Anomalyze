import streamlit as st
import pandas as pd
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Column normalization logic ---
CDR_COLUMN_MAP = {
    "cdr_id": ["cdrid", "cdr_id"],
    "calling_number": ["callingnumber", "caller", "msisdn"],
    "called_number": ["callednumber", "callee", "dst"],
    "imsi": ["imsi"],
    "imei": ["imei"],
    "start_time": ["start_time", "starttime", "timestamp"],
    "end_time": ["end_time", "endtime", "end"],
    "duration_seconds": ["duration_seconds", "duration", "callduration"],
    "call_type": ["calltype", "call_type"],
    "call_direction": ["direction", "call_direction"],
    "call_status": ["status", "call_status"],
    "tower_id": ["towerid", "tower_id"],
    "lac": ["lac"],
    "cell_id": ["cellid", "cell_id"],
    "latitude": ["latitude", "lat"],
    "longitude": ["longitude", "lon"],
    "city": ["city", "city_name"],
    "network_type": ["networktype", "network_type"],
    "roaming_status": ["roamingstatus", "roaming_status"],
    "operator": ["operator", "operator_name"],
    "billing_type": ["billingtype", "billing_type"],
    "charge_amount": ["charge", "charge_amount"],
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

REQUIRED_COLUMNS = [
    'calling_number', 'called_number', 'call_direction', 'start_time'
]

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Job"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def excessive_international_calls_analysis(df, threshold=5):
    international_calls = df[
        (df['call_direction'] == 'MO') &
        (~df['called_number'].astype(str).str.startswith('91'))
    ]
    call_counts = international_calls.groupby('calling_number').size().reset_index(name='international_call_count')
    suspicious_numbers = call_counts[call_counts['international_call_count'] > threshold]
    return suspicious_numbers

def generate_pdf_report(suspicious_numbers_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Excessive International Callers Report", ln=True, align='C')
    pdf.ln(10)
    if suspicious_numbers_df.empty:
        pdf.cell(200, 10, txt="No numbers with excessive international outgoing calls found.", ln=True)
    else:
        for idx, row in suspicious_numbers_df.iterrows():
            pdf.cell(200, 10, txt=f"Number: {row['calling_number']}, Calls: {row['international_call_count']}", ln=True)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit Layout with Session State ---
st.title("Excessive International Outgoing Call Detection")

# Initialize session state variables
if 'uploaded_file' not in st.session_state:
    st.session_state['uploaded_file'] = None
if 'result' not in st.session_state:
    st.session_state['result'] = None
if 'pdf_path' not in st.session_state:
    st.session_state['pdf_path'] = None
if 'completion_time' not in st.session_state:
    st.session_state['completion_time'] = None
if 'threshold' not in st.session_state:
    st.session_state['threshold'] = 5

# User input widgets
uploaded_file = st.file_uploader("Upload CDR CSV or Excel File", type=["csv", "xlsx"], key='file_uploader')
threshold = st.number_input("Threshold for excessive calls", min_value=1, max_value=100, value=st.session_state['threshold'], key='threshold_input')

if uploaded_file is not None:
    st.session_state['uploaded_file'] = uploaded_file
    st.session_state['threshold'] = threshold
    try:
        file_type = "csv" if uploaded_file.name.endswith(".csv") else "excel"
        df = pd.read_csv(uploaded_file) if file_type == "csv" else pd.read_excel(uploaded_file)
        df = parse_cdr(df)
        if 'start_time' in df.columns:
            df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
        df = validate_input(df, REQUIRED_COLUMNS)
        result = excessive_international_calls_analysis(df, threshold)
        st.session_state['result'] = result
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state['completion_time'] = completion_time
        pdf_path = generate_pdf_report(result)
        st.session_state['pdf_path'] = pdf_path
    except Exception as e:
        st.error(f"Error processing file: {e}")

# Display results from session state if available
if st.session_state['result'] is not None:
    st.success(f"International Call Analysis completed at {st.session_state['completion_time']}")
    st.write("----")
    if st.session_state['result'].empty:
        st.info("No numbers with excessive international outgoing calls found.")
    else:
        st.write("Numbers with excessive international outgoing calls:")
        st.dataframe(st.session_state['result'])
        st.bar_chart(st.session_state['result'].set_index('calling_number')['international_call_count'])

    if st.session_state['pdf_path'] and os.path.exists(st.session_state['pdf_path']):
        with open(st.session_state['pdf_path'], "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name="excessive_international_calls_report.pdf",
                mime="application/pdf"
            )
        # Optionally, you can remove the PDF after download if desired
        # os.remove(st.session_state['pdf_path'])