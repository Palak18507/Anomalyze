import streamlit as st
import pandas as pd
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Page Setup ---
st.set_page_config(page_title="Call Failure & Common Callee Report", layout="wide")
st.title("Call Failure & Common Callee Report")

st.markdown("""
Upload a single CDR file (CSV or Excel). This analysis detects:
-  Callers with **3 or more failed attempts**
-  Numbers called **5 or more times**
""")

# --- Column normalization logic ---
CDR_COLUMN_MAP = {
    "calling_number": ["calling_number", "caller"],
    "called_number": ["called_number", "callee"],
    "call_status": ["call_status", "status"],
    "start_time": ["start_time", "timestamp"],
    "end_time": ["end_time"]
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

REQUIRED_COLUMNS = ['calling_number', 'called_number', 'call_status', 'start_time', 'end_time']

def validate_input(df, required_columns=REQUIRED_COLUMNS):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def analyze_failures_and_callees(cdr_df):
    cdr_df['start_time'] = pd.to_datetime(cdr_df['start_time'], errors='coerce')
    cdr_df['end_time'] = pd.to_datetime(cdr_df['end_time'], errors='coerce')
    cdr_df['call_status'] = cdr_df['call_status'].astype(str)

    failed_calls = cdr_df[cdr_df['call_status'].str.upper() != 'ANSWERED']
    repeated_failures = failed_calls.groupby('calling_number').agg(
        failed_attempts=('call_status', 'count'),
        first_failed_call=('start_time', 'min'),
        last_failed_call=('end_time', 'max')
    ).reset_index()
    repeated_failures = repeated_failures[repeated_failures['failed_attempts'] >= 3]

    common_callees = cdr_df.groupby('called_number').agg(
        total_times_called=('calling_number', 'count'),
        unique_callers=('calling_number', 'nunique'),
        first_time_called=('start_time', 'min'),
        last_time_called=('end_time', 'max')
    ).reset_index()
    common_callees = common_callees[common_callees['total_times_called'] >= 5]
    common_callees = common_callees.sort_values(by='total_times_called', ascending=False)

    return repeated_failures, common_callees

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(repeated_failures, common_callees):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Call Failure & Common Callee Report", ln=True, align='C')
    pdf.ln(10)

    if not repeated_failures.empty:
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt="Repeated Call Failures", ln=True)
        pdf.set_font("Arial", size=11)
        for _, row in repeated_failures.iterrows():
            pdf.multi_cell(0, 8, txt=safe(f"""
Caller: {row['calling_number']}
Failed Attempts: {row['failed_attempts']}
First Failed Call: {row['first_failed_call']}
Last Failed Call: {row['last_failed_call']}
"""))

    if not common_callees.empty:
        pdf.ln(5)
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt="Common Callees (Frequently Called)", ln=True)
        pdf.set_font("Arial", size=11)
        for _, row in common_callees.iterrows():
            pdf.multi_cell(0, 8, txt=safe(f"""
Callee: {row['called_number']}
Times Called: {row['total_times_called']}
Unique Callers: {row['unique_callers']}
First Time Called: {row['first_time_called']}
Last Time Called: {row['last_time_called']}
"""))

    if repeated_failures.empty and common_callees.empty:
        pdf.cell(200, 10, txt="No suspicious behavior found.", ln=True)

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'repeated_failures' not in st.session_state:
    st.session_state['repeated_failures'] = pd.DataFrame()
if 'common_callees' not in st.session_state:
    st.session_state['common_callees'] = pd.DataFrame()
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
        repeated_failures, common_callees = analyze_failures_and_callees(df)

        st.session_state['df'] = df
        st.session_state['repeated_failures'] = repeated_failures
        st.session_state['common_callees'] = common_callees
        st.session_state['analysis_done'] = True

        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    repeated_failures = st.session_state['repeated_failures']
    common_callees = st.session_state['common_callees']

    if repeated_failures.empty:
        st.info("No repeated call failures detected.")
    else:
        st.subheader("Repeated Call Failures")
        st.dataframe(repeated_failures)

    if common_callees.empty:
        st.info("No common callees detected.")
    else:
        st.subheader("Frequently Called Numbers")
        st.dataframe(common_callees)

    if (not repeated_failures.empty or not common_callees.empty):
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(repeated_failures, common_callees)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="call_failure_common_callees_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single CDR file to begin analysis.")