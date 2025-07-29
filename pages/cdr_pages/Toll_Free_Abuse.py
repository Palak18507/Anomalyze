import streamlit as st
import pandas as pd
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Page Setup ---
st.set_page_config(page_title="Toll-Free Abuse Detection Report", layout="wide")
st.title("Toll-Free Abuse Detection Report")
st.markdown("""
Upload a single CDR file (CSV or Excel). This analysis detects:
- Callers making **excessive calls to toll-free numbers (e.g., 1800/1860/800) per day**
""")

# --- Column normalization logic ---
CDR_COLUMN_MAP = {
    "calling_number": ["calling_number", "caller"],
    "called_number": ["called_number", "callee"],
    "call_direction": ["call_direction", "direction"],
    "start_time": ["start_time", "timestamp", "date_time"]
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

def analyze_toll_free_abuse(df, abuse_threshold=5):
    # Normalize and filter toll-free calls
    df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
    df['call_direction'] = df['call_direction'].astype(str).str.upper()
    df['called_number'] = df['called_number'].astype(str)
    tollfree_prefixes = ('1800', '1860', '800')
    tollfree_calls = df[
        (df['call_direction'] == 'MO') &
        (df['called_number'].str.startswith(tollfree_prefixes))
    ].copy()
    tollfree_calls['call_date'] = tollfree_calls['start_time'].dt.date
    # Abuse detection: callers with > threshold toll-free calls per day
    daily_counts = tollfree_calls.groupby(['calling_number', 'call_date']).size().reset_index(name='call_count')
    abusive_users = daily_counts[daily_counts['call_count'] > abuse_threshold]
    # Top toll-free numbers overall
    top_tollfree_numbers = tollfree_calls['called_number'].value_counts().head(10).reset_index()
    top_tollfree_numbers.columns = ['called_number', 'times_called']
    return abusive_users, top_tollfree_numbers

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(abusive_users, top_tollfree_numbers, abuse_threshold):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Toll-Free Abuse Detection Report", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", size=11)
    pdf.cell(200, 10, txt=f"Abuse Threshold: > {abuse_threshold} calls/day", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(200, 10, txt="Frequent Toll-Free Callers", ln=True)
    pdf.set_font("Arial", size=11)
    if abusive_users.empty:
        pdf.cell(200, 10, txt="No abusive users detected.", ln=True)
    else:
        for _, row in abusive_users.iterrows():
            pdf.multi_cell(0, 8, txt=safe(f"""
Caller: {row['calling_number']}
Date: {row['call_date']}
Toll-Free Calls: {row['call_count']}
"""))

    pdf.ln(5)
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(200, 10, txt="Top Toll-Free Numbers Called", ln=True)
    pdf.set_font("Arial", size=11)
    if top_tollfree_numbers.empty:
        pdf.cell(200, 10, txt="No toll-free calls detected.", ln=True)
    else:
        for _, row in top_tollfree_numbers.iterrows():
            pdf.cell(200, 8, txt=f"{row['called_number']}: {row['times_called']} times", ln=True)

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'abusive_users' not in st.session_state:
    st.session_state['abusive_users'] = pd.DataFrame()
if 'top_tollfree_numbers' not in st.session_state:
    st.session_state['top_tollfree_numbers'] = pd.DataFrame()
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

# --- File Upload ---
uploaded_file = st.file_uploader("Upload CDR file", type=["csv", "xlsx"])

abuse_threshold = st.number_input("Abuse threshold (calls per day)", min_value=1, max_value=100, value=5)

if uploaded_file:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        df = parse_cdr(df)
        df = validate_input(df)
        abusive_users, top_tollfree_numbers = analyze_toll_free_abuse(df, abuse_threshold)
        st.session_state['df'] = df
        st.session_state['abusive_users'] = abusive_users
        st.session_state['top_tollfree_numbers'] = top_tollfree_numbers
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    abusive_users = st.session_state['abusive_users']
    top_tollfree_numbers = st.session_state['top_tollfree_numbers']

    if abusive_users.empty:
        st.info("No Toll-Free Abuse Detected.")
    else:
        st.subheader("Frequent Toll-Free Callers")
        st.dataframe(abusive_users)

    st.subheader("Top Toll-Free Numbers Called")
    st.dataframe(top_tollfree_numbers)

    if not abusive_users.empty or not top_tollfree_numbers.empty:
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(abusive_users, top_tollfree_numbers, abuse_threshold)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="toll_free_abuse_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single CDR file to begin analysis.")