import streamlit as st
import pandas as pd
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Page Setup ---
st.set_page_config(page_title="SIM Swapping Detection Report", layout="wide")
st.title("SIM Swapping Detection Report")
st.markdown("""
Upload a single CDR file (CSV or Excel). This analysis detects:
- **SIM swapping events**: Same IMEI used with multiple IMSIs, or IMSIs with highly similar call patterns
""")

# --- Column normalization logic ---
CDR_COLUMN_MAP = {
    "imsi": ["imsi"],
    "imei": ["imei"],
    "calling_number": ["calling_number", "caller"],
    "called_number": ["called_number", "callee"],
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

def generate_signature(group, interval='30min'):
    group = group.set_index('start_time')
    grouped = group.groupby(pd.Grouper(freq=interval))['called_number'].apply(list).reset_index()
    return grouped

def sim_pattern_analysis(df, interval='30min', similarity_threshold=0.6, min_matches=1):
    df_pattern = df[['imsi', 'start_time', 'calling_number', 'called_number']].dropna()
    df_pattern = df_pattern.sort_values(by=['imsi', 'start_time'])
    sim_patterns = {}
    for imsi, group in df_pattern.groupby('imsi'):
        sig = generate_signature(group, interval=interval)
        sim_patterns[imsi] = sig
    suspicious_sim_pairs = []
    imsi_list = list(sim_patterns.keys())
    for i in range(len(imsi_list)):
        for j in range(i + 1, len(imsi_list)):
            imsi_a, imsi_b = imsi_list[i], imsi_list[j]
            sig_a, sig_b = sim_patterns[imsi_a], sim_patterns[imsi_b]
            merged = pd.merge(sig_a, sig_b, on='start_time', how='inner', suffixes=('_a', '_b'))
            match_count = 0
            for _, row in merged.iterrows():
                set_a = set(row['called_number_a'])
                set_b = set(row['called_number_b'])
                if not set_a or not set_b:
                    continue
                similarity = len(set_a & set_b) / len(set_a | set_b)
                if similarity >= similarity_threshold:
                    match_count += 1
            if match_count >= min_matches:
                suspicious_sim_pairs.append({
                    'IMSI_1': imsi_a,
                    'IMSI_2': imsi_b,
                    'matching_windows': match_count
                })
    return pd.DataFrame(suspicious_sim_pairs)

def imei_swap_analysis(df):
    df_imei = df[['imei', 'imsi', 'start_time']].dropna()
    imei_to_imsis = df_imei.groupby('imei')['imsi'].nunique().reset_index(name='unique_imsis')
    multiple_imsis_same_imei = imei_to_imsis[imei_to_imsis['unique_imsis'] > 1]
    return multiple_imsis_same_imei

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(same_pattern_df, multiple_imsis_same_imei):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="SIM Swapping Detection Report", ln=True, align='C')
    pdf.ln(10)

    pdf.set_font("Arial", size=11)
    pdf.cell(200, 10, txt="Part 1: SIMs with Similar Call Patterns", ln=True)
    pdf.ln(5)
    if same_pattern_df.empty:
        pdf.cell(200, 10, txt="No suspicious SIM pairs found.", ln=True)
    else:
        for _, row in same_pattern_df.iterrows():
            pdf.cell(200, 10, txt=f"IMSI 1: {row['IMSI_1']}, IMSI 2: {row['IMSI_2']}, Matching Windows: {row['matching_windows']}", ln=True)
    pdf.ln(10)
    pdf.cell(200, 10, txt="Part 2: Same IMEI Used with Multiple SIMs", ln=True)
    pdf.ln(5)
    if multiple_imsis_same_imei.empty:
        pdf.cell(200, 10, txt="No suspicious IMEI swaps found.", ln=True)
    else:
        for _, row in multiple_imsis_same_imei.iterrows():
            pdf.cell(200, 10, txt=f"IMEI: {row['imei']}, Unique IMSIs: {row['unique_imsis']}", ln=True)

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'same_pattern_df' not in st.session_state:
    st.session_state['same_pattern_df'] = pd.DataFrame()
if 'multiple_imsis_same_imei' not in st.session_state:
    st.session_state['multiple_imsis_same_imei'] = pd.DataFrame()
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
        df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
        df = validate_input(df)
        # --- Detection with more flexible parameters ---
        same_pattern_df = sim_pattern_analysis(df, interval='30min', similarity_threshold=0.6, min_matches=1)
        multiple_imsis_same_imei = imei_swap_analysis(df)
        st.session_state['df'] = df
        st.session_state['same_pattern_df'] = same_pattern_df
        st.session_state['multiple_imsis_same_imei'] = multiple_imsis_same_imei
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    same_pattern_df = st.session_state['same_pattern_df']
    multiple_imsis_same_imei = st.session_state['multiple_imsis_same_imei']

    st.subheader("SIMs with Similar Call Patterns")
    if same_pattern_df.empty:
        st.info("No suspicious SIM pairs found.")
    else:
        st.dataframe(same_pattern_df)

    st.subheader("Same IMEI Used with Multiple SIMs")
    if multiple_imsis_same_imei.empty:
        st.info("No suspicious IMEI swaps found.")
    else:
        st.dataframe(multiple_imsis_same_imei)

    if not same_pattern_df.empty or not multiple_imsis_same_imei.empty:
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(same_pattern_df, multiple_imsis_same_imei)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="sim_swapping_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single CDR file to begin analysis.")