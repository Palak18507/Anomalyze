import streamlit as st
import pandas as pd
from fpdf import FPDF
import tempfile
import os

# --- Column normalization logic ---

CDR_COLUMN_MAP = {
    "calling_number": ["calling_number", "caller"],
    "called_number": ["called_number", "callee"],
    "start_time": ["start_time", "timestamp"],
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

REQUIRED_COLUMNS = ['calling_number', 'called_number', 'start_time', 'call_direction']

def validate_input(df, required_columns=REQUIRED_COLUMNS):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def analyze(df):
    outgoing_df = df[df['call_direction'] == 'MO'].copy()
    intl_calls = outgoing_df[~outgoing_df['called_number'].astype(str).str.startswith('91')]
    intl_counts = intl_calls.groupby('calling_number').size().reset_index(name='international_call_count')
    intl_suspects = intl_counts[intl_counts['international_call_count'] > 5]
    outgoing_df['hour_window'] = outgoing_df['start_time'].dt.floor('H')
    call_spikes = outgoing_df.groupby(['calling_number', 'hour_window']).size().reset_index(name='calls_in_hour')
    spike_suspects = call_spikes[call_spikes['calls_in_hour'] > 10]
    return intl_suspects, spike_suspects

def generate_pdf_report(file_name, intl_suspects, spike_suspects):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="CDR Outgoing Call Analysis Report", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(200, 10, txt=f"File: {file_name}", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", size=11)
    pdf.cell(200, 10, txt="Part 1: Excessive International Outgoing Calls", ln=True)
    if intl_suspects.empty:
        pdf.cell(200, 10, txt="No excessive international callers found.", ln=True)
    else:
        for _, row in intl_suspects.iterrows():
            pdf.cell(200, 10, txt=f"{row['calling_number']}: {row['international_call_count']} calls", ln=True)
    pdf.ln(5)
    pdf.cell(200, 10, txt="Part 2: Sudden Spike in Outgoing Calls", ln=True)
    if spike_suspects.empty:
        pdf.cell(200, 10, txt="No sudden spikes detected.", ln=True)
    else:
        for _, row in spike_suspects.iterrows():
            pdf.cell(200, 10, txt=f"{row['calling_number']} at {row['hour_window']}: {row['calls_in_hour']} calls", ln=True)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

def run_analysis():
    st.title("CDR Outgoing Call Analysis")

    # Initialize session state for persistence
    if 'uploaded_file' not in st.session_state:
        st.session_state.uploaded_file = None
    if 'intl_suspects' not in st.session_state:
        st.session_state.intl_suspects = None
    if 'spike_suspects' not in st.session_state:
        st.session_state.spike_suspects = None
    if 'pdf_path' not in st.session_state:
        st.session_state.pdf_path = None

    uploaded_file = st.file_uploader("Upload CDR CSV or Excel File", type=["csv", "xlsx"], key='file_uploader')

    # If a new file is uploaded, process it and store results in session state
    if uploaded_file is not None:
        st.session_state.uploaded_file = uploaded_file
        df = pd.read_csv(uploaded_file) if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file)
        df = parse_cdr(df)
        if 'start_time' in df.columns:
            df['start_time'] = pd.to_datetime(df['start_time'], errors='coerce')
        df = validate_input(df)
        intl_suspects, spike_suspects = analyze(df)
        st.session_state.intl_suspects = intl_suspects
        st.session_state.spike_suspects = spike_suspects
        st.session_state.pdf_path = generate_pdf_report(uploaded_file.name, intl_suspects, spike_suspects)

    # If session state has data, show it (even after navigation away and back)
    if st.session_state.uploaded_file is not None:
        st.success("CDR Outgoing Call Analysis Completed")
        st.write("----")
        st.subheader("Part 1: Excessive International Outgoing Calls")
        if st.session_state.intl_suspects is None or st.session_state.intl_suspects.empty:
            st.info("No excessive international callers found.")
        else:
            st.dataframe(st.session_state.intl_suspects)

        st.subheader("Part 2: Sudden Spike in Outgoing Calls")
        if st.session_state.spike_suspects is None or st.session_state.spike_suspects.empty:
            st.info("No sudden spikes in outgoing calls found.")
        else:
            st.dataframe(st.session_state.spike_suspects)

        if st.session_state.pdf_path is not None and os.path.exists(st.session_state.pdf_path):
            with open(st.session_state.pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f,
                    file_name="CDR_outgoing_analysis_report.pdf",
                    mime="application/pdf"
                )

run_analysis()