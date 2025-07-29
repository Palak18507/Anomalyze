import streamlit as st
import pandas as pd
import socket
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Page Setup ---
st.set_page_config(page_title="Frequent Domain/IP Access Report", layout="wide")
st.title("Frequent Domain/IP Access Report")
st.markdown("""
Upload a single IPDR file (CSV or Excel). This analysis detects:
- **Most frequently accessed domains or IPs** in your data
""")

# --- Column normalization logic ---
IPDR_COLUMN_MAP = {
    "dest_ip": ["dest_ip", "destination_ip", "dst_ip"],
    "destination_domain": ["destination_domain", "domain", "host"],
    "flow_start_time": ["flow_start_time", "timestamp", "date_time", "start_time"]
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

def parse_ipdr(df):
    return normalize_columns(df, IPDR_COLUMN_MAP)

REQUIRED_COLUMNS = ["dest_ip", "flow_start_time"]

def validate_input(df, required_columns=REQUIRED_COLUMNS):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def get_domain_name(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except Exception:
        return None

def analyze_frequent_access(df, top_n=10):
    if "destination_domain" in df.columns and df["destination_domain"].notnull().any():
        freq = df["destination_domain"].value_counts()
        mode = "Domain"
    else:
        freq = df["dest_ip"].value_counts()
        mode = "IP"
    return freq, mode

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(freq, mode, top_n=10, reverse_lookup=None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Frequent Domain/IP Access Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 10, f"Generated: {timestamp}", ln=1)
    pdf.cell(0, 10, f"Top {top_n} Most Accessed {mode}s", ln=1)
    pdf.ln(5)

    pdf.set_font("Arial", size=10)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(80, 8, f"{mode}", border=1, fill=True)
    pdf.cell(40, 8, "Access Count", border=1, fill=True)
    pdf.ln()
    for label, count in freq.head(top_n).items():
        pdf.cell(80, 8, str(label), border=1)
        pdf.cell(40, 8, str(count), border=1)
        pdf.ln()

    if reverse_lookup:
        pdf.ln(8)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Reverse DNS Lookup Results", ln=1)
        pdf.set_font("Arial", size=10)
        pdf.set_fill_color(220, 220, 220)
        pdf.cell(80, 8, "IP Address", border=1, fill=True)
        pdf.cell(80, 8, "Domain Name", border=1, fill=True)
        pdf.ln()
        for ip, domain in reverse_lookup:
            pdf.cell(80, 8, str(ip), border=1)
            pdf.cell(80, 8, str(domain), border=1)
            pdf.ln()

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'freq' not in st.session_state:
    st.session_state['freq'] = None
if 'mode' not in st.session_state:
    st.session_state['mode'] = None
if 'reverse_lookup' not in st.session_state:
    st.session_state['reverse_lookup'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

# --- File Upload ---
uploaded_file = st.file_uploader("Upload IPDR file", type=["csv", "xlsx"])
top_n = st.number_input("Show top N entries", min_value=1, max_value=100, value=10)

if uploaded_file:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        df = parse_ipdr(df)
        df = validate_input(df)
        freq, mode = analyze_frequent_access(df, top_n)
        reverse_lookup = None
        if mode == "IP":
            reverse_lookup = []
            for ip in freq.head(top_n).index:
                domain = get_domain_name(ip)
                reverse_lookup.append((ip, domain if domain else "[No domain found]"))
        st.session_state['df'] = df
        st.session_state['freq'] = freq
        st.session_state['mode'] = mode
        st.session_state['reverse_lookup'] = reverse_lookup
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    freq = st.session_state['freq']
    mode = st.session_state['mode']
    reverse_lookup = st.session_state['reverse_lookup']

    if freq is None or freq.empty:
        st.info("No frequent access entries detected.")
    else:
        st.subheader(f"Top {top_n} Most Frequently Accessed {mode}s")
        st.dataframe(freq.head(top_n).rename_axis(mode).reset_index(name="Access Count"))

        if mode == "IP" and reverse_lookup:
            st.subheader("Reverse DNS Lookup for Top IPs")
            st.dataframe(pd.DataFrame(reverse_lookup, columns=["IP", "Domain"]))

    if freq is not None and not freq.empty:
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(freq, mode, top_n, reverse_lookup if mode == "IP" else None)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="frequent_access_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single IPDR file to begin analysis.")