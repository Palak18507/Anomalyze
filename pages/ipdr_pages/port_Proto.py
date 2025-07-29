import streamlit as st
import pandas as pd
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Column normalization logic ---
IPDR_COLUMN_MAP = {
    "protocol": ["protocol"],
    "dest_port": ["dest_port", "destination_port", "port","dst_port"],
    "src_ip": ["src_ip", "source_ip"],
    "dest_ip": ["dest_ip", "destination_ip", "dst_ip"],
    "flow_start_time": ["flow_start_time", "timestamp", "date_time", "start_time"]
}

# Normalizing function

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


def parse_ipdr(df):
    return _normalize_columns(df, IPDR_COLUMN_MAP)


# --- Page Setup ---
st.set_page_config(page_title="Protocol-Port Anomaly Detection Report", layout="wide")
st.title("Protocol-Port Anomaly Detection Report")
st.markdown("""
Upload a single IPDR file (CSV or Excel). This analysis detects:
- **Protocol/port mismatches** (e.g., HTTP on non-standard port)
""")

# --- Standard Protocol/Port Definitions ---
STANDARD_PORTS = {
    'SSH': [22],
    'SFTP': [22],
    'HTTPS': [443],
    'HTTP': [80],
    'FTP': [21],
    'FTPS': [989, 990],
    'TELNET': [23],
    'SMTP': [25, 465, 587],
    'SMTPS': [465],
    'DNS': [53],
    'DoT': [853],
    'DoH': [443],
    'RDP': [3389],
    'IMAPS': [993],
    'POP3S': [995],
    'MYSQL': [3306],
    'POSTGRESQL': [5432],
    'MONGODB': [27017],
    'LDAPS': [636],
    'KERBEROS': [88],
    'OPENVPN': [1194],
    'IPSEC-IKE': [500],
    'IPSEC-NAT-T': [4500],
}

# --- Column normalization logic ---
IPDR_COLUMN_MAP = {
    "protocol": ["protocol"],
    "dest_port": ["dest_port", "destination_port", "port"],
    "src_ip": ["src_ip", "source_ip"],
    "dest_ip": ["dest_ip", "destination_ip"],
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

REQUIRED_COLUMNS = list(IPDR_COLUMN_MAP.keys())

def validate_input(df, required_columns=REQUIRED_COLUMNS):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def normalize_proto(proto):
    return str(proto).strip().upper()

def is_anomalous_protocol_port(row):
    proto = normalize_proto(row['protocol'])
    try:
        port = int(row['dest_port'])
    except Exception:
        return False
    if proto in STANDARD_PORTS and port not in STANDARD_PORTS[proto]:
        return True
    return False

def protocol_port_anomaly_analysis(df):
    df['flow_start_time'] = pd.to_datetime(df['flow_start_time'], errors='coerce')
    df['protocol_port_anomaly'] = df.apply(is_anomalous_protocol_port, axis=1)
    anomalies = df[df['protocol_port_anomaly']].copy()
    anomalies['evidence'] = anomalies.apply(
        lambda row: f"{row['protocol']} used on non-standard port {row['dest_port']}", axis=1
    )
    return anomalies

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(anomalies_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Protocol-Port Anomaly Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)

    if anomalies_df.empty:
        pdf.cell(0, 10, "No protocol/port anomalies detected.", ln=1)
    else:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Anomalies", ln=1)
        pdf.set_font("Arial", size=10)
        for _, row in anomalies_df.iterrows():
            pdf.multi_cell(0, 8, txt=safe(f"""
Protocol: {row['protocol']}
Dest Port: {row['dest_port']}
Source IP: {row['src_ip']}
Dest IP: {row['dest_ip']}
Evidence: {row['evidence']}
"""))
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'anomalies_df' not in st.session_state:
    st.session_state['anomalies_df'] = pd.DataFrame()
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

# --- File Upload ---
uploaded_file = st.file_uploader("Upload IPDR file", type=["csv", "xlsx"])

if uploaded_file:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        df = parse_ipdr(df)
        df = validate_input(df)
        anomalies_df = protocol_port_anomaly_analysis(df)
        st.session_state['df'] = df
        st.session_state['anomalies_df'] = anomalies_df
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    anomalies_df = st.session_state['anomalies_df']
    if anomalies_df.empty:
        st.info("No protocol/port anomalies detected.")
    else:
        st.subheader("Protocol-Port Anomalies")
        st.dataframe(anomalies_df[['protocol', 'dest_port', 'src_ip', 'dest_ip', 'evidence']])
    if not anomalies_df.empty:
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(anomalies_df)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="protocol_port_anomalies_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a single IPDR file to begin analysis.")