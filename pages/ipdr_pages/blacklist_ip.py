import streamlit as st
import pandas as pd
import ipaddress
import requests
from fpdf import FPDF
import tempfile
import os
from datetime import datetime

# --- Page Setup ---
st.set_page_config(page_title="Blacklisted IP/Domain Detection Report", layout="wide")
st.title("Blacklisted IP/Domain Detection Report")
st.markdown("""
Upload IPDR and/or DNS log files (CSV or Excel). This analysis detects:
- **IP addresses or domains** in your logs that match known blacklists.
""")

# --- Column normalization logic ---
IPDR_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src"],
    "dest_ip": ["dest_ip", "destination_ip", "dst_ip", "dest"],
    "timestamp": ["timestamp", "time", "date_time"]
}
DNS_COLUMN_MAP = {
    "client_ip": ["client_ip", "src_ip", "source_ip"],
    "server_ip": ["server_ip", "dest_ip", "destination_ip"],
    "answer_ip": ["answer_ip", "resolved_ip", "answer"],
    "timestamp": ["timestamp", "time", "date_time"]
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

def parse_dns(df):
    return normalize_columns(df, DNS_COLUMN_MAP)

# --- Blacklist Fetching and Checking ---
def fetch_blacklisted_networks(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        st.error(f"Error fetching blacklist: {e}")
        return set()
    networks = set()
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.add(ipaddress.ip_network(line))
        except ValueError:
            pass
    return networks

def remove_private_networks(networks):
    private_ranges = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('172.16.0.0/12')
    ]
    return {net for net in networks if not any(net.overlaps(priv) for priv in private_ranges)}

def is_blacklisted(ip, blacklisted_networks, custom_blacklist):
    try:
        if pd.isnull(ip):
            return False
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in blacklisted_networks) or ip in custom_blacklist
    except ValueError:
        return False

def blacklist_analysis(df, blacklisted_networks, custom_blacklist, ip_columns):
    for col in ip_columns:
        df[f'{col}_blacklisted'] = df[col].apply(lambda x: is_blacklisted(x, blacklisted_networks, custom_blacklist))
    return df

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(ipdr_df, dns_df, ipdr_cols, dns_cols, ipdr_start, ipdr_end, dns_start, dns_end, firehol_url):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Blacklisted IP/Domain Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 10, f"Generated: {timestamp_now}", ln=1)
    pdf.cell(0, 10, f"Blacklist Source: {firehol_url}", ln=1)
    pdf.ln(5)

    def add_section(title, df, ip_columns, start_time, end_time):
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"{title} (Processed: {start_time} to {end_time})", ln=1)
        pdf.set_font("Arial", size=10)
        pdf.set_fill_color(220, 220, 220)
        headers = ["Context", "Blacklisted IP/Domain", "Time"]
        for header in headers:
            pdf.cell(60, 8, header, border=1, fill=True)
        pdf.ln()

        filtered = df[df[[f'{col}_blacklisted' for col in ip_columns]].any(axis=1)]
        for _, row in filtered.iterrows():
            for col in ip_columns:
                if row.get(f'{col}_blacklisted', False):
                    context = col
                    ip_or_domain = str(row[col])
                    timestamp = str(row.get("timestamp", "-"))
                    pdf.cell(60, 8, context, border=1)
                    pdf.cell(60, 8, ip_or_domain, border=1)
                    pdf.cell(60, 8, timestamp, border=1)
                    pdf.ln()

    if ipdr_df is not None and not ipdr_df.empty:
        add_section("IPDR Blacklisted Matches", ipdr_df, ipdr_cols, ipdr_start, ipdr_end)
        pdf.ln(5)
    if dns_df is not None and not dns_df.empty:
        add_section("DNS Blacklisted Matches", dns_df, dns_cols, dns_start, dns_end)

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Session State Initialization ---
if 'ipdr_df' not in st.session_state:
    st.session_state['ipdr_df'] = None
if 'dns_df' not in st.session_state:
    st.session_state['dns_df'] = None
if 'ipdr_cols' not in st.session_state:
    st.session_state['ipdr_cols'] = []
if 'dns_cols' not in st.session_state:
    st.session_state['dns_cols'] = []
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

# --- File Upload ---
st.info("Upload your IPDR and DNS log files (CSV or Excel) for blacklist matching.")
ipdr_file = st.file_uploader("Upload IPDR file", type=["csv", "xlsx"], key="ipdr")
dns_file = st.file_uploader("Upload DNS file", type=["csv", "xlsx"], key="dns")

# --- Blacklist Source and Custom Blacklist ---
firehol_url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
st.markdown(f"**Using blacklist dataset:** {firehol_url}")

add_custom = st.radio("Do you want to add custom blacklisted IPs?", ("No", "Yes"))
if add_custom == "Yes":
    st.header("Add Custom Blacklisted IPs")
    custom_ip_input = st.text_input("Enter IP to manually blacklist")
    if 'custom_ip_list' not in st.session_state:
        st.session_state.custom_ip_list = []
    if st.button("Add IP"):
        try:
            ipaddress.ip_address(custom_ip_input)
            if custom_ip_input not in st.session_state.custom_ip_list:
                st.session_state.custom_ip_list.append(custom_ip_input)
                st.success(f"Added {custom_ip_input}")
        except ValueError:
            st.error("Invalid IP")
custom_blacklist = set(st.session_state.get('custom_ip_list', []))

# --- Analysis ---
if ipdr_file or dns_file:
    try:
        blacklisted_networks = remove_private_networks(fetch_blacklisted_networks(firehol_url))
        ipdr_df, dns_df = None, None
        ipdr_cols, dns_cols = [], []
        ipdr_start, ipdr_end, dns_start, dns_end = "", "", "", ""
        if ipdr_file:
            if ipdr_file.name.endswith('.csv'):
                df = pd.read_csv(ipdr_file)
            else:
                df = pd.read_excel(ipdr_file)
            df = parse_ipdr(df)
            ipdr_cols = [col for col in ['src_ip', 'dest_ip'] if col in df.columns]
            ipdr_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            df = blacklist_analysis(df, blacklisted_networks, custom_blacklist, ipdr_cols)
            ipdr_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state['ipdr_df'] = df
            st.session_state['ipdr_cols'] = ipdr_cols
        if dns_file:
            if dns_file.name.endswith('.csv'):
                df = pd.read_csv(dns_file)
            else:
                df = pd.read_excel(dns_file)
            df = parse_dns(df)
            dns_cols = [col for col in ['client_ip', 'server_ip', 'answer_ip'] if col in df.columns]
            dns_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            df = blacklist_analysis(df, blacklisted_networks, custom_blacklist, dns_cols)
            dns_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.session_state['dns_df'] = df
            st.session_state['dns_cols'] = dns_cols
        st.session_state['analysis_done'] = True
        completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("----")
    except Exception as e:
        st.error(f"Error: {e}")
        st.session_state['analysis_done'] = False

if st.session_state['analysis_done']:
    ipdr_df = st.session_state.get('ipdr_df', None)
    dns_df = st.session_state.get('dns_df', None)
    ipdr_cols = st.session_state.get('ipdr_cols', [])
    dns_cols = st.session_state.get('dns_cols', [])

    st.subheader("IPDR Blacklist Matches")
    if ipdr_df is not None and not ipdr_df.empty and ipdr_cols:
        ipdr_matches = ipdr_df[ipdr_df[[f'{col}_blacklisted' for col in ipdr_cols]].any(axis=1)]
        if ipdr_matches.empty:
            st.info("No blacklisted IPs found in IPDR.")
        else:
            st.dataframe(ipdr_matches[ipdr_cols + ['timestamp']] if 'timestamp' in ipdr_matches.columns else ipdr_matches[ipdr_cols])
    else:
        st.info("No IPDR file uploaded or no relevant columns found.")

    st.subheader("DNS Blacklist Matches")
    if dns_df is not None and not dns_df.empty and dns_cols:
        dns_matches = dns_df[dns_df[[f'{col}_blacklisted' for col in dns_cols]].any(axis=1)]
        if dns_matches.empty:
            st.info("No blacklisted IPs found in DNS logs.")
        else:
            st.dataframe(dns_matches[dns_cols + ['timestamp']] if 'timestamp' in dns_matches.columns else dns_matches[dns_cols])
    else:
        st.info("No DNS file uploaded or no relevant columns found.")

    if ((ipdr_df is not None and not ipdr_df.empty and ipdr_cols) or (dns_df is not None and not dns_df.empty and dns_cols)):
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(
                ipdr_df, dns_df, ipdr_cols, dns_cols,
                ipdr_start, ipdr_end, dns_start, dns_end, firehol_url
            )
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="blacklist_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload at least one file to begin analysis.")