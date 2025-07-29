import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from fpdf import FPDF
import ipaddress
from ipwhois import IPWhois
import time
import tempfile
import os

# --- Column Normalization Map ---
FIREWALL_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'src_port': ['src_port', 'source_port', 'sport'],
    'dst_port': ['dst_port', 'destination_port', 'dport'],
    'protocol': ['protocol', 'proto'],
    'action': ['action', 'activity'],
    'application': ['application', 'app', 'service'],
}

REQUIRED_COLUMNS = list(FIREWALL_COLUMN_MAP.keys())

DEFAULT_BLACKLIST = {
    '152.32.249.95', '80.94.95.15', '41.82.74.83', '196.251.70.185', '185.156.73.234', '156.205.63.169', '79.184.34.197',
    '43.157.188.74', '206.255.248.52', '202.4.102.249', '118.193.43.244', '39.106.34.238', '194.0.234.124', '92.205.21.23',
    '60.16.221.71', '45.131.155.253', '20.169.105.96', '5.255.231.18', '80.94.95.229', '203.33.206.106', '196.251.83.249',
    '104.23.180.160', '85.208.98.18', '62.146.113.177', '20.80.83.86', '207.167.66.226', '131.106.31.52'
}
DEFAULT_THREAT_TAGS = {
    '152.32.249.95': 'Bad Reputation', '80.94.95.15': 'Malware', '41.82.74.83': 'Phishing', '196.251.70.185': 'Botnet',
    '185.156.73.234': 'Spam', '156.205.63.169': 'Ransomware', '79.184.34.197': 'Spyware', '43.157.188.74': 'Bad Reputation',
    '206.255.248.52': 'Malware', '202.4.102.249': 'Phishing', '118.193.43.244': 'Botnet', '39.106.34.238': 'Spam',
    '194.0.234.124': 'Ransomware', '92.205.21.23': 'Spyware', '60.16.221.71': 'Bad Reputation', '45.131.155.253': 'Malware',
    '20.169.105.96': 'Phishing', '5.255.231.18': 'Botnet', '80.94.95.229': 'Spam', '203.33.206.106': 'Ransomware',
    '196.251.83.249': 'Spyware', '104.23.180.160': 'Bad Reputation', '85.208.98.18': 'Malware', '62.146.113.177': 'Phishing',
    '20.80.83.86': 'Botnet', '207.167.66.226': 'Spam', '131.106.31.52': 'Ransomware'
}

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

def parse_firewall_log(df):
    return _normalize_columns(df, FIREWALL_COLUMN_MAP)

# --- Input Validation ---
def validate_input(uploaded_file, required_columns=REQUIRED_COLUMNS, file_type="csv", job_name="Firewall Log"):
    if uploaded_file is None:
        st.error(f"Please upload a file for {job_name}.")
        st.stop()
    try:
        if file_type == "csv":
            df = pd.read_csv(uploaded_file)
        elif file_type == "excel":
            df = pd.read_excel(uploaded_file)
        else:
            st.error("Unsupported file type.")
            st.stop()
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()
    df = parse_firewall_log(df)
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

# --- Analysis Functions ---
def top_frequent_ips(df, column='src_ip', top_n=10):
    freq = df[column].value_counts().nlargest(top_n)
    freq_df = freq.reset_index()
    freq_df.columns = [column, 'Count']
    if len(freq_df) < top_n:
        for _ in range(top_n - len(freq_df)):
            freq_df = pd.concat([freq_df, pd.DataFrame({column: [""], 'Count': [0]})], ignore_index=True)
    return freq_df

def check_blacklist(df, blacklist_set, column='dst_ip'):
    df = df.copy()
    df['is_blacklisted'] = df[column].isin(blacklist_set)
    blacklisted = df[df['is_blacklisted']]
    return blacklisted

def tag_threat_intel(df, threat_tag_ips, column='dst_ip'):
    df = df.copy()
    df['threat_tag'] = df[column].apply(lambda ip: threat_tag_ips.get(str(ip), ''))
    tagged = df[df['threat_tag'] != '']
    return tagged

def whois_owner(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        nets = results.get('nets', [])
        org = nets[0].get('description', '').strip() if nets else ''
        country = nets[0].get('country', '').strip() if nets else ''
        return org if org else 'N/A', country if country else 'N/A'
    except Exception:
        return 'N/A', 'N/A'

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def flag_whois_mismatch(df, column='dst_ip', org_col='expected_org', country_col='expected_country'):
    df = df.copy()
    unique_ips = df[column].unique()
    whois_data = {}
    private_ips = []
    public_ips = []
    for ip in unique_ips:
        if is_private_ip(ip):
            whois_data[ip] = {'org': 'Private', 'country': 'Private'}
            private_ips.append(ip)
        else:
            org, country = whois_owner(ip)
            whois_data[ip] = {'org': org, 'country': country}
            public_ips.append(ip)
        time.sleep(2)
    df['whois_org'] = df[column].map(lambda ip: whois_data[ip]['org'])
    df['whois_country'] = df[column].map(lambda ip: whois_data[ip]['country'])
    df['ip_type'] = df[column].map(lambda ip: 'Private' if ip in private_ips else 'Public')
    def check_mismatch(row):
        if row['ip_type'] == 'Private':
            return False
        org_mismatch = False
        country_mismatch = False
        if org_col in row and pd.notnull(row.get(org_col, None)) and str(row[org_col]).strip():
            org_mismatch = str(row[org_col]).lower() not in str(row['whois_org']).lower()
        if country_col in row and pd.notnull(row.get(country_col, None)) and str(row[country_col]).strip():
            country_mismatch = str(row['whois_country']).upper() != str(row[country_col]).upper()
        return org_mismatch or country_mismatch
    df['whois_mismatch'] = df.apply(check_mismatch, axis=1)
    mismatches = df[(df['whois_mismatch']) & (df['ip_type'] == 'Public')]
    if not mismatches.empty:
        for ip in mismatches['dst_ip'].unique():
            org, country = whois_owner(ip)
            df.loc[(df['dst_ip'] == ip) & (df['whois_mismatch']), 'whois_org'] = org if org else 'N/A'
            df.loc[(df['dst_ip'] == ip) & (df['whois_mismatch']), 'whois_country'] = country if country else 'N/A'
    return mismatches, private_ips

def generate_pdf_report(freq_src, freq_dst, blacklisted, threat_tagged, mismatches):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "IP Analysis Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Top Most Frequent Source IPs", ln=1)
    pdf.set_font("Arial", "", 10)
    for _, row in freq_src.iterrows():
        pdf.cell(0, 8, f"{row['src_ip']}: {row['Count']}", ln=1)
    pdf.ln(2)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Top Most Frequent Destination IPs", ln=1)
    pdf.set_font("Arial", "", 10)
    for _, row in freq_dst.iterrows():
        pdf.cell(0, 8, f"{row['dst_ip']}: {row['Count']}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Connections to Blacklisted IPs", ln=1)
    pdf.set_font("Arial", "", 9)
    if not blacklisted.empty:
        for _, row in blacklisted.iterrows():
            pdf.cell(0, 7, f"{row['dst_ip']} | Src: {row['src_ip']} | Time: {row['timestamp']} | Action: {row.get('action', '')}", ln=1)
    else:
        pdf.cell(0, 7, "No connections to blacklisted IPs detected.", ln=1)
    pdf.ln(3)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Threat Intel Tagged Connections", ln=1)
    pdf.set_font("Arial", "", 9)
    if not threat_tagged.empty:
        for _, row in threat_tagged.iterrows():
            pdf.cell(0, 7, f"{row['dst_ip']} | Src: {row['src_ip']} | Time: {row['timestamp']} | Tag: {row['threat_tag']}", ln=1)
    else:
        pdf.cell(0, 7, "No threat-tagged connections detected.", ln=1)
    pdf.ln(3)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "WHOIS Mismatches", ln=1)
    pdf.set_font("Arial", "", 9)
    if not mismatches.empty:
        for _, row in mismatches.iterrows():
            pdf.cell(0, 7, f"{row['dst_ip']} | Src: {row['src_ip']} | Time: {row['timestamp']} | Org: {row.get('whois_org', '')} | Country: {row.get('whois_country', '')}", ln=1)
    else:
        pdf.cell(0, 7, "No WHOIS mismatches detected.", ln=1)
    pdf.ln(3)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="IP Analysis Forensic Tool", layout="wide")
st.title("IP Analysis Forensic Tool: Firewall Log Investigation")

st.markdown("""
This tool analyzes firewall logs for frequent IPs, blacklists, threat tags, and WHOIS mismatches.

**How to use:**
- Upload a firewall log CSV file.
- Choose custom or default blacklists/threat tags.
- Review flagged IPs, visualizations, and download a PDF report.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'freq_src' not in st.session_state:
    st.session_state['freq_src'] = None
if 'freq_dst' not in st.session_state:
    st.session_state['freq_dst'] = None
if 'blacklisted' not in st.session_state:
    st.session_state['blacklisted'] = None
if 'threat_tagged' not in st.session_state:
    st.session_state['threat_tagged'] = None
if 'mismatches' not in st.session_state:
    st.session_state['mismatches'] = None
if 'private_ips' not in st.session_state:
    st.session_state['private_ips'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

fw_file = st.file_uploader("Upload Firewall Log CSV", type=['csv'])
run_analysis = st.button("Run Detection")

if run_analysis and fw_file:
    try:
        df = validate_input(fw_file, REQUIRED_COLUMNS, "csv", "Firewall Log")
        st.session_state['df'] = df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process firewall log: {e}")
        st.stop()

    top_n = st.number_input("How many frequent IPs do you want to see?", min_value=1, max_value=100, value=10, step=1)
    custom_ip_choice = st.radio(
        "Would you like to provide your own blacklisted and bad reputation IPs?",
        ("No, use default sets", "Yes, I want to provide my own IPs"),
        index=0
    )

    if custom_ip_choice == "No, use default sets":
        st.warning("No custom blacklist provided. Using default blacklist set for analysis.")
        st.warning("No custom bad reputation IPs provided. Using default threat tag set for analysis.")
        blacklist_set = DEFAULT_BLACKLIST
        threat_tag_ips = DEFAULT_THREAT_TAGS
    else:
        st.markdown("**Enter Blacklisted IPs (one per line):**")
        user_blacklist_text = st.text_area("Blacklisted IPs", height=100)
        blacklist_set = set(ip.strip() for ip in user_blacklist_text.splitlines() if ip.strip())
        st.markdown("**Enter Bad Reputation IPs (ip:tag, one per line):**")
        user_threat_tag_text = st.text_area("Bad Reputation IPs", height=100)
        threat_tag_ips = {}
        for line in user_threat_tag_text.splitlines():
            if ':' in line:
                ip, tag = line.split(':', 1)
                threat_tag_ips[ip.strip()] = tag.strip()
        if not blacklist_set:
            st.warning("No custom blacklist provided. Using default blacklist set for analysis.")
            blacklist_set = DEFAULT_BLACKLIST
        if not threat_tag_ips:
            st.warning("No custom bad reputation IPs provided. Using default threat tag set for analysis.")
            threat_tag_ips = DEFAULT_THREAT_TAGS

    freq_src = top_frequent_ips(df, 'src_ip', top_n=top_n)
    freq_dst = top_frequent_ips(df, 'dst_ip', top_n=top_n)
    st.session_state['freq_src'] = freq_src
    st.session_state['freq_dst'] = freq_dst

    st.subheader(f"Top {top_n} Most Frequent Source IPs")
    st.dataframe(freq_src)
    fig_src = px.bar(freq_src, x='src_ip', y='Count', title=f'Top {top_n} Source IPs (Appearance Count)')
    fig_src.update_yaxes(dtick=1, tickformat=',d')
    st.plotly_chart(fig_src, use_container_width=True)

    st.subheader(f"Top {top_n} Most Frequent Destination IPs")
    st.dataframe(freq_dst)
    fig_dst = px.bar(freq_dst, x='dst_ip', y='Count', title=f'Top {top_n} Destination IPs (Appearance Count)')
    fig_dst.update_yaxes(dtick=1, tickformat=',d')
    st.plotly_chart(fig_dst, use_container_width=True)

    blacklisted = check_blacklist(df, blacklist_set, column='dst_ip')
    st.session_state['blacklisted'] = blacklisted
    st.subheader("Connections to Blacklisted Destination IPs")
    if not blacklisted.empty:
        st.dataframe(blacklisted[['dst_ip', 'src_ip', 'timestamp', 'action']])
    else:
        st.success("No connections to blacklisted IPs detected.")

    threat_tagged = tag_threat_intel(df, threat_tag_ips, column='dst_ip')
    st.session_state['threat_tagged'] = threat_tagged
    st.subheader("Connections to Bad Reputation/Threat-Tagged IPs")
    if not threat_tagged.empty:
        st.dataframe(threat_tagged[['dst_ip', 'src_ip', 'timestamp', 'action', 'threat_tag']])
    else:
        st.success("No threat-tagged connections detected.")

    mismatches, private_ips = flag_whois_mismatch(df, column='dst_ip', org_col='expected_org', country_col='expected_country')
    st.session_state['mismatches'] = mismatches
    st.session_state['private_ips'] = private_ips
    st.subheader("WHOIS Mismatch Detection (Public Destination IPs)")
    if not mismatches.empty:
        st.dataframe(mismatches[['dst_ip', 'src_ip', 'timestamp', 'action', 'whois_org', 'whois_country']])
    else:
        st.success("No WHOIS mismatches detected for public IPs.")
    if private_ips:
        st.info(f"Private IPs (WHOIS not applicable): {', '.join(private_ips)}")

    st.subheader("Flagged IPs by Category")
    map_records = []
    for _, row in blacklisted.iterrows():
        map_records.append({'ip': row['dst_ip'], 'type': 'Blacklisted'})
    for _, row in threat_tagged.iterrows():
        map_records.append({'ip': row['dst_ip'], 'type': 'Bad Reputation'})
    for _, row in mismatches.iterrows():
        map_records.append({'ip': row['dst_ip'], 'type': 'WHOIS Mismatch'})
    if map_records:
        map_df = pd.DataFrame(map_records)
        fig = px.histogram(map_df, x="type", color="type", title="Flagged IPs by Category")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No flagged IPs to display on map.")

    st.subheader("Download PDF Report")
    if st.button("Generate PDF Report"):
        pdf_file = generate_pdf_report(freq_src, freq_dst, blacklisted, threat_tagged, mismatches)
        with open(pdf_file, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name="ip_analysis_report.pdf",
                mime="application/pdf"
            )
        st.success("PDF report generated and ready for download.")

else:
    st.info("Please upload a firewall log file and click 'Run Detection' to begin analysis.")