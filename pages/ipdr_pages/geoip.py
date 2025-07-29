import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from fpdf import FPDF
import tempfile
import os

# --- Configuration ---
OFAC_BLOCKED_COUNTRIES = {'CU', 'IR', 'KP', 'RU', 'SY', 'BY', 'VE'}
EXPECTED_COUNTRIES = {'IN', 'US', 'GB', 'SG', 'AE', 'CA', 'AU'}
SUSPICIOUS_REGISTRARS = {'Bizcn', 'NameSilo', 'AlibabaCloud', 'Eranet'}
RECENT_DAYS = 15
NEAR_EXPIRY_DAYS = 15
DATACENTER_KEYWORDS = [
    'Amazon', 'AWS', 'Google', 'Microsoft', 'Azure', 'DigitalOcean', 'OVH',
    'Hetzner', 'Linode', 'Vultr', 'Alibaba', 'Tencent', 'LeaseWeb', 'Contabo',
    'GoDaddy', 'Oracle', 'Cloudflare', 'Hivelocity', 'InterServer', 'Rackspace',
    'SoftLayer', 'DreamHost', 'HostGator', 'Bluehost', 'G-Core', 'Scaleway'
]

# --- Input Validation ---
def validate_input(uploaded_file, required_columns=None, file_type="csv", job_name="Job"):
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
    if required_columns:
        missing = [col for col in required_columns if col not in df.columns]
        if missing:
            st.error(f"Missing required columns: {missing}")
            st.stop()
    return df

# --- Anomaly Detection Functions ---
def detect_country_mismatch(row):
    if pd.isnull(row['country']) or pd.isnull(row['registrant_country']):
        return 'unknown'
    return 'yes' if row['country'].strip().upper() != row['registrant_country'].strip().upper() else 'no'

def enrich_ipdr(ipdr_df, geoip_df, expected_countries, ofac_blocked, datacenter_keywords):
    ipdr_df['dest_ip'] = ipdr_df['dest_ip'].astype(str)
    geoip_df['ip'] = geoip_df['ip'].astype(str)
    ipdr_df = ipdr_df.merge(geoip_df, left_on='dest_ip', right_on='ip', how='left')
    ipdr_df['unexpected_country'] = ipdr_df['country'].apply(lambda c: 'yes' if pd.notnull(c) and c not in expected_countries else 'no')
    ipdr_df['datacenter_ip'] = ipdr_df['organization'].apply(lambda org: 'yes' if any(k in str(org) for k in datacenter_keywords) else 'no')
    ipdr_df['policy_violation'] = ipdr_df['country'].apply(lambda c: 'yes' if c in ofac_blocked else 'no')
    ipdr_df['enrichment_missing'] = ipdr_df['country'].apply(lambda c: 'yes' if pd.isnull(c) else 'no')
    return ipdr_df

def impossible_travel_flag(ipdr_df):
    ipdr_df = ipdr_df.sort_values(['user_id', 'flow_start_time'])
    ipdr_df['prev_latitude'] = ipdr_df.groupby('user_id')['latitude'].shift(1)
    ipdr_df['prev_longitude'] = ipdr_df.groupby('user_id')['longitude'].shift(1)
    ipdr_df['prev_time'] = ipdr_df.groupby('user_id')['flow_start_time'].shift(1)
    ipdr_df['time_diff_hr'] = (ipdr_df['flow_start_time'] - ipdr_df['prev_time']).dt.total_seconds() / 3600
    def haversine_np(lat1, lon1, lat2, lon2):
        lat1, lat2, lon1, lon2 = map(np.radians, [lat1, lat2, lon1, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = np.sin(dlat/2.0)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2.0)**2
        c = 2 * np.arcsin(np.sqrt(a))
        return 6371 * c
    ipdr_df['distance_km'] = haversine_np(
        ipdr_df['latitude'], ipdr_df['longitude'],
        ipdr_df['prev_latitude'], ipdr_df['prev_longitude']
    )
    ipdr_df['impossible_travel'] = (
        (ipdr_df['distance_km'] > 1000) &
        (ipdr_df['time_diff_hr'] < 2) &
        ipdr_df['distance_km'].notnull() &
        ipdr_df['time_diff_hr'].notnull()
    )
    ipdr_df.drop(['prev_latitude', 'prev_longitude', 'prev_time', 'time_diff_hr', 'distance_km'], axis=1, inplace=True)
    return ipdr_df

def enrich_dns(dns_df, whois_df, geoip_df):
    dns_df['query_name'] = dns_df['query_name'].astype(str)
    whois_df['domain'] = whois_df['domain'].astype(str)
    geoip_df['ip'] = geoip_df['ip'].astype(str)
    dns_df = dns_df.merge(whois_df, left_on='query_name', right_on='domain', how='left')
    dns_df = dns_df.merge(geoip_df[['ip', 'country']], left_on='answer_ip', right_on='ip', how='left', suffixes=('', '_geo'))
    dns_df['country_mismatch'] = dns_df.apply(detect_country_mismatch, axis=1)
    return dns_df

def whois_anomalies(row, current_date, recent_days, near_expiry_days, suspicious_registrars):
    anomalies = []
    if pd.notnull(row['registration_date']) and (current_date - row['registration_date']) <= timedelta(days=recent_days):
        anomalies.append("recent_registration")
    if pd.notnull(row['expiry_date']) and row['expiry_date'] < current_date:
        anomalies.append("expired")
    elif pd.notnull(row['expiry_date']) and (row['expiry_date'] - current_date) <= timedelta(days=near_expiry_days):
        anomalies.append("near_expiry")
    if str(row['registrar']).strip() in suspicious_registrars:
        anomalies.append("suspicious_registrar")
    return ", ".join(anomalies) if anomalies else None

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf(ipdr_sample, dns_sample, cols):
    path = tempfile.mktemp(suffix=".pdf")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "GeoIP & WHOIS Anomaly Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(10)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "IPDR Sample Anomalies", ln=1)
    pdf.set_font("Arial", size=10)
    for _, row in ipdr_sample.iterrows():
        pdf.cell(0, 8, f"User: {row['user_id']} | IP: {row['dest_ip']} | Issues: {', '.join([col for col in cols if row[col]=='yes'])}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "WHOIS Sample Anomalies", ln=1)
    pdf.set_font("Arial", size=10)
    for _, row in dns_sample.iterrows():
        issues = row['whois_anomalies'] if pd.notnull(row['whois_anomalies']) else ''
        if row['country_mismatch'] == 'yes':
            issues += ', country_mismatch'
        pdf.cell(0, 8, f"Domain: {row['query_name']} | Anomalies: {issues.strip(', ')}", ln=1)
    pdf.output(path)
    return path

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="GeoIP & WHOIS Anomaly Detection", layout="wide")
st.title("GeoIP & WHOIS Anomaly Detection (Multi-File, Repeat Calls Workflow)")

st.markdown("""
This tool detects anomalies in IPDR, DNS, GEOIP, and WHOIS datasets, including:
- Unexpected or OFAC-blocked countries
- Datacenter IPs
- Policy violations
- Impossible travel events
- Suspicious registrar or domain expiry
- Country mismatches between WHOIS and GEOIP

**How to use:**
- Upload one or more CSV files for each required data type (IPDR, DNS, GEOIP, WHOIS).
- Click "Run Detection" to analyze and visualize results.
""")

if 'ipdr_df' not in st.session_state:
    st.session_state['ipdr_df'] = None
if 'dns_df' not in st.session_state:
    st.session_state['dns_df'] = None
if 'geoip_df' not in st.session_state:
    st.session_state['geoip_df'] = None
if 'whois_df' not in st.session_state:
    st.session_state['whois_df'] = None
if 'ipdr_sample' not in st.session_state:
    st.session_state['ipdr_sample'] = None
if 'dns_sample' not in st.session_state:
    st.session_state['dns_sample'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

ipdr_files = st.file_uploader(
    "Upload one or more IPDR CSV files", type=["csv"], accept_multiple_files=True, key="ipdr"
)
dns_files = st.file_uploader(
    "Upload one or more DNS CSV files", type=["csv"], accept_multiple_files=True, key="dns"
)
geoip_files = st.file_uploader(
    "Upload one or more GEOIP CSV files", type=["csv"], accept_multiple_files=True, key="geoip"
)
whois_files = st.file_uploader(
    "Upload one or more WHOIS CSV files", type=["csv"], accept_multiple_files=True, key="whois"
)
run_analysis = st.button("Run Detection")

if run_analysis and ipdr_files and dns_files and geoip_files and whois_files:
    # Load and validate all files
    all_ipdr = pd.DataFrame()
    for f in ipdr_files:
        df = validate_input(f, required_columns=['user_id', 'dest_ip', 'flow_start_time', 'latitude', 'longitude'], file_type="csv", job_name="IPDR")
        all_ipdr = pd.concat([all_ipdr, df], ignore_index=True)
    all_dns = pd.DataFrame()
    for f in dns_files:
        df = validate_input(f, required_columns=['client_ip', 'query_name', 'answer_ip'], file_type="csv", job_name="DNS")
        all_dns = pd.concat([all_dns, df], ignore_index=True)
    all_geoip = pd.DataFrame()
    for f in geoip_files:
        df = validate_input(f, required_columns=['ip', 'country', 'organization', 'latitude', 'longitude'], file_type="csv", job_name="GEOIP")
        all_geoip = pd.concat([all_geoip, df], ignore_index=True)
    all_whois = pd.DataFrame()
    for f in whois_files:
        df = validate_input(f, required_columns=['domain', 'registration_date', 'expiry_date', 'registrar', 'registrant_country'], file_type="csv", job_name="WHOIS")
        all_whois = pd.concat([all_whois, df], ignore_index=True)

    # Convert dates
    all_ipdr['flow_start_time'] = pd.to_datetime(all_ipdr['flow_start_time'], errors='coerce')
    all_whois['registration_date'] = pd.to_datetime(all_whois['registration_date'], errors='coerce')
    all_whois['expiry_date'] = pd.to_datetime(all_whois['expiry_date'], errors='coerce')

    # Enrich and detect anomalies
    all_geoip = all_geoip.drop_duplicates('ip')
    ipdr_df = enrich_ipdr(all_ipdr, all_geoip, EXPECTED_COUNTRIES, OFAC_BLOCKED_COUNTRIES, DATACENTER_KEYWORDS)
    ipdr_df = impossible_travel_flag(ipdr_df)
    dns_df = enrich_dns(all_dns, all_whois, all_geoip)
    current_date = datetime.now()
    dns_df['whois_anomalies'] = dns_df.apply(lambda row: whois_anomalies(row, current_date, RECENT_DAYS, NEAR_EXPIRY_DAYS, SUSPICIOUS_REGISTRARS), axis=1)

    st.session_state['ipdr_df'] = ipdr_df
    st.session_state['dns_df'] = dns_df
    st.session_state['geoip_df'] = all_geoip
    st.session_state['whois_df'] = all_whois

    cols = ['unexpected_country', 'datacenter_ip', 'policy_violation', 'enrichment_missing', 'impossible_travel']
    ipdr_sample = ipdr_df[cols + ['user_id', 'dest_ip']].head(10)
    dns_sample = dns_df[['client_ip', 'query_name', 'whois_anomalies', 'country_mismatch']].dropna().head(10)
    st.session_state['ipdr_sample'] = ipdr_sample
    st.session_state['dns_sample'] = dns_sample
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"GeoIP & WHOIS Anomaly Detection completed at {completion_time}")
    st.write("---")

if st.session_state.get('analysis_done'):
    st.markdown("### 📌 IPDR Anomalies (sample):")
    st.dataframe(st.session_state['ipdr_sample'])

    st.markdown("### 📌 DNS/WHOIS Anomalies (sample):")
    st.dataframe(st.session_state['dns_sample'])

    if st.session_state['ipdr_sample'].empty and st.session_state['dns_sample'].empty:
        st.success("✅ No suspicious anomalies detected in provided datasets.")

    if st.button("Generate PDF Report"):
        pdf_path = generate_pdf(st.session_state['ipdr_sample'], st.session_state['dns_sample'], ['unexpected_country', 'datacenter_ip', 'policy_violation', 'enrichment_missing', 'impossible_travel'])
        with open(pdf_path, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f.read(),
                file_name="geoip_whois_anomalies.pdf",
                mime="application/pdf"
            )
        try:
            os.remove(pdf_path)
        except Exception:
            pass
else:
    st.info("Please upload all required datasets and click 'Run Detection' to begin analysis.")