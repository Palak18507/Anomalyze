import streamlit as st
import pandas as pd
import plotly.express as px
import geoip2.database
import ipaddress
from fpdf import FPDF
import tempfile
import os
from collections import Counter
from datetime import datetime

# --- Column Normalization Map ---
DNS_COLUMN_MAP = {
    "timestamp": ["timestamp", "time", "date_time"],
    "client_ip": ["client_ip", "src_ip", "source_ip"],
    "query_name": ["query_name", "domain", "host", "fqdn"],
    "answer_ip": ["answer_ip", "resolved_ip", "answer", "ip"]
}

REQUIRED_COLUMNS = list(DNS_COLUMN_MAP.keys())

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

def parse_dns_log(df):
    return _normalize_columns(df, DNS_COLUMN_MAP)

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

class GeoIPReader:
    def __init__(self, db_file):
        self.reader = geoip2.database.Reader(db_file)
    def get_country(self, ip):
        try:
            return self.reader.city(ip).country.iso_code
        except Exception:
            return None

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'DNS Anomaly Detection Report', 0, 1, 'C')
    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(4)
    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 10, body)
        self.ln()
    def add_anomalies_table(self, df):
        self.set_font('Arial', 'B', 10)
        col_widths = [30, 30, 40, 30, 30, 30]
        headers = ['Timestamp', 'Client IP', 'Domain', 'Answer IP', 'Resolved Country', 'Expected Country']
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 10, header, 1)
        self.ln()
        self.set_font('Arial', '', 9)
        for _, row in df.iterrows():
            self.cell(col_widths[0], 10, str(row['timestamp']), 1)
            self.cell(col_widths[1], 10, str(row['client_ip']), 1)
            self.cell(col_widths[2], 10, str(row['query_name']), 1)
            self.cell(col_widths[3], 10, str(row['answer_ip']), 1)
            self.cell(col_widths[4], 10, str(row['resolved_country']), 1)
            self.cell(col_widths[5], 10, str(row['expected_country']), 1)
            self.ln()

def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- DNS Anomaly Detection Workflow ---
def workflow(dns_files, geoip_file):
    all_dns = pd.DataFrame()
    for f in dns_files:
        df = pd.read_csv(f)
        df = parse_dns_log(df)
        df = validate_input(df, REQUIRED_COLUMNS, f.name)
        df['query_name'] = df['query_name'].astype(str).str.lower().str.rstrip('.')
        all_dns = pd.concat([all_dns, df], ignore_index=True)
    # Prepare GeoIP reader
    with tempfile.NamedTemporaryFile(delete=False, suffix='.mmdb') as tmp_geoip:
        tmp_geoip.write(geoip_file.read())
        tmp_geoip.flush()
        geoip_reader = GeoIPReader(tmp_geoip.name)
        st.info("Resolving countries for all answer IPs. This may take a few seconds...")
        all_dns['resolved_country'] = all_dns['answer_ip'].apply(
            lambda ip: "Internal" if is_private_ip(str(ip)) else geoip_reader.get_country(str(ip)) if pd.notnull(ip) and ip != '' else None
        )
    # Infer expected country for each domain (most common country for that domain)
    domain_country_mode = (
        all_dns[all_dns['resolved_country'].notnull() & (all_dns['resolved_country'] != "Internal")]
        .groupby('query_name')['resolved_country']
        .agg(lambda x: Counter(x).most_common(1)[0][0])
        .to_dict()
    )
    all_dns['expected_country'] = all_dns['query_name'].map(domain_country_mode)
    # For each domain, get the set of all countries it has resolved to before
    domain_country_set = (
        all_dns[all_dns['resolved_country'].notnull() & (all_dns['resolved_country'] != "Internal")]
        .groupby('query_name')['resolved_country']
        .agg(lambda x: set(x))
        .to_dict()
    )
    def is_anomaly_loose(row):
        if pd.isnull(row['resolved_country']) or row['resolved_country'] == "Internal":
            return False
        return row['resolved_country'] != row['expected_country']
    def is_anomaly_strict(row):
        if pd.isnull(row['resolved_country']) or row['resolved_country'] == "Internal":
            return False
        expected_set = domain_country_set.get(row['query_name'], set())
        return row['resolved_country'] not in expected_set
    all_dns['anomaly_loose'] = all_dns.apply(is_anomaly_loose, axis=1)
    all_dns['anomaly_strict'] = all_dns.apply(is_anomaly_strict, axis=1)
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"DNS Anomaly Detection completed at {completion_time}")
    st.write("----")

    st.markdown("""
### DNS Resolution Sample

| Timestamp | Client IP | Domain | Answer IP | Resolved Country | Expected Country | Loose Anomaly | Strict Anomaly |
|-----------|-----------|--------|-----------|------------------|-----------------|---------------|---------------|
""")
    st.dataframe(
        all_dns[['timestamp', 'client_ip', 'query_name', 'answer_ip', 'resolved_country', 'expected_country', 'anomaly_loose', 'anomaly_strict']].head(20)
    )

    st.markdown("### Loose Anomalies (domain resolved to a country different from the most common):")
    loose = all_dns[all_dns['anomaly_loose'] == True][['timestamp', 'client_ip', 'query_name', 'answer_ip', 'resolved_country', 'expected_country']]
    st.dataframe(loose.head(20))

    st.markdown("### Strict Anomalies (domain resolved to a country never seen before):")
    strict = all_dns[all_dns['anomaly_strict'] == True][['timestamp', 'client_ip', 'query_name', 'answer_ip', 'resolved_country', 'expected_country']]
    st.dataframe(strict.head(20))

    # Visualization: Bar chart of anomaly counts by country
    st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Anomaly Counts by Resolved Country** | Shows which countries are most frequently involved in anomalies. |
| **Anomaly Counts by Domain** | Highlights which domains are most often involved in anomalies. |
""")

    st.subheader("Bar Chart: Anomaly Counts by Resolved Country")
    if not loose.empty:
        loose_country_counts = loose['resolved_country'].value_counts().reset_index().rename(
            columns={'index': 'resolved_country', 'resolved_country': 'count'}
        )
        fig_loose = px.bar(
            loose_country_counts,
            x='resolved_country',
            y='count',
            color_discrete_sequence=["orchid"],
            labels={'resolved_country': 'Resolved Country', 'count': 'Loose Anomaly Count'},
            title="Loose Anomaly Counts by Resolved Country"
        )
        st.plotly_chart(fig_loose, use_container_width=True)
    else:
        st.info("No loose anomalies for country bar chart.")

    st.subheader("Bar Chart: Anomaly Counts by Domain")
    if not loose.empty:
        loose_domain_counts = loose['query_name'].value_counts().reset_index().rename(
            columns={'index': 'query_name', 'query_name': 'count'}
        )
        fig_loose_domain = px.bar(
            loose_domain_counts,
            x='query_name',
            y='count',
            color_discrete_sequence=["skyblue"],
            labels={'query_name': 'Domain', 'count': 'Loose Anomaly Count'},
            title="Loose Anomaly Counts by Domain"
        )
        st.plotly_chart(fig_loose_domain, use_container_width=True)
    else:
        st.info("No loose anomalies for domain bar chart.")

    st.subheader("Bar Chart: Strict Anomaly Counts by Resolved Country")
    if not strict.empty:
        strict_country_counts = strict['resolved_country'].value_counts().reset_index().rename(
            columns={'index': 'resolved_country', 'resolved_country': 'count'}
        )
        fig_strict = px.bar(
            strict_country_counts,
            x='resolved_country',
            y='count',
            color_discrete_sequence=["salmon"],
            labels={'resolved_country': 'Resolved Country', 'count': 'Strict Anomaly Count'},
            title="Strict Anomaly Counts by Resolved Country"
        )
        st.plotly_chart(fig_strict, use_container_width=True)
    else:
        st.info("No strict anomalies for country bar chart.")

    st.subheader("Bar Chart: Strict Anomaly Counts by Domain")
    if not strict.empty:
        strict_domain_counts = strict['query_name'].value_counts().reset_index().rename(
            columns={'index': 'query_name', 'query_name': 'count'}
        )
        fig_strict_domain = px.bar(
            strict_domain_counts,
            x='query_name',
            y='count',
            color_discrete_sequence=["orange"],
            labels={'query_name': 'Domain', 'count': 'Strict Anomaly Count'},
            title="Strict Anomaly Counts by Domain"
        )
        st.plotly_chart(fig_strict_domain, use_container_width=True)
    else:
        st.info("No strict anomalies for domain bar chart.")

    # PDF Report Download
    if st.button("Generate PDF Report"):
        pdf = PDFReport()
        pdf.add_page()
        pdf.chapter_title('Loose DNS Anomalies')
        if not loose.empty:
            pdf.add_anomalies_table(loose.head(30))
        else:
            pdf.chapter_body('No loose anomalies detected.')
        pdf.chapter_title('Strict DNS Anomalies')
        if not strict.empty:
            pdf.add_anomalies_table(strict.head(30))
        else:
            pdf.chapter_body('No strict anomalies detected.')
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            pdf.output(tmp_file.name)
            tmp_file_path = tmp_file.name
        with open(tmp_file_path, 'rb') as f:
            pdf_bytes = f.read()
        st.download_button('Download PDF Report', pdf_bytes, file_name='dns_anomaly_report.pdf', mime='application/pdf')
        os.remove(tmp_file_path)
    os.remove(tmp_geoip.name)
    return completion_time

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="DNS Anomaly Detection", layout="wide")
st.title("DNS Anomaly Detection: Multi-File Log & GeoIP Analysis")

st.markdown("""
This tool detects DNS anomalies by comparing resolved countries for domains against their historical patterns using GeoIP data.

**How to use:**
- Upload one or more DNS log CSV files.
- Upload a GeoLite2-City.mmdb file for country resolution.
- Click "Run Detection" to analyze and visualize results.
""")

if 'dns_df' not in st.session_state:
    st.session_state['dns_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

dns_files = st.file_uploader(
    "Upload one or more DNS Logs CSV files", type=["csv"], accept_multiple_files=True, key="dns"
)
geoip_file = st.file_uploader(
    "Upload GeoLite2-City.mmdb", type=["mmdb"], key="geoip"
)
run_analysis = st.button("Run Detection")

if run_analysis and dns_files and geoip_file:
    try:
        workflow(dns_files, geoip_file)
        st.session_state['analysis_done'] = True
    except Exception as e:
        st.error(f"Failed to process files: {e}")
        st.stop()
else:
    st.info("Please upload at least one DNS log file and a GeoIP database to begin analysis.")