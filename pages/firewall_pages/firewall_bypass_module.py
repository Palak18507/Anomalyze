import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import tempfile
import os

# --- Column Normalization Maps ---
FW_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'src_port': ['src_port', 'source_port', 'sport'],
    'dst_port': ['dst_port', 'destination_port', 'dport'],
    'protocol': ['protocol', 'proto'],
    'action': ['action', 'activity'],
}
DNS_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'client_ip': ['client_ip', 'src_ip', 'source_ip', 'src', 'source'],
    'query_name': ['query_name', 'domain', 'query', 'hostname'],
    'answer_ip': ['answer_ip', 'resolved_ip', 'ip', 'address'],
}

FW_REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())
DNS_REQUIRED_COLUMNS = list(DNS_COLUMN_MAP.keys())

# --- Known Bypass Indicators ---
KNOWN_BYPASS_DOMAINS = [
    'example-tunnel.com', 'dns2tcp.net', 'iodine.org', 'yourcompany-bypass.com',
    'minapronetvpn.com', 'dozapp.xyz', 'tcat.site', 'rcsmf100.net',
    'hammercdntech.com', 'todoreal.cf', '53r.de', '8u6.de', '1yf.de',
    'spotilocal.com', 'anyconnect.stream', 'bigip.stream', 'fortiweb.download',
    'kaspersky.science', 'ampproject.net'
]
KNOWN_BYPASS_PORTS = [53, 443, 8080, 8888]
SUSPICIOUS_PROTOCOLS = ['ICMP', 'UDP']

THREAT_SEVERITY_MAP = {
    'DNS tunneling domain queried': ('Data Exfiltration', 'High'),
    'Suspicious port/protocol usage': ('Evasion/Recon', 'Medium'),
    'Connection to recently resolved DNS IP': ('Covert Channel/Abuse', 'Medium'),
    'Protocol/Port mismatch': ('Protocol Abuse', 'High'),
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
    return _normalize_columns(df, FW_COLUMN_MAP)

def parse_dns_log(df):
    return _normalize_columns(df, DNS_COLUMN_MAP)

# --- Input Validation ---
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Detection Logic ---
def detect_firewall_bypass(firewall_df, dns_df):
    anomalies = []

    # 1. DNS tunneling: Connections to known bypass domains
    dns_bypass = dns_df[dns_df['query_name'].str.lower().isin([d.lower() for d in KNOWN_BYPASS_DOMAINS])]
    for _, row in dns_bypass.iterrows():
        category, severity = THREAT_SEVERITY_MAP['DNS tunneling domain queried']
        anomalies.append({
            'Timestamp': row['timestamp'],
            'Source IP': row['client_ip'],
            'Destination': row.get('answer_ip', ''),
            'Technique': 'DNS tunneling domain queried',
            'Threat Category': category,
            'Severity': severity,
            'Details': row['query_name']
        })

    # 2. Network connections on suspicious ports/protocols
    suspicious_conns = firewall_df[
        (firewall_df['dst_port'].isin(KNOWN_BYPASS_PORTS)) &
        (firewall_df['protocol'].str.upper().isin([p.upper() for p in SUSPICIOUS_PROTOCOLS])) &
        (firewall_df['action'].str.lower() == 'allow')
    ]
    for _, row in suspicious_conns.iterrows():
        category, severity = THREAT_SEVERITY_MAP['Suspicious port/protocol usage']
        anomalies.append({
            'Timestamp': row['timestamp'],
            'Source IP': row['src_ip'],
            'Destination': row['dst_ip'],
            'Technique': 'Suspicious port/protocol usage',
            'Threat Category': category,
            'Severity': severity,
            'Details': f"Port {row['dst_port']}, Protocol {row['protocol']}"
        })

    # 3. Connections to IPs recently resolved via DNS queries (potential tunneling)
    dns_recent = dns_df[['timestamp', 'client_ip', 'answer_ip', 'query_name']]
    for _, dns_row in dns_recent.iterrows():
        window_start = pd.to_datetime(dns_row['timestamp'])
        window_end = window_start + pd.Timedelta(minutes=5)
        matches = firewall_df[
            (firewall_df['src_ip'] == dns_row['client_ip']) &
            (firewall_df['dst_ip'] == dns_row['answer_ip']) &
            (pd.to_datetime(firewall_df['timestamp']) >= window_start) &
            (pd.to_datetime(firewall_df['timestamp']) <= window_end) &
            (firewall_df['action'].str.lower() == 'allow')
        ]
        for _, net_row in matches.iterrows():
            category, severity = THREAT_SEVERITY_MAP['Connection to recently resolved DNS IP']
            anomalies.append({
                'Timestamp': net_row['timestamp'],
                'Source IP': net_row['src_ip'],
                'Destination': net_row['dst_ip'],
                'Technique': 'Connection to recently resolved DNS IP',
                'Threat Category': category,
                'Severity': severity,
                'Details': f"Domain: {dns_row['query_name']}"
            })

    # 4. Protocol/Port mismatch (e.g., TCP on port 53)
    proto_port_mismatch = firewall_df[
        (firewall_df['dst_port'] == 53) &
        (firewall_df['protocol'].str.upper() == 'TCP') &
        (firewall_df['action'].str.lower() == 'allow')
    ]
    for _, row in proto_port_mismatch.iterrows():
        category, severity = THREAT_SEVERITY_MAP['Protocol/Port mismatch']
        anomalies.append({
            'Timestamp': row['timestamp'],
            'Source IP': row['src_ip'],
            'Destination': row['dst_ip'],
            'Technique': 'Protocol/Port mismatch',
            'Threat Category': category,
            'Severity': severity,
            'Details': 'TCP connection on DNS port 53'
        })

    return pd.DataFrame(anomalies)

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Firewall Bypass Detection", layout="wide")
st.title("Firewall Bypass Detection: DNS Tunneling, Protocol Abuse, and Evasion Analysis")

st.markdown("""
This tool detects firewall bypass attempts including DNS tunneling, protocol/port abuse, and covert channels by correlating firewall and DNS logs.

**How to use:**
- Upload at least one firewall log CSV and one DNS log CSV file.
- Click "Run Detection" to analyze and visualize results.
""")

if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'dns_df' not in st.session_state:
    st.session_state['dns_df'] = None
if 'anomalies_df' not in st.session_state:
    st.session_state['anomalies_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

firewall_file = st.file_uploader("Upload Firewall Log CSV", type=['csv'])
dns_file = st.file_uploader("Upload DNS Log CSV", type=['csv'])
run_analysis = st.button("Run Detection")

if run_analysis and firewall_file and dns_file:
    try:
        fw_raw = pd.read_csv(firewall_file)
        dns_raw = pd.read_csv(dns_file)
        fw_df = parse_firewall_log(fw_raw)
        dns_df = parse_dns_log(dns_raw)
        fw_df = validate_input(fw_df, FW_REQUIRED_COLUMNS, "Firewall Log")
        dns_df = validate_input(dns_df, DNS_REQUIRED_COLUMNS, "DNS Log")
        st.session_state['fw_df'] = fw_df
        st.session_state['dns_df'] = dns_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process input files: {e}")
        st.stop()

    anomalies_df = detect_firewall_bypass(st.session_state['fw_df'], st.session_state['dns_df'])
    st.session_state['anomalies_df'] = anomalies_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Detection completed at {completion_time}")
    st.write("---")

if st.session_state.get('anomalies_df') is not None and st.session_state.get('analysis_done'):
    anomalies_df = st.session_state['anomalies_df']

    st.markdown("### Detected Firewall Bypass Events")
    st.dataframe(anomalies_df.head(50))

    st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Incident Counts by Source IP** | Shows which IPs are most frequently involved in bypass attempts. |
| **Incident Counts by Technique** | Highlights the distribution of bypass techniques detected. |
| **Incident Severity Distribution** | Displays the distribution of severity levels among detected events. |
| **Timeline of Events** | Shows the chronological order of detected bypass events. |
""")

    st.subheader("Bar Chart: Incident Counts by Source IP")
    src_ip_counts = anomalies_df["Source IP"].value_counts().reset_index().rename(
        columns={"index": "Source IP", "Source IP": "count"}
    )
    fig_ip = px.bar(
        src_ip_counts,
        x="Source IP",
        y="count",
        color_discrete_sequence=["orchid"],
        labels={"Source IP": "Source IP", "count": "Number of Events"},
        title="Incident Counts by Source IP"
    )
    st.plotly_chart(fig_ip, use_container_width=True)

    st.subheader("Bar Chart: Incident Counts by Technique")
    tech_counts = anomalies_df["Technique"].value_counts().reset_index().rename(
        columns={"index": "Technique", "Technique": "count"}
    )
    fig_tech = px.bar(
        tech_counts,
        x="Technique",
        y="count",
        color_discrete_sequence=["skyblue"],
        labels={"Technique": "Technique", "count": "Number of Events"},
        title="Incident Counts by Technique"
    )
    st.plotly_chart(fig_tech, use_container_width=True)

    st.subheader("Incident Severity Distribution")
    if "Severity" in anomalies_df.columns:
        sev_counts = anomalies_df["Severity"].value_counts().reset_index().rename(
            columns={"index": "Severity", "Severity": "Count"}
        )
        fig_sev = px.pie(
            sev_counts,
            names="Severity",
            values="Count",
            title="Incident Severity Distribution"
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No severity data for visualization.")

    st.subheader("Timeline of Events")
    if not anomalies_df.empty:
        timeline = anomalies_df.sort_values('Timestamp')
        st.dataframe(timeline[['Timestamp', 'Source IP', 'Destination', 'Technique', 'Severity']])
    else:
        st.info("No events to display in timeline.")

    # --- CSV Export ---
    csv_path = generate_csv_report(anomalies_df)
    with open(csv_path, "rb") as f:
        st.download_button(
            label="Download CSV Report",
            data=f.read(),
            file_name="firewall_bypass_report.csv",
            mime="text/csv"
        )
    try:
        os.remove(csv_path)
    except Exception:
        pass

else:
    st.info("Please upload both firewall and DNS log files and click 'Run Detection' to begin analysis.")