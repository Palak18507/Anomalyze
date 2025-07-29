import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
from datetime import datetime
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
    'bytes_sent': ['bytes_sent', 'bytes', 'sent_bytes', 'data_sent'],
    'bytes_received': ['bytes_received', 'received_bytes', 'data_received'],
}
REQUIRED_COLUMNS = list(FIREWALL_COLUMN_MAP.keys())

# --- Suspicious/Unusual Ports Definition ---
SUSPICIOUS_PORTS = {
    23:  ("Telnet - Unencrypted remote access", "High"),
    6667: ("IRC - Often used by botnets", "High"),
    3389: ("RDP - Remote Desktop, targeted by brute-force", "High"),
    8080: ("Alternate HTTP port, sometimes used for proxies", "Medium"),
    8443: ("Alternate HTTPS port, sometimes used for proxies", "Medium"),
    31337: ("Back Orifice - Known malware/backdoor", "Critical"),
    12345: ("NetBus - Backdoor/Trojan", "Critical"),
    4444: ("Metasploit/remote shells", "High"),
    54321: ("Possible backdoor", "High"),
    65535: ("Highest TCP/UDP port, often used in scans", "Medium"),
    400: ("Uncommon, sometimes used in attacks", "Low"),
    401: ("Uncommon, sometimes used in attacks", "Low"),
    403: ("Uncommon, sometimes used in attacks", "Low"),
    407: ("Proxy authentication", "Medium"),
    418: ("Unused, sometimes used in attacks", "Low"),
    429: ("Unused, sometimes used in attacks", "Low"),
    451: ("Unused, sometimes used in attacks", "Low"),
    444: ("Uncommon, sometimes used for malware", "Medium"),
    666: ("Uncommon, sometimes used for malware", "Medium"),
    10000: ("Often used by remote admin tools", "Medium"),
    31338: ("Backdoor, malware", "Critical"),
    1234: ("Common test/backdoor port", "Medium"),
    9999: ("Remote admin, sometimes used for attacks", "Medium"),
    6969: ("Uncommon, sometimes used for attacks", "Low"),
    2000: ("Cisco SCCP, sometimes targeted", "Medium"),
    6776: ("Backdoor, malware", "Critical"),
    9400: ("Elasticsearch, sometimes targeted", "Medium"),
    9989: ("Uncommon, sometimes used for attacks", "Low"),
    16959: ("Backdoor, malware", "Critical"),
    5010: ("Uncommon, sometimes used for attacks", "Low"),
    54320: ("Backdoor, malware", "Critical")
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
def validate_input(uploaded_file, required_columns=None, file_type="csv", job_name="Firewall Log"):
    if uploaded_file is None:
        st.error(f"Please upload a file for {job_name}.")
        st.stop()
    try:
        if file_type == "csv":
            df = pd.read_csv(uploaded_file, parse_dates=['timestamp'])
        elif file_type == "excel":
            df = pd.read_excel(uploaded_file, parse_dates=['timestamp'])
        else:
            st.error("Unsupported file type.")
            st.stop()
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()
    df = parse_firewall_log(df)
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    for col in ['src_port', 'dst_port', 'bytes_sent', 'bytes_received']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
    return df

# --- Top N Frequent Ports ---
def top_frequent_ports(df, column='src_port', top_n=10):
    freq = df[column].value_counts().head(top_n)
    freq_df = freq.reset_index()
    freq_df.columns = [column, 'Count']
    return freq_df

# --- Timeline Line Chart for Frequent Ports ---
def frequent_ports_timeline(df, port_column, frequent_ports):
    df = df[df[port_column].isin(frequent_ports)]
    usage = df.groupby([pd.Grouper(key='timestamp', freq='H'), port_column]).size().reset_index(name='Count')
    fig = px.line(
        usage,
        x='timestamp',
        y='Count',
        color=port_column,
        title=f'Timeline of Frequent {port_column.replace("_", " ").title()}s',
        markers=True
    )
    fig.update_yaxes(dtick=1, tickformat=',d')
    return fig

# --- Port Probing Detection ---
def detect_port_probing_refined(df, min_ports=10, time_window_seconds=300):
    alerts = []
    grouped = df.groupby('src_ip')
    for src_ip, group in grouped:
        group = group.sort_values('timestamp')
        ports = group['dst_port'].tolist()
        times = group['timestamp'].tolist()
        if len(ports) < min_ports:
            continue
        sequential_found = False
        for i in range(len(ports) - min_ports + 1):
            window_ports = ports[i:i+min_ports]
            window_times = times[i:i+min_ports]
            diffs = [window_ports[j+1] - window_ports[j] for j in range(len(window_ports)-1)]
            if all(diff == 1 for diff in diffs):
                time_diff = (window_times[-1] - window_times[0]).total_seconds()
                if time_diff <= time_window_seconds:
                    sequential_found = True
                    alerts.append({
                        'src_ip': src_ip,
                        'scan_type': 'Sequential',
                        'start_time': window_times[0],
                        'end_time': window_times[-1],
                        'num_ports_scanned': len(window_ports),
                        'ports_scanned': window_ports,
                        'scan_duration_sec': time_diff
                    })
                    break
        if not sequential_found:
            time_span = (times[-1] - times[0]).total_seconds()
            if len(ports) >= min_ports and time_span <= time_window_seconds:
                alerts.append({
                    'src_ip': src_ip,
                    'scan_type': 'Random',
                    'start_time': times[0],
                    'end_time': times[-1],
                    'num_ports_scanned': len(ports),
                    'ports_scanned': ports,
                    'scan_duration_sec': time_span
                })
    return pd.DataFrame(alerts)

# --- Data Exfiltration Port Summary ---
def find_exfiltration_ports_refined(df, byte_threshold=100000):
    exfil_df = df[df['bytes_sent'] > byte_threshold]
    summary = exfil_df.groupby('dst_port').agg(
        total_bytes_sent=pd.NamedAgg(column='bytes_sent', aggfunc='sum'),
        connection_count=pd.NamedAgg(column='dst_port', aggfunc='count'),
        first_exfil=pd.NamedAgg(column='timestamp', aggfunc='min'),
        last_exfil=pd.NamedAgg(column='timestamp', aggfunc='max')
    ).reset_index().sort_values(by='total_bytes_sent', ascending=False)
    return summary

# --- Unusual Port Traffic Summary ---
def monitor_unusual_ports_refined(df, suspicious_ports_dict):
    unusual_ports = list(suspicious_ports_dict.keys())
    unusual_traffic = df[df['dst_port'].isin(unusual_ports)]
    summary = unusual_traffic.groupby(['dst_port', 'src_ip']).agg(
        total_bytes_sent=pd.NamedAgg(column='bytes_sent', aggfunc='sum'),
        total_bytes_received=pd.NamedAgg(column='bytes_received', aggfunc='sum'),
        first_seen=pd.NamedAgg(column='timestamp', aggfunc='min'),
        last_seen=pd.NamedAgg(column='timestamp', aggfunc='max'),
        connection_count=pd.NamedAgg(column='dst_port', aggfunc='count')
    ).reset_index()
    summary['reason'] = summary['dst_port'].apply(lambda p: suspicious_ports_dict[p][0])
    summary['severity'] = summary['dst_port'].apply(lambda p: suspicious_ports_dict[p][1])
    summary = summary.sort_values(by='total_bytes_sent', ascending=False)
    return summary

# --- PDF Report Generation ---
def generate_pdf_report(
    freq_src_ports, freq_dst_ports,
    port_scan_alerts, exfil_ports, unusual_port_summary, pdf_file='firewall_analysis_report.pdf'
):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Firewall Log Security Analysis Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)

    # Top frequent ports
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Top Most Frequent Source Ports", ln=1)
    pdf.set_font("Arial", "", 10)
    for _, row in freq_src_ports.iterrows():
        pdf.cell(0, 8, f"{row['src_port']}: {row['Count']}", ln=1)
    pdf.ln(2)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Top Most Frequent Destination Ports", ln=1)
    pdf.set_font("Arial", "", 10)
    for _, row in freq_dst_ports.iterrows():
        pdf.cell(0, 8, f"{row['dst_port']}: {row['Count']}", ln=1)
    pdf.ln(5)

    # Port probing alerts
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Port Probing Alerts", ln=1)
    pdf.set_font("Arial", "", 9)
    if not port_scan_alerts.empty:
        for _, row in port_scan_alerts.iterrows():
            pdf.cell(0, 7, f"{row['src_ip']} | {row['scan_type']} | {row['start_time']} - {row['end_time']} | Ports: {row['ports_scanned']}", ln=1)
    else:
        pdf.cell(0, 7, "No port scanning behavior detected.", ln=1)
    pdf.ln(3)

    # Data exfiltration summary
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Data Exfiltration Port Summary", ln=1)
    pdf.set_font("Arial", "", 9)
    if not exfil_ports.empty:
        for _, row in exfil_ports.iterrows():
            pdf.cell(0, 7, f"Port {row['dst_port']} | {row['total_bytes_sent']} bytes | {row['connection_count']} connections | {row['first_exfil']} - {row['last_exfil']}", ln=1)
    else:
        pdf.cell(0, 7, "No significant data exfiltration detected.", ln=1)
    pdf.ln(3)

    # Unusual port traffic summary
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Unusual Port Traffic Summary", ln=1)
    pdf.set_font("Arial", "", 9)
    if not unusual_port_summary.empty:
        for _, row in unusual_port_summary.iterrows():
            pdf.cell(0, 7, f"Port {row['dst_port']} | {row['src_ip']} | Severity: {row['severity']} | Reason: {row['reason']}", ln=1)
    else:
        pdf.cell(0, 7, "No unusual port traffic detected.", ln=1)
    pdf.ln(3)
    pdf.output(pdf_file)
    return pdf_file

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Firewall Log Security Analysis Dashboard", layout="wide")
st.title("Firewall Log Security Analysis Dashboard")

st.markdown("""
This dashboard analyzes firewall logs for:
- Top N most frequent source and destination ports
- Timeline charts for frequent ports
- Port probing (scan) detection
- Data exfiltration summary by port
- Unusual port traffic (reason, severity)
- PDF report with all tables
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'freq_src_ports' not in st.session_state:
    st.session_state['freq_src_ports'] = None
if 'freq_dst_ports' not in st.session_state:
    st.session_state['freq_dst_ports'] = None
if 'port_scan_alerts' not in st.session_state:
    st.session_state['port_scan_alerts'] = None
if 'exfil_ports' not in st.session_state:
    st.session_state['exfil_ports'] = None
if 'unusual_port_summary' not in st.session_state:
    st.session_state['unusual_port_summary'] = None
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
        st.error(f"Failed to process firewall log file: {e}")
        st.stop()

    top_n = st.number_input("How many frequent ports do you want to see?", min_value=1, max_value=100, value=10, step=1)

    freq_src_ports = top_frequent_ports(df, 'src_port', top_n=top_n)
    freq_dst_ports = top_frequent_ports(df, 'dst_port', top_n=top_n)
    st.session_state['freq_src_ports'] = freq_src_ports
    st.session_state['freq_dst_ports'] = freq_dst_ports

    st.subheader(f"Top {top_n} Most Frequent Source Ports")
    st.dataframe(freq_src_ports)
    st.subheader(f"Top {top_n} Most Frequent Destination Ports")
    st.dataframe(freq_dst_ports)

    st.subheader("Timeline of Frequent Source Ports")
    fig_src_timeline = frequent_ports_timeline(df, 'src_port', freq_src_ports['src_port'].tolist())
    st.plotly_chart(fig_src_timeline, use_container_width=True)

    st.subheader("Timeline of Frequent Destination Ports")
    fig_dst_timeline = frequent_ports_timeline(df, 'dst_port', freq_dst_ports['dst_port'].tolist())
    st.plotly_chart(fig_dst_timeline, use_container_width=True)

    st.subheader("Port Probing Alerts")
    port_scan_alerts = detect_port_probing_refined(df)
    st.session_state['port_scan_alerts'] = port_scan_alerts
    if not port_scan_alerts.empty:
        st.dataframe(port_scan_alerts[['src_ip', 'scan_type', 'start_time', 'end_time', 'num_ports_scanned', 'scan_duration_sec', 'ports_scanned']])
    else:
        st.success("No port scanning behavior detected.")

    st.subheader("Data Exfiltration Port Summary")
    exfil_ports = find_exfiltration_ports_refined(df)
    st.session_state['exfil_ports'] = exfil_ports
    if not exfil_ports.empty:
        st.dataframe(exfil_ports[['dst_port', 'total_bytes_sent', 'connection_count', 'first_exfil', 'last_exfil']])
    else:
        st.success("No significant data exfiltration detected.")

    st.subheader("Unusual Port Traffic Summary")
    unusual_port_summary = monitor_unusual_ports_refined(df, SUSPICIOUS_PORTS)
    st.session_state['unusual_port_summary'] = unusual_port_summary
    if not unusual_port_summary.empty:
        def color_severity(val):
            color = {'Critical': '#f44336', 'High': '#ff9800', 'Medium': '#ffeb3b', 'Low': '#8bc34a'}
            return f'background-color: {color.get(val, "")}'
        styled = unusual_port_summary[['dst_port', 'src_ip', 'total_bytes_sent', 'total_bytes_received', 'first_seen', 'last_seen', 'connection_count', 'reason', 'severity']].style.applymap(color_severity, subset=['severity'])
        st.dataframe(styled)

        st.subheader("Unusual Port Traffic Severity Distribution")
        severity_counts = unusual_port_summary['severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        fig_pie = px.pie(severity_counts, names='Severity', values='Count', title="Unusual Port Traffic by Severity",
                         color='Severity',
                         color_discrete_map={'Critical': '#f44336', 'High': '#ff9800', 'Medium': '#ffeb3b', 'Low': '#8bc34a'})
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.success("No unusual port traffic detected.")

    st.subheader("Download PDF Report")
    if st.button("Generate PDF Report"):
        pdf_file = generate_pdf_report(
            st.session_state['freq_src_ports'],
            st.session_state['freq_dst_ports'],
            st.session_state['port_scan_alerts'],
            st.session_state['exfil_ports'],
            st.session_state['unusual_port_summary']
        )
        with open(pdf_file, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name="firewall_analysis_report.pdf",
                mime="application/pdf"
            )
        st.success("PDF report generated and ready for download.")

else:
    st.info("Please upload a firewall log file and click 'Run Detection' to begin analysis.")