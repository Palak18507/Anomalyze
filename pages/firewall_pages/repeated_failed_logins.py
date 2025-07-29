import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import timedelta, datetime
from fpdf import FPDF
import tempfile
import os

# --- Column Normalization Map ---
FIREWALL_COLUMN_MAP = {
    'timestamp': ['timestamp', 'time', 'date'],
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'dst_ip': ['dst_ip', 'destination_ip', 'dest', 'destination'],
    'protocol': ['protocol', 'proto'],
    'action': ['action', 'activity'],
    'application': ['application', 'app', 'service'],
    'user_id': ['user_id', 'userid', 'user'],
    'start_time':['flow_start_time','start_time']
}

REQUIRED_COLUMNS = list(FIREWALL_COLUMN_MAP.keys())

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
def validate_input(uploaded_file, required_columns, job_name="Firewall Log"):
    if uploaded_file is None:
        st.error(f"Please upload a file for {job_name}.")
        st.stop()
    try:
        df = pd.read_csv(uploaded_file, parse_dates=['timestamp'])
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()
    df = parse_firewall_log(df)
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

# --- Detection Functions ---
def detect_failed_logins(df, min_attempts=5, window_minutes=5):
    fail_mask = df['action'].str.lower().isin(['block', 'deny', 'denied'])
    failed_df = df[fail_mask].copy()
    failed_df = failed_df.sort_values('timestamp')
    alerts = []
    for src_ip, group in failed_df.groupby('src_ip'):
        group = group.sort_values('timestamp')
        times = group['timestamp'].tolist()
        user_ids = group['user_id'].tolist() if 'user_id' in group else ['N/A'] * len(times)
        for i in range(len(times) - min_attempts + 1):
            window = times[i:i+min_attempts]
            window_users = user_ids[i:i+min_attempts]
            if (window[-1] - window[0]) <= timedelta(minutes=window_minutes):
                alerts.append({
                    'src_ip': src_ip,
                    'start_time': window[0],
                    'end_time': window[-1],
                    'fail_count': min_attempts,
                    'user_ids': ', '.join(set(window_users)),
                    'event_type': 'Brute-force/Repeated Failed Logins'
                })
                break
    return pd.DataFrame(alerts)

def detect_ddos_patterns(df, min_denied=20, window_seconds=60):
    denied_df = df[df['action'].str.lower().isin(['block', 'deny', 'denied'])].copy()
    denied_df = denied_df.sort_values('timestamp')
    alerts = []
    for src_ip, group in denied_df.groupby('src_ip'):
        times = group['timestamp'].tolist()
        user_ids = group['user_id'].tolist() if 'user_id' in group else ['N/A'] * len(times)
        for i in range(len(times) - min_denied + 1):
            window = times[i:i+min_denied]
            window_users = user_ids[i:i+min_denied]
            if (window[-1] - window[0]).total_seconds() <= window_seconds:
                alerts.append({
                    'src_ip': src_ip,
                    'start_time': window[0],
                    'end_time': window[-1],
                    'fail_count': min_denied,
                    'user_ids': ', '.join(set(window_users)),
                    'event_type': 'Possible DDoS/Denial Spike'
                })
                break
    times = denied_df['timestamp'].tolist()
    user_ids = denied_df['user_id'].tolist() if 'user_id' in denied_df else ['N/A'] * len(times)
    for i in range(len(times) - min_denied + 1):
        window = times[i:i+min_denied]
        window_users = user_ids[i:i+min_denied]
        if (window[-1] - window[0]).total_seconds() <= window_seconds:
            alerts.append({
                'src_ip': 'Multiple',
                'start_time': window[0],
                'end_time': window[-1],
                'fail_count': min_denied,
                'user_ids': ', '.join(set(window_users)),
                'event_type': 'Global Denial Spike (Possible DDoS)'
            })
            break
    return pd.DataFrame(alerts)

def detect_syn_without_ack(df, min_syns=10, window_seconds=60):
    syn_df = df[(df['protocol'].str.upper() == 'TCP') & (df['action'].str.lower() == 'block')]
    alerts = []
    for src_ip, group in syn_df.groupby('src_ip'):
        times = group['timestamp'].tolist()
        user_ids = group['user_id'].tolist() if 'user_id' in group else ['N/A'] * len(times)
        for i in range(len(times) - min_syns + 1):
            window = times[i:i+min_syns]
            window_users = user_ids[i:i+min_syns]
            if (window[-1] - window[0]).total_seconds() <= window_seconds:
                alerts.append({
                    'src_ip': src_ip,
                    'start_time': window[0],
                    'end_time': window[-1],
                    'syn_like_blocked_count': min_syns,
                    'user_ids': ', '.join(set(window_users)),
                    'event_type': 'Possible SYN Flood (Blocked TCP Connections)'
                })
                break
    return pd.DataFrame(alerts)

def detect_udp_flood(df, min_packets=20, window_seconds=60):
    udp_df = df[df['protocol'].str.upper() == 'UDP'].copy()
    udp_df = udp_df.sort_values('timestamp')
    alerts = []
    for src_ip, group in udp_df.groupby('src_ip'):
        times = group['timestamp'].tolist()
        user_ids = group['user_id'].tolist() if 'user_id' in group else ['N/A'] * len(times)
        for i in range(len(times) - min_packets + 1):
            window = times[i:i+min_packets]
            window_users = user_ids[i:i+min_packets]
            if (window[-1] - window[0]).total_seconds() <= window_seconds:
                alerts.append({
                    'src_ip': src_ip,
                    'start_time': window[0],
                    'end_time': window[-1],
                    'udp_packet_count': min_packets,
                    'user_ids': ', '.join(set(window_users)),
                    'event_type': 'UDP Flood'
                })
                break
    return pd.DataFrame(alerts)

def detect_icmp_flood(df, min_packets=20, window_seconds=60):
    icmp_df = df[df['protocol'].str.upper() == 'ICMP'].copy()
    icmp_df = icmp_df.sort_values('timestamp')
    alerts = []
    for src_ip, group in icmp_df.groupby('src_ip'):
        times = group['timestamp'].tolist()
        user_ids = group['user_id'].tolist() if 'user_id' in group else ['N/A'] * len(times)
        for i in range(len(times) - min_packets + 1):
            window = times[i:i+min_packets]
            window_users = user_ids[i:i+min_packets]
            if (window[-1] - window[0]).total_seconds() <= window_seconds:
                alerts.append({
                    'src_ip': src_ip,
                    'start_time': window[0],
                    'end_time': window[-1],
                    'icmp_packet_count': min_packets,
                    'user_ids': ', '.join(set(window_users)),
                    'event_type': 'ICMP Flood'
                })
                break
    return pd.DataFrame(alerts)

def detect_dns_flood(df, min_packets=20, window_seconds=60):
    dns_df = df[df['application'].str.upper() == 'DNS'].copy()
    dns_df = dns_df.sort_values('timestamp')
    alerts = []
    for src_ip, group in dns_df.groupby('src_ip'):
        times = group['timestamp'].tolist()
        user_ids = group['user_id'].tolist() if 'user_id' in group else ['N/A'] * len(times)
        for i in range(len(times) - min_packets + 1):
            window = times[i:i+min_packets]
            window_users = user_ids[i:i+min_packets]
            if (window[-1] - window[0]).total_seconds() <= window_seconds:
                alerts.append({
                    'src_ip': src_ip,
                    'start_time': window[0],
                    'end_time': window[-1],
                    'dns_packet_count': min_packets,
                    'user_ids': ', '.join(set(window_users)),
                    'event_type': 'DNS Flood'
                })
                break
    return pd.DataFrame(alerts)

def detect_http_flood(df, min_requests=20, window_seconds=60):
    http_df = df[df['application'].str.upper().isin(['HTTP', 'HTTPS'])].copy()
    http_df = http_df.sort_values('timestamp')
    alerts = []
    for src_ip, group in http_df.groupby('src_ip'):
        times = group['timestamp'].tolist()
        user_ids = group['user_id'].tolist() if 'user_id' in group else ['N/A'] * len(times)
        for i in range(len(times) - min_requests + 1):
            window = times[i:i+min_requests]
            window_users = user_ids[i:i+min_requests]
            if (window[-1] - window[0]).total_seconds() <= window_seconds:
                alerts.append({
                    'src_ip': src_ip,
                    'start_time': window[0],
                    'end_time': window[-1],
                    'http_request_count': min_requests,
                    'user_ids': ', '.join(set(window_users)),
                    'event_type': 'HTTP Flood'
                })
                break
    return pd.DataFrame(alerts)

def detect_global_spike(df, action_filter='BLOCK', min_events=50, window_seconds=60):
    filtered_df = df[df['action'].str.lower() == action_filter.lower()].copy()
    filtered_df = filtered_df.sort_values('timestamp')
    times = filtered_df['timestamp'].tolist()
    user_ids = filtered_df['user_id'].tolist() if 'user_id' in filtered_df else ['N/A'] * len(times)
    alerts = []
    for i in range(len(times) - min_events + 1):
        window = times[i:i+min_events]
        window_users = user_ids[i:i+min_events]
        if (window[-1] - window[0]).total_seconds() <= window_seconds:
            alerts.append({
                'src_ip': 'Multiple',
                'start_time': window[0],
                'end_time': window[-1],
                'event_count': min_events,
                'user_ids': ', '.join(set(window_users)),
                'event_type': f'Global {action_filter} Spike'
            })
            break
    return pd.DataFrame(alerts)

# --- PDF Report Generation ---
def generate_pdf_report(events_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Firewall Threat Detection Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Detected Security Events", ln=1)
    pdf.set_font("Arial", "", 10)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(30, 8, "Type", border=1, fill=True)
    pdf.cell(35, 8, "Source IP", border=1, fill=True)
    pdf.cell(40, 8, "Start Time", border=1, fill=True)
    pdf.cell(40, 8, "End Time", border=1, fill=True)
    pdf.cell(45, 8, "User IDs", border=1, fill=True)
    pdf.ln()
    for _, row in events_df.iterrows():
        pdf.cell(30, 8, str(row.get('event_type', '')), border=1)
        pdf.cell(35, 8, str(row.get('src_ip', '')), border=1)
        pdf.cell(40, 8, str(row.get('start_time', '')), border=1)
        pdf.cell(40, 8, str(row.get('end_time', '')), border=1)
        pdf.cell(45, 8, str(row.get('user_ids', '')), border=1)
        pdf.ln()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Firewall Log Threat Detection Dashboard", layout="wide")
st.title("Firewall Log Threat Detection Dashboard")

st.markdown("""
This dashboard analyzes firewall logs for brute-force attempts, DDoS/denial spikes, SYN/UDP/ICMP/DNS/HTTP floods, and global denial spikes.

**How to use:**
- Upload a firewall log CSV file.
- Review detected events, interactive visualizations, and download a PDF report.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'all_events' not in st.session_state:
    st.session_state['all_events'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_file = st.file_uploader("Upload Firewall Log CSV", type=['csv'])
run_analysis = st.button("Run Detection")

if run_analysis and uploaded_file:
    try:
        df = validate_input(uploaded_file, REQUIRED_COLUMNS, "Firewall Log")
        st.session_state['df'] = df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process firewall log: {e}")
        st.stop()

    # --- Detection ---
    brute_alerts = detect_failed_logins(df)
    ddos_alerts = detect_ddos_patterns(df)
    syn_alerts = detect_syn_without_ack(df)
    udp_alerts = detect_udp_flood(df)
    icmp_alerts = detect_icmp_flood(df)
    dns_alerts = detect_dns_flood(df)
    http_alerts = detect_http_flood(df)
    global_spike_alerts = detect_global_spike(df)

    all_events = pd.concat([
        brute_alerts, ddos_alerts, syn_alerts, udp_alerts,
        icmp_alerts, dns_alerts, http_alerts, global_spike_alerts
    ], ignore_index=True).sort_values('start_time')
    st.session_state['all_events'] = all_events
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Threat detection completed at {completion_time}")
    st.write("---")

if st.session_state.get('analysis_done'):
    df = st.session_state['df']
    all_events = st.session_state['all_events']

    # Brute-force/failed logins
    st.header("Brute-force / Repeated Failed Login Attempts")
    brute_alerts = detect_failed_logins(df)
    st.metric("Brute-force Events", brute_alerts.shape[0])
    if not brute_alerts.empty:
        st.dataframe(brute_alerts[['src_ip', 'start_time', 'end_time', 'fail_count', 'user_ids', 'event_type']])
        fig = px.scatter(brute_alerts, x='start_time', y='src_ip', color='fail_count', title="Brute-force Attempts Over Time")
        st.plotly_chart(fig, use_container_width=True)
        brute_alerts['hour'] = pd.to_datetime(brute_alerts['start_time']).dt.hour
        brute_alerts['date'] = pd.to_datetime(brute_alerts['start_time']).dt.date
        heatmap_data = brute_alerts.groupby(['date', 'hour']).size().reset_index(name='count')
        fig_hm = px.density_heatmap(heatmap_data, x='hour', y='date', z='count', color_continuous_scale='Reds', title="Failed Login Heatmap")
        st.plotly_chart(fig_hm, use_container_width=True)
    else:
        st.success("No brute-force/repeated failed login attempts detected.")

    # DDoS/denial spikes
    st.header("DDoS / Denial Spike Detection")
    ddos_alerts = detect_ddos_patterns(df)
    st.metric("DDoS/Denial Spikes", ddos_alerts.shape[0])
    if not ddos_alerts.empty:
        st.dataframe(ddos_alerts[['src_ip', 'start_time', 'end_time', 'fail_count', 'user_ids', 'event_type']])
        fig = px.scatter(ddos_alerts, x='start_time', y='src_ip', color='fail_count', title="Denial Spikes Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No DDoS/denial spikes detected.")

    # SYN flood
    st.header("SYN Flood (SYN without ACK) Detection")
    syn_alerts = detect_syn_without_ack(df)
    st.metric("SYN Flood Events", syn_alerts.shape[0])
    if not syn_alerts.empty:
        st.dataframe(syn_alerts[['src_ip', 'start_time', 'end_time', 'syn_like_blocked_count', 'user_ids', 'event_type']])
        fig = px.scatter(syn_alerts, x='start_time', y='src_ip', color='syn_like_blocked_count', title="SYN Flood Events Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No SYN flood patterns detected.")

    # UDP flood
    st.header("UDP Flood Detection")
    udp_alerts = detect_udp_flood(df)
    st.metric("UDP Flood Events", udp_alerts.shape[0])
    if not udp_alerts.empty:
        st.dataframe(udp_alerts[['src_ip', 'start_time', 'end_time', 'udp_packet_count', 'user_ids', 'event_type']])
        fig = px.scatter(udp_alerts, x='start_time', y='src_ip', color='udp_packet_count', title="UDP Flood Events Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No UDP flood patterns detected.")

    # ICMP flood
    st.header("ICMP Flood Detection")
    icmp_alerts = detect_icmp_flood(df)
    st.metric("ICMP Flood Events", icmp_alerts.shape[0])
    if not icmp_alerts.empty:
        st.dataframe(icmp_alerts[['src_ip', 'start_time', 'end_time', 'icmp_packet_count', 'user_ids', 'event_type']])
        fig = px.scatter(icmp_alerts, x='start_time', y='src_ip', color='icmp_packet_count', title="ICMP Flood Events Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No ICMP flood patterns detected.")

    # DNS flood
    st.header("DNS Flood Detection")
    dns_alerts = detect_dns_flood(df)
    st.metric("DNS Flood Events", dns_alerts.shape[0])
    if not dns_alerts.empty:
        st.dataframe(dns_alerts[['src_ip', 'start_time', 'end_time', 'dns_packet_count', 'user_ids', 'event_type']])
        fig = px.scatter(dns_alerts, x='start_time', y='src_ip', color='dns_packet_count', title="DNS Flood Events Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No DNS flood patterns detected.")

    # HTTP flood
    st.header("HTTP Flood Detection")
    http_alerts = detect_http_flood(df)
    st.metric("HTTP Flood Events", http_alerts.shape[0])
    if not http_alerts.empty:
        st.dataframe(http_alerts[['src_ip', 'start_time', 'end_time', 'http_request_count', 'user_ids', 'event_type']])
        fig = px.scatter(http_alerts, x='start_time', y='src_ip', color='http_request_count', title="HTTP Flood Events Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No HTTP flood patterns detected.")

    # Global denial spike
    st.header("Global Denial Spike Detection")
    global_spike_alerts = detect_global_spike(df)
    st.metric("Global Denial Spikes", global_spike_alerts.shape[0])
    if not global_spike_alerts.empty:
        st.dataframe(global_spike_alerts[['src_ip', 'start_time', 'end_time', 'event_count', 'user_ids', 'event_type']])
        fig = px.scatter(global_spike_alerts, x='start_time', y='event_count', color='event_count', title="Global Denial Spikes Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No global denial spikes detected.")

    # PDF report download
    st.header("Download PDF Threat Report")
    if not all_events.empty and st.button("Generate PDF Report"):
        pdf_path = generate_pdf_report(all_events)
        with open(pdf_path, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f.read(),
                file_name="firewall_threat_report.pdf",
                mime="application/pdf"
            )
        try:
            os.remove(pdf_path)
        except Exception:
            pass

else:
    st.info("Please upload a firewall log file and click 'Run Detection' to begin analysis.")