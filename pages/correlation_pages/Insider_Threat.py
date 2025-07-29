import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile
import os
import ipaddress
import json

# --- Column normalization map ---
LOG_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
    "dest_ip": ["dest_ip", "destination_ip", "dest", "destination"],
    "dest_port": ["dest_port", "destination_port", "port"],
    "bytes_sent": ["bytes_sent", "bytes", "sent_bytes", "data_sent"],
    "timestamp": ["timestamp", "time", "date"]
}

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

def parse_log(df):
    return _normalize_columns(df, LOG_COLUMN_MAP)

REQUIRED_COLUMNS = list(LOG_COLUMN_MAP.keys())

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Log File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def parse_vpn_ips(file):
    file.seek(0)
    ips = set()
    for line in file.readlines():
        try:
            line = line.decode("utf-8").strip()
        except AttributeError:
            line = line.strip()
        if not line:
            continue
        ip = None
        import re
        match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        if match:
            ip = match.group(1)
        if ip:
            ips.add(ip)
    return ips

def parse_internal_networks(ranges_str):
    internal_networks = []
    for cidr in ranges_str.split(","):
        try:
            internal_networks.append(ipaddress.ip_network(cidr.strip()))
        except Exception:
            continue
    return internal_networks

def is_internal_ip(ip, internal_networks):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in internal_networks)
    except Exception:
        return False

def detect_insider_threat(df, vpn_ips, internal_networks, data_threshold_bytes=100*1024*1024):
    incidents = []
    for _, entry in df.iterrows():
        src_ip = entry.get("src_ip")
        dest_ip = entry.get("dest_ip", "")
        dest_port = str(entry.get("dest_port", ""))
        bytes_sent = int(entry.get("bytes_sent", 0))
        timestamp = entry.get("timestamp")
        is_internal = is_internal_ip(src_ip, internal_networks)
        is_vpn = src_ip in vpn_ips
        is_exfil = bytes_sent > data_threshold_bytes

        if is_internal and is_vpn:
            incidents.append({
                "type": "Internal IP via VPN",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "bytes_sent": bytes_sent,
                "timestamp": timestamp,
                "details": entry.to_dict()
            })
        if is_internal and is_exfil:
            incidents.append({
                "type": "Internal IP Data Exfiltration",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "bytes_sent": bytes_sent,
                "timestamp": timestamp,
                "details": entry.to_dict()
            })
        if is_internal and is_vpn and is_exfil:
            incidents.append({
                "type": "Insider Threat (VPN + Exfil)",
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "bytes_sent": bytes_sent,
                "timestamp": timestamp,
                "details": entry.to_dict()
            })
    return incidents

def correlate_incidents(incidents):
    from collections import defaultdict
    correlation = defaultdict(list)
    for inc in incidents:
        correlation[inc["src_ip"]].append(inc)
    return [
        {"src_ip": ip, "num_incidents": len(incs), "incident_types": list(set(i["type"] for i in incs))}
        for ip, incs in correlation.items() if len(incs) > 1
    ]

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(incidents):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Insider Threat Detection Report", ln=True, align='C')
    pdf.ln(10)
    if not incidents:
        pdf.cell(200, 10, txt="No insider threat incidents detected.", ln=True)
    else:
        for inc in incidents:
            pdf.multi_cell(0, 10, txt=safe(
                f"""
Type: {inc['type']}
Source IP: {inc['src_ip']}
Destination IP: {inc['dest_ip']}
Destination Port: {inc['dest_port']}
Bytes Sent: {inc['bytes_sent']}
Timestamp: {inc['timestamp']}
"""
            ))
            pdf.ln(2)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

def plot_bar(data, x, y, title, xlabel, ylabel, color):
    if data is None or (hasattr(data, "empty") and data.empty):
        st.info("No data for visualization.")
        return
    df = pd.DataFrame(data)
    fig = px.bar(
        df,
        x=x,
        y=y,
        color_discrete_sequence=[color],
        labels={x: xlabel, y: ylabel},
        title=title
    )
    st.plotly_chart(fig, use_container_width=True)

def plot_heatmap_by_hour(incidents):
    if not incidents:
        st.info("No incidents to display in heatmap.")
        return
    df = pd.DataFrame(incidents)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['hour'] = df['timestamp'].dt.hour
    hour_counts = df.groupby('hour').size().reindex(range(24), fill_value=0)
    heatmap_df = pd.DataFrame({'hour': range(24), 'count': hour_counts.values})
    fig = px.density_heatmap(
        heatmap_df,
        x='hour',
        y=['Incidents'] * 24,
        z='count',
        color_continuous_scale='YlOrRd',
        title='Heatmap of Incidents by Hour'
    )
    st.plotly_chart(fig, use_container_width=True)

# --- Streamlit UI with Session State Preservation ---
st.set_page_config(page_title="Insider Threat Detection", layout="wide")
st.title("Insider Threat Detection: Internal IP + VPN + Data Exfiltration")

st.markdown("""
This tool detects insider threat incidents from firewall logs, including internal IPs using VPN, data exfiltration, and their combinations.

**How to use:**
- Upload one or more firewall log CSV files.
- Upload a VPN IPs text file (one IP per line).
- Optionally adjust internal IP ranges and the data exfiltration threshold.
""")

if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'incidents' not in st.session_state:
    st.session_state['incidents'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_files = st.file_uploader("Upload Firewall Log CSV files", type=["csv"], accept_multiple_files=True)
vpn_file = st.file_uploader("Upload VPN IPs file", type=["txt"])
internal_ranges = st.text_input("Internal IP Ranges (comma-separated CIDR)", value="10.0.0.0/8,192.168.0.0/16,172.16.0.0/12")
data_threshold_mb = st.number_input("Data Exfiltration Threshold (MB)", min_value=1, value=100)

if uploaded_files and vpn_file:
    try:
        dfs = []
        for file in uploaded_files:
            df = pd.read_csv(file)
            df = parse_log(df)
            df = validate_input(df, REQUIRED_COLUMNS, file.name)
            dfs.append(df)
        combined_df = pd.concat(dfs, ignore_index=True)
        st.session_state['df'] = combined_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to read log files: {e}")
        st.stop()
    try:
        vpn_ips = parse_vpn_ips(vpn_file)
        internal_networks = parse_internal_networks(internal_ranges)
        data_threshold_bytes = data_threshold_mb * 1024 * 1024
    except Exception as e:
        st.error(f"Failed to process VPN/internal ranges: {e}")
        st.stop()

    if st.session_state['df'] is not None and not st.session_state['analysis_done']:
        incidents = detect_insider_threat(
            st.session_state['df'], vpn_ips, internal_networks, data_threshold_bytes
        )
        st.session_state['incidents'] = incidents
        st.session_state['analysis_done'] = True
        completion_time = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
        st.success(f"Analysis completed at {completion_time}")
        st.write("---")

if st.session_state.get('incidents') is not None:
    incidents = st.session_state['incidents']
    if not incidents:
        st.info("No insider threat incidents detected.")
    else:
        st.markdown("### Detected Incidents")
        df_events = pd.DataFrame([{
            "Type": inc["type"],
            "Source IP": inc["src_ip"],
            "Destination IP": inc["dest_ip"],
            "Destination Port": inc["dest_port"],
            "Bytes Sent": inc["bytes_sent"],
            "Timestamp": inc["timestamp"],
            "Details": json.dumps(inc["details"])
        } for inc in incidents])
        st.dataframe(df_events)

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Incident Counts by Source IP** | Shows which internal IPs are most frequently involved in suspicious activity. Helps identify potentially compromised or misused hosts. |
| **Incident Counts by Destination IP** | Highlights which external IPs are most often targeted or contacted during incidents. Useful for spotting exfiltration targets or command-and-control endpoints. |
| **Incident Counts by Destination Port** | Reveals which network services or ports are most commonly used in detected incidents. Can indicate protocol abuse or unusual service usage. |
| **Heatmap of Incidents by Hour** | Displays the distribution of incidents across each hour of the day. Helps uncover time-based patterns, such as after-hours data exfiltration or off-peak attacks. |
| **Correlated Incidents Table** | Lists internal IPs involved in multiple types of incidents, aiding in correlation and deeper investigation. |
""")

        st.subheader("Bar Chart: Incident Counts by Source IP")
        plot_bar(
            pd.Series([inc["src_ip"] for inc in incidents]).value_counts().reset_index().rename(
                columns={"index": "src_ip", 0: "count"}
            ),
            x="src_ip", y="count",
            title="Incident Counts by Source IP",
            xlabel="Source IP", ylabel="Number of Incidents", color='orchid'
        )

        st.subheader("Bar Chart: Incident Counts by Destination IP")
        plot_bar(
            pd.Series([inc["dest_ip"] for inc in incidents]).value_counts().reset_index().rename(
                columns={"index": "dest_ip", 0: "count"}
            ),
            x="dest_ip", y="count",
            title="Incident Counts by Destination IP",
            xlabel="Destination IP", ylabel="Number of Incidents", color='skyblue'
        )

        st.subheader("Bar Chart: Incident Counts by Destination Port")
        plot_bar(
            pd.Series([inc["dest_port"] for inc in incidents]).value_counts().reset_index().rename(
                columns={"index": "dest_port", 0: "count"}
            ),
            x="dest_port", y="count",
            title="Incident Counts by Destination Port",
            xlabel="Destination Port", ylabel="Number of Incidents", color='salmon'
        )

        st.subheader("Heatmap: Incidents by Hour")
        plot_heatmap_by_hour(incidents)

        st.subheader("Correlated Incidents (IPs with Multiple Incident Types)")
        correlated = correlate_incidents(incidents)
        if correlated:
            correlated_df = pd.DataFrame(correlated)
            correlated_df["incident_types"] = correlated_df["incident_types"].apply(lambda x: ", ".join(x))
            st.markdown("""
| Source IP | Number of Incidents | Incident Types |
|-----------|--------------------|---------------|
""" + "\n".join(
    f"| {row['src_ip']} | {row['num_incidents']} | {row['incident_types']} |"
    for _, row in correlated_df.iterrows()
))
        else:
            st.info("No correlated incidents found.")

        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(incidents)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="insider_threat_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload all required files to begin analysis.")