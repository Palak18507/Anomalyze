import streamlit as st
import pandas as pd
import json
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

# --- P2P/Torrent Detection Configuration ---
P2P_PORTS = set([
    6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6890,  # BitTorrent
    4662, 4672,  # eMule
    6346, 6347,  # Gnutella
    135, 137, 138, 139, 445,  # NetBIOS (sometimes used)
    51413,  # Transmission
    2234,  # Shareaza
    4444,  # iMesh
    6699,  # WinMX
])
P2P_KEYWORDS = [
    "bittorrent", "torrent", "emule", "gnutella", "edonkey", "kazaa", "limewire",
    "shareaza", "winmx", "p2p", "transmission", "utorrent", "vuze", "frostwire"
]

# --- Utility Functions ---

def validate_required_columns(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        return False
    return True

def detect_p2p_torrent_activity(df):
    incidents = []
    for _, entry in df.iterrows():
        src_ip = entry.get("src_ip")
        dst_ip = entry.get("dst_ip")
        dst_port = entry.get("dst_port")
        app_field = str(entry.get("application", "")).lower()
        url_field = str(entry.get("dest_url", "")).lower()
        try:
            port = int(dst_port)
        except (TypeError, ValueError):
            port = None
        port_match = port in P2P_PORTS if port else False
        keyword_match = any(keyword in app_field or keyword in url_field for keyword in P2P_KEYWORDS)
        if port_match or keyword_match:
            incidents.append({
                "type": "P2P/Torrent Activity",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "application": app_field,
                "dest_url": url_field,
                "timestamp": entry.get("timestamp"),
                "details": entry.to_dict()
            })
    return incidents

def detect_swarming_behavior(df, min_unique_peers=20, time_window_minutes=10):
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.sort_values('timestamp')
    swarming_alerts = []
    grouped = df.groupby('src_ip')
    for src_ip, group in grouped:
        group = group.reset_index(drop=True)
        for i in range(len(group)):
            window_start = group.loc[i, 'timestamp']
            window_end = window_start + pd.Timedelta(minutes=time_window_minutes)
            window = group[(group['timestamp'] >= window_start) & (group['timestamp'] < window_end)]
            unique_peers = set(zip(window['dst_ip'], window['dst_port']))
            if len(unique_peers) >= min_unique_peers:
                swarming_alerts.append({
                    "type": "P2P Swarming Behavior",
                    "src_ip": src_ip,
                    "unique_peers": len(unique_peers),
                    "window_start": window_start,
                    "window_end": window_end,
                    "details": window.to_dict()
                })
                break  # Alert once per src_ip
    return swarming_alerts

def generate_csv_report(events):
    import tempfile, os
    df = pd.DataFrame(events)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Workflow Function ---

def workflow(log_files, required_columns, job_name="P2P/Torrent Activity Detector"):
    st.title(job_name)
    st.write("Upload your IPDR or firewall log CSV files for analysis.")

    if not log_files:
        st.warning("Please upload at least one log file to proceed.")
        st.stop()

    all_logs_df = []
    for uploaded_file in log_files:
        df = pd.read_csv(uploaded_file)
        if not validate_required_columns(df, required_columns, uploaded_file.name):
            st.stop()
        all_logs_df.append(df)
    combined_df = pd.concat(all_logs_df, ignore_index=True)

    # Main detection
    incidents = detect_p2p_torrent_activity(combined_df)
    # Swarming behavior detection
    swarming_alerts = detect_swarming_behavior(combined_df)

    completion_time = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"{job_name} completed at {completion_time}")
    st.write("----")

    st.subheader("Alert Summary")
    alert_summary = defaultdict(int)
    for inc in incidents:
        alert_summary[inc["type"]] += 1
    for alert in swarming_alerts:
        alert_summary[alert["type"]] += 1

    if alert_summary:
        for alert_type, count in alert_summary.items():
            st.write(f"{alert_type}: {count}")
    else:
        st.write("No P2P/torrent activity detected.")

    # Event list
    if incidents or swarming_alerts:
        df_events = pd.DataFrame([
            {
                "Type": inc["type"],
                "Source IP": inc["src_ip"],
                "Destination IP": inc.get("dst_ip", ""),
                "Destination Port": inc.get("dst_port", ""),
                "Timestamp": inc.get("timestamp", inc.get("window_start", "")),
                "Details": json.dumps(inc["details"])
            }
            for inc in incidents + swarming_alerts
        ])
        st.subheader("Detected Incidents")
        st.dataframe(df_events)

        # Export CSV Report
        csv_path = generate_csv_report(incidents + swarming_alerts)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f.read(),
                file_name="p2p_torrent_activity_report.csv",
                mime="text/csv"
            )
        import os
        os.remove(csv_path)
    else:
        st.write("No incidents detected.")

    # Visualization: Top Source IPs by Incident Count
    src_ips = [inc["src_ip"] for inc in incidents]
    if src_ips:
        src_ip_counts = Counter(src_ips)
        ips_list = list(src_ip_counts.keys())
        counts_list = list(src_ip_counts.values())
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.bar(ips_list, counts_list, color='orchid')
        ax.set_title('Incident Counts by Source IP')
        ax.set_xlabel('Source IP')
        ax.set_ylabel('Number of Incidents')
        ax.grid(axis='y')
        st.pyplot(fig)
    else:
        st.write("No source IP data for bar chart.")

    # Visualization: Incident count by destination port
    dst_ports = [inc.get("dst_port") for inc in incidents if inc.get("dst_port")]
    if dst_ports:
        port_counts = Counter(dst_ports)
        ports_list = [str(p) for p in port_counts.keys()]
        counts_list = list(port_counts.values())
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.bar(ports_list, counts_list, color='skyblue')
        ax.set_title('Incident Counts by Destination Port')
        ax.set_xlabel('Destination Port')
        ax.set_ylabel('Number of Incidents')
        ax.grid(axis='y')
        st.pyplot(fig)
    else:
        st.write("No port data available for port chart.")

    return completion_time

# --- Main App Entrypoint ---

def main():
    st.title("P2P/Torrent Activity Detector")
    log_files = st.file_uploader(
        "Upload IPDR/Firewall Log CSV files", type=["csv"], accept_multiple_files=True
    )
    required_columns = ["timestamp", "src_ip", "dst_ip", "dst_port"]
    if st.button("Run Detection"):
        if not log_files:
            st.error("Please upload at least one log file before running detection.")
        else:
            workflow(
                log_files=log_files,
                required_columns=required_columns,
                job_name="P2P/Torrent Activity Detector"
            )

if __name__ == "__main__":
    main()
