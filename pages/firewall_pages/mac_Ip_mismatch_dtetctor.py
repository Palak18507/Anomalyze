import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import tempfile
import os

# --- Column Normalization Maps ---
FW_COLUMN_MAP = {
    'src_ip': ['src_ip', 'source_ip', 'src', 'source'],
    'src_mac': ['src_mac', 'mac', 'mac_address', 'mac addr', 'hardware address', 'client mac'],
    'timestamp': ['timestamp', 'time', 'date'],
}
DHCP_COLUMN_MAP = {
    'ip_address': [
        'ip_address', 'ip', 'ip addr', 'ipaddress', 'client ip', 'assigned ip', 'address'
    ],
    'mac_address': [
        'mac_address', 'mac', 'mac addr', 'hardware address', 'client mac', 'macaddress'
    ],
    'lease_start': [
        'lease_start', 'start', 'lease start', 'start time', 'start_date', 'start date'
    ],
    'lease_end': [
        'lease_end', 'end', 'lease end', 'end time', 'end_date', 'end date',
        'expiry', 'expires', 'expiration', 'expiration time'
    ],
}

FW_REQUIRED_COLUMNS = list(FW_COLUMN_MAP.keys())
DHCP_REQUIRED_COLUMNS = list(DHCP_COLUMN_MAP.keys())

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

def parse_dhcp_leases(df):
    df = _normalize_columns(df, DHCP_COLUMN_MAP)
    # Clean whitespace and types
    for col in ['ip_address', 'mac_address']:
        df[col] = df[col].astype(str).str.strip()
    # Parse datetime columns (coerce errors to NaT)
    for col in ['lease_start', 'lease_end']:
        df[col] = pd.to_datetime(df[col], errors='coerce')
    # Drop rows with missing or invalid data
    df = df.dropna(subset=DHCP_REQUIRED_COLUMNS)
    return df

# --- Input Validation ---
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Datetime Parsing ---
def parse_datetime(dt_value):
    try:
        if isinstance(dt_value, pd.Timestamp):
            return dt_value
        elif isinstance(dt_value, str):
            return datetime.fromisoformat(dt_value)
        elif isinstance(dt_value, datetime):
            return dt_value
        else:
            return pd.NaT
    except Exception:
        return pd.NaT

# --- Lease Lookup Construction ---
def build_lease_lookup(dhcp_df):
    lease_dict = {}
    for _, row in dhcp_df.iterrows():
        ip = row['ip_address']
        mac = row['mac_address']
        lease_start = row['lease_start']
        lease_end = row['lease_end']
        lease_dict.setdefault(ip, []).append((lease_start, lease_end, mac))
    return lease_dict

def find_expected_mac(ip, timestamp, lease_dict):
    if ip not in lease_dict:
        return None
    for lease_start, lease_end, mac in lease_dict[ip]:
        if lease_start <= timestamp <= lease_end:
            return mac
    return None

def detect_mac_ip_mismatches(fw_df, lease_dict):
    anomalies = []
    for idx, row in fw_df.iterrows():
        ip = row['src_ip']
        mac = row['src_mac']
        timestamp = row['timestamp']
        if not mac or pd.isna(timestamp):
            continue
        expected_mac = find_expected_mac(ip, timestamp, lease_dict)
        if expected_mac and mac.lower() != expected_mac.lower():
            anomaly = row.to_dict()
            anomaly['expected_mac'] = expected_mac
            anomalies.append(anomaly)
    return pd.DataFrame(anomalies)

def generate_csv_report(df):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="MAC/IP Mismatch Detection", layout="wide")
st.title("MAC/IP Mismatch Detection: Firewall & DHCP Log Analysis")

st.markdown("""
This tool detects MAC/IP mismatches by correlating firewall logs with DHCP lease records.

**How to use:**
- Upload at least one firewall log CSV file and one DHCP lease CSV file.
- Click "Run Detection" to analyze and visualize results.
""")

if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'dhcp_df' not in st.session_state:
    st.session_state['dhcp_df'] = None
if 'anomalies_df' not in st.session_state:
    st.session_state['anomalies_df'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

firewall_file = st.file_uploader("Upload Firewall Log CSV file", type=["csv"])
dhcp_file = st.file_uploader("Upload DHCP Lease CSV file", type=["csv"])
run_analysis = st.button("Run Detection")

if run_analysis and firewall_file and dhcp_file:
    try:
        fw_raw = pd.read_csv(firewall_file)
        dhcp_raw = pd.read_csv(dhcp_file)
        fw_df = parse_firewall_log(fw_raw)
        dhcp_df = parse_dhcp_leases(dhcp_raw)
        fw_df = validate_input(fw_df, FW_REQUIRED_COLUMNS, "Firewall Log")
        dhcp_df = validate_input(dhcp_df, DHCP_REQUIRED_COLUMNS, "DHCP Lease")
        fw_df['timestamp'] = fw_df['timestamp'].apply(parse_datetime)
        dhcp_df['lease_start'] = dhcp_df['lease_start'].apply(parse_datetime)
        dhcp_df['lease_end'] = dhcp_df['lease_end'].apply(parse_datetime)
        st.session_state['fw_df'] = fw_df
        st.session_state['dhcp_df'] = dhcp_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process input files: {e}")
        st.stop()

    lease_dict = build_lease_lookup(st.session_state['dhcp_df'])
    anomalies_df = detect_mac_ip_mismatches(st.session_state['fw_df'], lease_dict)
    st.session_state['anomalies_df'] = anomalies_df
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"MAC/IP Mismatch Analysis completed at {completion_time}")
    st.write("---")

if st.session_state.get('anomalies_df') is not None and st.session_state.get('analysis_done'):
    anomalies_df = st.session_state['anomalies_df']

    if not anomalies_df.empty:
        st.warning(f"{len(anomalies_df)} MAC/IP mismatch events detected!")
        st.markdown("### Recent Mismatches (last 5)")
        st.dataframe(anomalies_df.sort_values("timestamp", ascending=False).head(5))

        st.markdown("### All Mismatches (preview)")
        st.dataframe(anomalies_df.head(20))

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Incident Counts by Source IP** | Shows which source IPs are most frequently involved in mismatches. |
| **Incident Counts by MAC Address** | Highlights which MACs are most often anomalous. |
| **Incident Counts by Expected MAC** | Reveals which expected MACs are most commonly mismatched. |
| **Heatmap of Mismatches by Hour** | Displays the distribution of mismatches across each hour of the day. |
""")

        st.subheader("Bar Chart: Incident Counts by Source IP")
        src_ip_counts = anomalies_df["src_ip"].value_counts().reset_index().rename(
            columns={"index": "src_ip", "src_ip": "count"}
        )
        fig_ip = px.bar(
            src_ip_counts,
            x="src_ip",
            y="count",
            color_discrete_sequence=["orchid"],
            labels={"src_ip": "Source IP", "count": "Number of Mismatches"},
            title="Incident Counts by Source IP"
        )
        st.plotly_chart(fig_ip, use_container_width=True)

        st.subheader("Bar Chart: Incident Counts by MAC Address")
        mac_counts = anomalies_df["src_mac"].value_counts().reset_index().rename(
            columns={"index": "src_mac", "src_mac": "count"}
        )
        fig_mac = px.bar(
            mac_counts,
            x="src_mac",
            y="count",
            color_discrete_sequence=["skyblue"],
            labels={"src_mac": "MAC Address", "count": "Number of Mismatches"},
            title="Incident Counts by MAC Address"
        )
        st.plotly_chart(fig_mac, use_container_width=True)

        st.subheader("Bar Chart: Incident Counts by Expected MAC")
        exp_mac_counts = anomalies_df["expected_mac"].value_counts().reset_index().rename(
            columns={"index": "expected_mac", "expected_mac": "count"}
        )
        fig_exp_mac = px.bar(
            exp_mac_counts,
            x="expected_mac",
            y="count",
            color_discrete_sequence=["salmon"],
            labels={"expected_mac": "Expected MAC", "count": "Number of Mismatches"},
            title="Incident Counts by Expected MAC"
        )
        st.plotly_chart(fig_exp_mac, use_container_width=True)

        st.subheader("Heatmap: Mismatches by Hour")
        anomalies_df['hour'] = pd.to_datetime(anomalies_df['timestamp'], errors='coerce').dt.hour
        hour_counts = anomalies_df.groupby('hour').size().reindex(range(24), fill_value=0)
        heatmap_df = pd.DataFrame({'hour': range(24), 'count': hour_counts.values})
        fig_heat = px.density_heatmap(
            heatmap_df,
            x='hour',
            y=['Mismatches'] * 24,
            z='count',
            color_continuous_scale='YlOrRd',
            title='Heatmap of Mismatches by Hour'
        )
        st.plotly_chart(fig_heat, use_container_width=True)

        # --- CSV Export ---
        csv_path = generate_csv_report(anomalies_df)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f.read(),
                file_name="mac_ip_mismatch_report.csv",
                mime="text/csv"
            )
        try:
            os.remove(csv_path)
        except Exception:
            pass

    else:
        st.success("No MAC/IP mismatches detected.")
else:
    st.info("Please upload both firewall and DHCP lease files and click 'Run Detection' to begin analysis.")