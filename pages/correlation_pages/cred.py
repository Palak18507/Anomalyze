import streamlit as st
import pandas as pd
import plotly.express as px
import json
import tempfile
import os
from collections import Counter, defaultdict
from datetime import datetime

# --- Column Normalization Maps ---
CDR_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
    "login_status": ["login_status", "status", "auth_status"],
    "timestamp": ["timestamp", "time", "date"],
}
FW_COLUMN_MAP = {
    "src_ip": ["src_ip", "source_ip", "src", "source"],
    "event_type": ["event_type", "event", "log_type"],
    "action": ["action", "activity"],
    "timestamp": ["timestamp", "time", "date"],
}
SMS_COLUMN_MAP = {
    "phone_number": ["phone_number", "number", "msisdn"],
    "sms_status": ["sms_status", "status", "delivery_status"],
    "timestamp": ["timestamp", "time", "date"],
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

def parse_cdr(df):
    return _normalize_columns(df, CDR_COLUMN_MAP)

def parse_firewall_log(df):
    return _normalize_columns(df, FW_COLUMN_MAP)

def parse_sms_log(df):
    return _normalize_columns(df, SMS_COLUMN_MAP)

# --- Input Validation ---
def validate_input(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- Detection Logic ---
def detect_brute_force(df_cdr, df_fw, df_sms, fail_threshold=5, block_threshold=1):
    incidents = []

    # Firewall failed logins
    if df_fw is not None:
        fw_failed = df_fw[df_fw['event_type'].str.lower().str.contains('failed login')]
        fw_group = fw_failed.groupby('src_ip').size()
        for ip, count in fw_group.items():
            if count >= fail_threshold:
                incidents.append({
                    "type": "Brute Force (Firewall)",
                    "src_ip": ip,
                    "fail_count": count,
                    "details": fw_failed[fw_failed['src_ip'] == ip].to_dict('records')
                })
        if 'action' in df_fw.columns:
            blocked = df_fw[df_fw['action'].str.lower().str.contains('block')]
            for ip in blocked['src_ip'].unique():
                incidents.append({
                    "type": "Blocked IP (Firewall)",
                    "src_ip": ip,
                    "details": blocked[blocked['src_ip'] == ip].to_dict('records')
                })

    # CDR failed logins
    if df_cdr is not None and 'login_status' in df_cdr.columns:
        cdr_failed = df_cdr[df_cdr['login_status'].str.lower() == 'fail']
        cdr_group = cdr_failed.groupby('src_ip').size()
        for ip, count in cdr_group.items():
            if count >= fail_threshold:
                incidents.append({
                    "type": "Brute Force (CDR)",
                    "src_ip": ip,
                    "fail_count": count,
                    "details": cdr_failed[cdr_failed['src_ip'] == ip].to_dict('records')
                })

    # SMS failed logins
    if df_sms is not None:
        sms_failed = df_sms[df_sms['sms_status'].str.lower() == 'fail']
        sms_group = sms_failed.groupby('phone_number').size()
        for phone, count in sms_group.items():
            if count >= fail_threshold:
                incidents.append({
                    "type": "Brute Force (SMS)",
                    "phone_number": phone,
                    "fail_count": count,
                    "details": sms_failed[sms_failed['phone_number'] == phone].to_dict('records')
                })

    return incidents

def correlate_incidents(incidents):
    correlation = defaultdict(list)
    for inc in incidents:
        key = inc.get("src_ip") or inc.get("phone_number")
        correlation[key].append(inc)
    return [
        {
            "entity": key,
            "num_incidents": len(incs),
            "incident_types": ", ".join(sorted(set(i["type"] for i in incs)))
        }
        for key, incs in correlation.items() if len(incs) > 1
    ]

def generate_csv_report(incidents):
    df = pd.DataFrame(incidents)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
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

def plot_heatmap_by_hour(incidents, time_field='timestamp'):
    if not incidents:
        st.info("No incidents to display in heatmap.")
        return
    df = pd.DataFrame(incidents)
    if time_field not in df.columns:
        st.info("No timestamp data for heatmap.")
        return
    df[time_field] = pd.to_datetime(df[time_field], errors='coerce')
    df['hour'] = df[time_field].dt.hour
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

# --- Streamlit UI with Session State ---
st.set_page_config(page_title="Credential Brute Force Detection", layout="wide")
st.title("Credential Brute Force Detection: Multi-Source Log Analysis")

st.markdown("""
This tool detects brute force credential attacks from CDR, firewall, and SMS logs.

**How to use:**
- Upload one or more log files for each source (CDR, Firewall, SMS).
- Adjust detection parameters in the sidebar.
- Click "Run Detection" to analyze and visualize results.
""")

if 'cdr_df' not in st.session_state:
    st.session_state['cdr_df'] = None
if 'fw_df' not in st.session_state:
    st.session_state['fw_df'] = None
if 'sms_df' not in st.session_state:
    st.session_state['sms_df'] = None
if 'incidents' not in st.session_state:
    st.session_state['incidents'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

cdr_files = st.file_uploader(
    "Upload CDR Log CSV files", type=["csv"], accept_multiple_files=True
)
fw_files = st.file_uploader(
    "Upload Firewall Log CSV files", type=["csv"], accept_multiple_files=True
)
sms_files = st.file_uploader(
    "Upload SMS Log CSV files", type=["csv"], accept_multiple_files=True
)
st.sidebar.header("Detection Parameters")
fail_threshold = st.sidebar.number_input("Failed Login Threshold", min_value=1, value=5)
block_threshold = st.sidebar.number_input("Blocked IP Threshold", min_value=1, value=1)
run_analysis = st.button("Run Detection")

if run_analysis and (cdr_files or fw_files or sms_files):
    try:
        def load_and_concat(files, parse_func, required_columns, label):
            dfs = []
            for uploaded_file in files:
                df = pd.read_csv(uploaded_file)
                df = parse_func(df)
                df = validate_input(df, required_columns, uploaded_file.name)
                dfs.append(df)
            return pd.concat(dfs, ignore_index=True) if dfs else None

        cdr_df = load_and_concat(cdr_files, parse_cdr, ["src_ip", "login_status", "timestamp"], "CDR Log") if cdr_files else None
        fw_df = load_and_concat(fw_files, parse_firewall_log, ["src_ip", "event_type", "timestamp"], "Firewall Log") if fw_files else None
        sms_df = load_and_concat(sms_files, parse_sms_log, ["phone_number", "sms_status", "timestamp"], "SMS Log") if sms_files else None

        st.session_state['cdr_df'] = cdr_df
        st.session_state['fw_df'] = fw_df
        st.session_state['sms_df'] = sms_df
        st.session_state['analysis_done'] = False
    except Exception as e:
        st.error(f"Failed to process log files: {e}")
        st.stop()

    if not (cdr_df is not None or fw_df is not None or sms_df is not None):
        st.error("Please upload at least one log file from any source.")
        st.stop()

    incidents = detect_brute_force(cdr_df, fw_df, sms_df, fail_threshold, block_threshold)
    st.session_state['incidents'] = incidents
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Detection completed at {completion_time}")
    st.write("---")

if st.session_state.get('incidents') is not None and st.session_state.get('analysis_done'):
    incidents = st.session_state['incidents']

    st.subheader("Alert Summary")
    alert_summary = Counter([inc["type"] for inc in incidents])
    if alert_summary:
        for alert_type, count in alert_summary.items():
            st.write(f"{alert_type}: {count}")
    else:
        st.info("No brute force incidents detected.")

    if incidents:
        st.markdown("### Detected Incidents")
        df_events = pd.DataFrame([{
            "Type": inc["type"],
            "Source IP": inc.get("src_ip", ""),
            "Phone Number": inc.get("phone_number", ""),
            "Fail Count": inc.get("fail_count", ""),
            "Details": json.dumps(inc["details"])
        } for inc in incidents])
        st.dataframe(df_events)

        # --- CSV Export ---
        csv_path = generate_csv_report(incidents)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f.read(),
                file_name="credential_brute_force_report.csv",
                mime="text/csv"
            )
        try:
            os.remove(csv_path)
        except Exception:
            pass

        st.markdown("""
---
### Visualizations Overview

| Visualization | Description |
|---------------|-------------|
| **Incident Counts by Source IP** | Shows which IPs are most frequently involved in brute force activity. |
| **Incident Counts by Phone Number** | Highlights which phone numbers are most often targeted. |
| **Heatmap of Incidents by Hour** | Displays the distribution of incidents across each hour of the day. |
| **Correlated Incidents Table** | Lists entities involved in multiple types of incidents. |
""")

        st.subheader("Bar Chart: Incident Counts by Source IP")
        src_ip_counts = pd.Series([inc.get("src_ip") for inc in incidents if inc.get("src_ip")]).value_counts().reset_index().rename(
            columns={"index": "src_ip", 0: "count"}
        )
        plot_bar(src_ip_counts, "src_ip", "count", "Incident Counts by Source IP", "Source IP", "Number of Incidents", "salmon")

        st.subheader("Bar Chart: Incident Counts by Phone Number")
        phone_counts = pd.Series([inc.get("phone_number") for inc in incidents if inc.get("phone_number")]).value_counts().reset_index().rename(
            columns={"index": "phone_number", 0: "count"}
        )
        plot_bar(phone_counts, "phone_number", "count", "Incident Counts by Phone Number", "Phone Number", "Number of Incidents", "skyblue")

        st.subheader("Heatmap: Incidents by Hour")
        if st.session_state['fw_df'] is not None:
            plot_heatmap_by_hour(st.session_state['fw_df'][st.session_state['fw_df']['event_type'].str.lower().str.contains('failed login')], 'timestamp')
        elif st.session_state['cdr_df'] is not None:
            plot_heatmap_by_hour(st.session_state['cdr_df'][st.session_state['cdr_df']['login_status'].str.lower() == 'fail'], 'timestamp')
        elif st.session_state['sms_df'] is not None:
            plot_heatmap_by_hour(st.session_state['sms_df'][st.session_state['sms_df']['sms_status'].str.lower() == 'fail'], 'timestamp')
        else:
            st.info("No timestamp data for heatmap.")

        st.subheader("Correlated Incidents (Entities with Multiple Incident Types)")
        correlated = correlate_incidents(incidents)
        if correlated:
            correlated_df = pd.DataFrame(correlated)
            st.markdown("""
| Entity | Number of Incidents | Incident Types |
|--------|--------------------|---------------|
""" + "\n".join(
    f"| {row['entity']} | {row['num_incidents']} | {row['incident_types']} |"
    for _, row in correlated_df.iterrows()
))
        else:
            st.info("No correlated incidents found.")

    else:
        st.info("No incidents detected.")
else:
    st.info("Please upload log files and click 'Run Detection' to begin analysis.")