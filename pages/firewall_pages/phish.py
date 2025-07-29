import streamlit as st
import pandas as pd
import json
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter, defaultdict

# --- Input Validation ---
def validate_required_columns(df, required_columns, job_name="File"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        return False
    return True

# --- Domain List Loader ---
def load_domain_list(domain_file):
    domain_file.seek(0)
    domains = set()
    for line in domain_file.readlines():
        domain = line.decode("utf-8").strip().lower()
        if domain:
            domains.add(domain)
    return domains

# --- Domain Matching (Exact or Subdomain) ---
def match_domain(dest_domain, domain_set):
    dest_domain = dest_domain.lower()
    for domain in domain_set:
        if dest_domain == domain or dest_domain.endswith("." + domain):
            return domain
    return None

# --- Detection Logic ---
def detect_phishing_c2_access(df, phishing_domains, c2_domains):
    incidents = []
    for _, entry in df.iterrows():
        src_ip = entry.get("src_ip")
        dest_domain = str(entry.get("dest_domain", "")).lower()
        timestamp = entry.get("timestamp")
        matched_phishing = match_domain(dest_domain, phishing_domains)
        matched_c2 = match_domain(dest_domain, c2_domains)
        if matched_phishing:
            incidents.append({
                "type": "Phishing Domain Access",
                "src_ip": src_ip,
                "dest_domain": dest_domain,
                "matched_domain": matched_phishing,
                "timestamp": timestamp,
                "details": entry.to_dict()
            })
        if matched_c2:
            incidents.append({
                "type": "C2 Domain Access",
                "src_ip": src_ip,
                "dest_domain": dest_domain,
                "matched_domain": matched_c2,
                "timestamp": timestamp,
                "details": entry.to_dict()
            })
    return incidents

def correlate_incidents(incidents):
    correlation = defaultdict(list)
    for inc in incidents:
        correlation[inc["src_ip"]].append(inc)
    return [
        {"src_ip": ip, "incidents": incs}
        for ip, incs in correlation.items() if len(incs) > 1
    ]

def plot_heatmap_by_hour(incidents):
    if not incidents:
        st.write("No incidents to display in heatmap.")
        return
    df = pd.DataFrame(incidents)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['hour'] = df['timestamp'].dt.hour
    hour_counts = df.groupby('hour').size().reindex(range(24), fill_value=0)
    plt.figure(figsize=(10, 2))
    sns.heatmap([hour_counts.values], cmap='YlOrRd', annot=True, cbar=False, xticklabels=range(24), yticklabels=["Incidents"])
    plt.title('Heatmap of Incidents by Hour')
    plt.xlabel('Hour of Day')
    st.pyplot(plt.gcf())
    plt.close()

def generate_csv_report(incidents):
    import tempfile, os
    df = pd.DataFrame(incidents)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.csv')
    df.to_csv(tmp_file.name, index=False)
    return tmp_file.name

# --- Workflow Function ---
def workflow(log_files, phishing_file, c2_file, required_columns, job_name="Access to Phishing & C2 Domains Detector"):
    st.title(job_name)
    st.write("Upload two or more firewall log CSV files, a phishing domain list, and a C2 domain list.")

    if not log_files or len(log_files) < 2 or phishing_file is None or c2_file is None:
        st.warning("Please upload at least two log files and both domain lists to proceed.")
        st.stop()

    phishing_domains = load_domain_list(phishing_file)
    c2_domains = load_domain_list(c2_file)

    all_logs_df = []
    for uploaded_file in log_files:
        df = pd.read_csv(uploaded_file)
        if not validate_required_columns(df, required_columns, uploaded_file.name):
            st.stop()
        all_logs_df.append(df)
    combined_df = pd.concat(all_logs_df, ignore_index=True)

    incidents = detect_phishing_c2_access(combined_df, phishing_domains, c2_domains)

    completion_time = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"{job_name} completed at {completion_time}")
    st.write("----")

    st.subheader("Alert Summary")
    alert_summary = Counter([inc["type"] for inc in incidents])
    if alert_summary:
        for alert_type, count in alert_summary.items():
            st.write(f"{alert_type}: {count}")
    else:
        st.write("No phishing or C2 domain access detected.")

    # Event list
    if incidents:
        df_events = pd.DataFrame([{
            "Type": inc["type"],
            "Source IP": inc["src_ip"],
            "Destination Domain": inc["dest_domain"],
            "Matched Domain": inc["matched_domain"],
            "Timestamp": inc["timestamp"],
            "Details": json.dumps(inc["details"])
        } for inc in incidents])
        st.subheader("Event List (Detected Incidents)")
        st.dataframe(df_events)

        # Export CSV Report
        csv_path = generate_csv_report(incidents)
        with open(csv_path, "rb") as f:
            st.download_button(
                label="Download CSV Report",
                data=f.read(),
                file_name="phishing_c2_access_report.csv",
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
        plt.close(fig)
    else:
        st.write("No source IP data for bar chart.")

    # Visualization: Incident count by Destination Domain
    dest_domains = [inc["dest_domain"] for inc in incidents]
    if dest_domains:
        domain_counts = Counter(dest_domains)
        dom_list = list(domain_counts.keys())
        counts_list = list(domain_counts.values())
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.bar(dom_list, counts_list, color='skyblue')
        ax.set_title('Incident Counts by Destination Domain')
        ax.set_xlabel('Destination Domain')
        ax.set_ylabel('Number of Incidents')
        ax.grid(axis='y')
        st.pyplot(fig)
        plt.close(fig)
    else:
        st.write("No domain data for bar chart.")

    # Heatmap visualization by hour
    st.subheader("Heatmap of Incidents by Hour")
    plot_heatmap_by_hour(incidents)

    # Correlated incidents
    correlated = correlate_incidents(incidents)
    if correlated:
        st.subheader("Correlated Incidents (IPs with Multiple Incident Types)")
        for item in correlated:
            st.write(f"Source IP: {item['src_ip']} - Number of incidents: {len(item['incidents'])}")
    else:
        st.write("No correlated incidents found.")

    return completion_time

# --- Main App Entrypoint ---
def main():
    st.title("Access to Phishing & C2 Domains Detector")
    log_files = st.file_uploader(
        "Upload two or more Firewall Log CSV files", type=["csv"], accept_multiple_files=True
    )
    phishing_file = st.file_uploader("Upload Phishing Domains file (.txt, one per line)", type=["txt"])
    c2_file = st.file_uploader("Upload C2 Domains file (.txt, one per line)", type=["txt"])
    required_columns = ["src_ip", "dest_domain", "timestamp"]
    if st.button("Run Detection"):
        if not log_files or len(log_files) < 2 or phishing_file is None or c2_file is None:
            st.error("Please upload at least two log files and both domain lists before running detection.")
        else:
            workflow(
                log_files=log_files,
                phishing_file=phishing_file,
                c2_file=c2_file,
                required_columns=required_columns,
                job_name="Access to Phishing & C2 Domains Detector"
            )

if __name__ == "__main__":
    main()