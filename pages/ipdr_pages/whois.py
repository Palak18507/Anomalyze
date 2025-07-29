import streamlit as st
import pandas as pd
from datetime import datetime
from collections import Counter
from fpdf import FPDF
import tempfile
import plotly.express as px
import os

# --- Column Normalization Map ---
WHOIS_COLUMN_MAP = {
    "record_id": ["record_id", "id", "row_id"],
    "domain": ["domain", "domain_name", "fqdn"],
    "lookup_time": ["lookup_time", "lookup", "whois_time", "time"],
    "registration_date": ["registration_date", "registered_on", "reg_date"],
    "expiry_date": ["expiry_date", "expires_on", "expiration_date"],
    "registrar": ["registrar", "registrar_name"],
    "privacy_protected": ["privacy_protected", "privacy", "whois_privacy"],
    "privacy_provider": ["privacy_provider", "privacy_service", "privacy_vendor"]
}
REQUIRED_COLUMNS = list(WHOIS_COLUMN_MAP.keys())

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

def parse_whois(df):
    return _normalize_columns(df, WHOIS_COLUMN_MAP)

# --- Anomaly Detection Logic ---
def detect_anomalies(row, current_date, recent_days, near_expiry_days, suspicious_registrars):
    anomalies = []
    if pd.notnull(row['registration_date']) and (current_date - row['registration_date']) <= pd.Timedelta(days=recent_days):
        anomalies.append('recent_registration')
    if pd.notnull(row['expiry_date']) and row['expiry_date'] < current_date:
        anomalies.append('expired')
    elif pd.notnull(row['expiry_date']) and (row['expiry_date'] - current_date) <= pd.Timedelta(days=near_expiry_days):
        anomalies.append('near_expiry')
    if str(row['registrar']).strip() in suspicious_registrars:
        anomalies.append('suspicious_registrar')
    if row.get('privacy_protected', False):
        anomalies.append('privacy_protected')
    if row.get('privacy_protected', False) and (pd.isnull(row.get('privacy_provider')) or row.get('privacy_provider') == ""):
        anomalies.append('privacy_inconsistent')
    return anomalies

# --- Input Validation ---
def validate_input(df, required_columns, job_name="WHOIS"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"{job_name} is missing required columns: {missing}")
        st.stop()
    return df

# --- PDF Report Generation ---
def generate_pdf_report(anomalies_df, anomaly_counter, top_n=20):
    tmp_path = tempfile.mktemp(suffix=".pdf")
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "WHOIS Anomaly Detection Report", ln=1, align='C')
    pdf.set_font("Arial", size=12)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 10, f"Generated: {timestamp}", ln=1)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Top Domains with Most Anomalies", ln=1)
    pdf.set_font("Arial", size=10)
    headers = ["Domain", "Anomalies", "Anomaly Count"]
    col_widths = [60, 80, 30]
    for h, w in zip(headers, col_widths):
        pdf.cell(w, 8, h, border=1)
    pdf.ln()
    for _, row in anomalies_df.sort_values('anomaly_count', ascending=False).head(top_n).iterrows():
        pdf.cell(col_widths[0], 8, str(row['domain']), border=1)
        pdf.cell(col_widths[1], 8, str(row['anomalies']), border=1)
        pdf.cell(col_widths[2], 8, str(row['anomaly_count']), border=1)
        pdf.ln()

    pdf.ln(8)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Anomaly Type Breakdown", ln=1)
    pdf.set_font("Arial", size=10)
    pdf.cell(60, 8, "Anomaly Type", border=1)
    pdf.cell(30, 8, "Count", border=1)
    pdf.ln()
    for anomaly, count in anomaly_counter.most_common():
        pdf.cell(60, 8, anomaly, border=1)
        pdf.cell(30, 8, str(count), border=1)
        pdf.ln()

    pdf.output(tmp_path)
    return tmp_path

# --- Workflow Function ---
def workflow(whois_files, recent_days=30, near_expiry_days=30, suspicious_registrars=None):
    st.info(f"Started analysis at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    suspicious_registrars = suspicious_registrars or []
    all_whois = pd.DataFrame()
    for f in whois_files:
        df = pd.read_csv(f, parse_dates=['lookup_time', 'registration_date', 'expiry_date'])
        df = parse_whois(df)
        df = validate_input(df, REQUIRED_COLUMNS, job_name="WHOIS")
        all_whois = pd.concat([all_whois, df], ignore_index=True)
    current_date = pd.Timestamp.now()
    all_whois['anomalies'] = all_whois.apply(
        lambda row: detect_anomalies(row, current_date, recent_days, near_expiry_days, suspicious_registrars), axis=1
    )
    anomalies_df = all_whois[all_whois['anomalies'].apply(len) > 0].copy()
    anomalies_df['anomalies'] = anomalies_df['anomalies'].apply(lambda x: ', '.join(x))
    anomalies_df['anomaly_count'] = anomalies_df['anomalies'].apply(lambda x: x.count(',') + 1 if x else 0)

    st.metric("Total WHOIS Records", len(all_whois))
    st.metric("Records with Anomalies", len(anomalies_df))

    st.markdown("### 📌 Sample of Detected Anomalies")
    st.dataframe(anomalies_df[['record_id', 'domain', 'anomalies']].head(10))

    st.markdown("### 📌 Top Domains with Most Anomalies")
    top_n = 20
    top_anomalies = anomalies_df.sort_values('anomaly_count', ascending=False).head(top_n)
    st.dataframe(top_anomalies[['record_id', 'domain', 'anomalies', 'anomaly_count']])

    st.markdown("### 📌 Anomaly Type Breakdown")
    anomaly_counter = Counter()
    for anomaly_str in anomalies_df['anomalies']:
        for a in [x.strip() for x in anomaly_str.split(',') if x.strip()]:
            anomaly_counter[a] += 1
    anomaly_breakdown_df = pd.DataFrame.from_dict(anomaly_counter, orient='index', columns=['Count']).sort_values('Count', ascending=False)
    st.dataframe(anomaly_breakdown_df)

    st.subheader("Anomaly Type Distribution")
    fig = px.bar(anomaly_breakdown_df.reset_index(), x='index', y='Count',
                 labels={'index': 'Anomaly Type', 'Count': 'Count'},
                 title='Anomaly Type Frequency')
    st.plotly_chart(fig, use_container_width=True)

    if st.button("Generate PDF Report"):
        pdf_file = generate_pdf_report(anomalies_df, anomaly_counter, top_n=top_n)
        with open(pdf_file, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f,
                file_name="whois_anomaly_report.pdf",
                mime="application/pdf"
            )
        st.success("PDF Report Generated Successfully")
        try:
            os.remove(pdf_file)
        except Exception:
            pass

    st.success(f"Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# --- Main App Entrypoint ---
def main():
    st.set_page_config(page_title="WHOIS Anomaly Detection", layout="wide")
    st.title("WHOIS Anomaly Detection (Multi-File Analysis)")

    RECENT_DAYS = 30
    NEAR_EXPIRY_DAYS = 30
    SUSPICIOUS_REGISTRARS = [
        "Domain International Services Limited", "nicenic.net",
        "OPENPROV-RU", "Name.com", "Dynadot",
        "Dominet (HK) Limited", "Aceville Pte. Ltd.",
    ]

    whois_files = st.file_uploader(
        "Upload one or more WHOIS CSV files", type=["csv"], accept_multiple_files=True, key="whois"
    )
    if whois_files:
        workflow(
            whois_files=whois_files,
            recent_days=RECENT_DAYS,
            near_expiry_days=NEAR_EXPIRY_DAYS,
            suspicious_registrars=SUSPICIOUS_REGISTRARS
        )
    else:
        st.info("Please upload at least one WHOIS correlated dataset to begin.")

if __name__ == "__main__":
    main()