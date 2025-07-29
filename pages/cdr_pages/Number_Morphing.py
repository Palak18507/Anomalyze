import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile
import os

# --- Column normalization map ---
CDR_COLUMN_MAP = {
    "calling_number": ["calling_number", "caller"],
    "called_number": ["called_number", "callee"],
    "call_direction": ["call_direction", "direction"],
    "duration_seconds": ["duration_seconds", "duration", "callduration"],
    "start_time": ["start_time", "timestamp"],
    "end_time": ["end_time"]
}

def _normalize_columns(df, column_map):
    """Rename columns to standard names based on mapping."""
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
    """Apply column normalization."""
    return _normalize_columns(df, CDR_COLUMN_MAP)

REQUIRED_COLUMNS = list(CDR_COLUMN_MAP.keys())

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Job"):
    """Ensure all required columns are present."""
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

def analyze_short_calls(cdr_df):
    """Detect frequent short outgoing calls (≤ 30s, ≥ 3 calls between same pair)."""
    cdr_df['duration_seconds'] = pd.to_numeric(cdr_df['duration_seconds'], errors='coerce')
    cdr_df['start_time'] = pd.to_datetime(cdr_df['start_time'], errors='coerce')
    cdr_df['end_time'] = pd.to_datetime(cdr_df['end_time'], errors='coerce')
    short_calls = cdr_df[(cdr_df['call_direction'] == 'MO') & (cdr_df['duration_seconds'] <= 30)]
    grouped = short_calls.groupby(['calling_number', 'called_number'])
    frequent_short_calls = grouped.filter(lambda x: len(x) >= 3)
    result = frequent_short_calls.groupby(['calling_number', 'called_number']).agg(
        total_calls=('duration_seconds', 'count'),
        total_duration=('duration_seconds', 'sum'),
        avg_duration=('duration_seconds', 'mean'),
        first_call=('start_time', 'min'),
        last_call=('end_time', 'max')
    ).reset_index()
    return result

def safe(text):
    """Ensure text is PDF-safe."""
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(result):
    """Generate a PDF report and return its file path."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Frequent Short Calls Report", ln=True, align='C')
    pdf.ln(10)
    if result.empty:
        pdf.cell(200, 10, txt="No frequent short calls detected.", ln=True)
    else:
        for _, row in result.iterrows():
            pdf.multi_cell(0, 10, txt=safe(f"""
Caller: {row['calling_number']}
Callee: {row['called_number']}
Total Calls: {row['total_calls']}
Total Duration (sec): {row['total_duration']}
Average Duration (sec): {row['avg_duration']:.2f}
First Call: {row['first_call']}
Last Call: {row['last_call']}
"""))
            pdf.ln(2)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

def plot_calls_bar(result):
    """Show bar chart for total calls and average duration per caller-callee pair."""
    if result.empty:
        st.info("No data for visualization.")
        return
    result['pair'] = result['calling_number'].astype(str) + '-' + result['called_number'].astype(str)
    fig = px.bar(
        result,
        x='pair',
        y=['total_calls', 'avg_duration'],
        barmode='group',
        labels={'value': 'Count / Duration (sec)', 'pair': 'Caller-Callee Pair', 'variable': 'Metric'},
        title='Total Calls and Average Duration per Caller-Callee Pair'
    )
    st.plotly_chart(fig, use_container_width=True)

def plot_calls_heatmap(cdr_df):
    """Show heatmap of short outgoing calls by hour and caller."""
    if 'start_time' not in cdr_df.columns or cdr_df['start_time'].isnull().all():
        st.info("No valid start_time data for heatmap.")
        return
    cdr_df = cdr_df.copy()
    cdr_df['hour'] = cdr_df['start_time'].dt.hour
    heatmap_data = cdr_df[(cdr_df['call_direction'] == 'MO') & (cdr_df['duration_seconds'] <= 30)]
    if heatmap_data.empty:
        st.info("No data for heatmap.")
        return
    counts = heatmap_data.groupby(['calling_number', 'hour']).size().reset_index(name='count')
    fig = px.density_heatmap(
        counts,
        x='hour',
        y='calling_number',
        z='count',
        color_continuous_scale='Blues',
        title='Heatmap of Short Outgoing Calls by Hour and Caller'
    )
    st.plotly_chart(fig, use_container_width=True)

# --- Streamlit UI with Session State Preservation ---
st.set_page_config(page_title="Frequent Short Calls Detection", layout="wide")
st.title("Frequent Short Calls Detection")

st.markdown("""
This tool detects frequent short outgoing calls (≤ 30 seconds and at least 3 calls) between any two numbers.
Upload a single CDR file in CSV or Excel format.
""")

# Initialize session state for data and results
if 'df' not in st.session_state:
    st.session_state['df'] = None
if 'result' not in st.session_state:
    st.session_state['result'] = None
if 'analysis_done' not in st.session_state:
    st.session_state['analysis_done'] = False

uploaded_file = st.file_uploader("Upload a CDR CSV or Excel File", type=["csv", "xlsx"])

if uploaded_file:
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)
        df = parse_cdr(df)
        df = validate_input(df, REQUIRED_COLUMNS, "Frequent Short Calls Detection")
        st.session_state['df'] = df
        st.session_state['analysis_done'] = False  # Reset analysis flag on new upload
    except Exception as e:
        st.error(f"Failed to read file: {e}")
        st.stop()

if st.session_state['df'] is not None and not st.session_state['analysis_done']:
    result = analyze_short_calls(st.session_state['df'])
    st.session_state['result'] = result
    st.session_state['analysis_done'] = True
    completion_time = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state['result'] is not None:
    result = st.session_state['result']
    if result.empty:
        st.info("No frequent short calls detected.")
    else:
        st.dataframe(result)

        st.subheader("Bar Chart: Total Calls and Average Duration")
        plot_calls_bar(result)

        st.subheader("Heatmap: Call Activity by Hour and Caller")
        plot_calls_heatmap(st.session_state['df'])

        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(result)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="frequent_short_calls_report.pdf",
                    mime="application/pdf"
                )
            # Ensure file is deleted after download
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a CDR file to begin analysis.")