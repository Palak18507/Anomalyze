import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile
import os
from datetime import datetime
from geopy.geocoders import Nominatim
from geopy.extra.rate_limiter import RateLimiter

# --- Column normalization map ---
CDR_COLUMN_MAP = {
    "calling_number": ["calling_number", "caller", "msisdn"],
    "imei": ["imei"],
    "start_time": ["start_time", "timestamp"],
    "end_time": ["end_time"],
    "city": ["city", "location"],
    "latitude": ["latitude", "lat"],
    "longitude": ["longitude", "lon", "lng"],
    "roaming_status": ["roaming_status", "roaming"]
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

def parse_cdr(df):
    return _normalize_columns(df, CDR_COLUMN_MAP)

REQUIRED_COLUMNS = list(CDR_COLUMN_MAP.keys())

def validate_input(df, required_columns=REQUIRED_COLUMNS, job_name="Roaming/GeoIP Analysis"):
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()
    return df

# --- Country code mapping (prefix: country) ---
COUNTRY_CODE_MAP = {
    '1': 'USA/Canada',
    '7': 'Russia/Kazakhstan',
    '20': 'Egypt',
    '27': 'South Africa',
    '30': 'Greece',
    '31': 'Netherlands',
    '32': 'Belgium',
    '33': 'France',
    '34': 'Spain',
    '36': 'Hungary',
    '39': 'Italy',
    '40': 'Romania',
    '41': 'Switzerland',
    '43': 'Austria',
    '44': 'UK',
    '45': 'Denmark',
    '46': 'Sweden',
    '47': 'Norway',
    '48': 'Poland',
    '49': 'Germany',
    '51': 'Peru',
    '52': 'Mexico',
    '53': 'Cuba',
    '54': 'Argentina',
    '55': 'Brazil',
    '56': 'Chile',
    '57': 'Colombia',
    '58': 'Venezuela',
    '60': 'Malaysia',
    '61': 'Australia',
    '62': 'Indonesia',
    '63': 'Philippines',
    '64': 'New Zealand',
    '65': 'Singapore',
    '66': 'Thailand',
    '81': 'Japan',
    '82': 'South Korea',
    '84': 'Vietnam',
    '86': 'China',
    '90': 'Turkey',
    '91': 'India',
    '92': 'Pakistan',
    '93': 'Afghanistan',
    '94': 'Sri Lanka',
    '95': 'Myanmar',
    '98': 'Iran',
    '211': 'South Sudan',
    '212': 'Morocco',
    '213': 'Algeria',
    '216': 'Tunisia',
    '218': 'Libya',
    '220': 'Gambia',
    '221': 'Senegal',
    '222': 'Mauritania',
    '223': 'Mali',
    '224': 'Guinea',
    '225': "Côte d'Ivoire",
    '226': 'Burkina Faso',
    '227': 'Niger',
    '228': 'Togo',
    '229': 'Benin',
    '230': 'Mauritius',
    '231': 'Liberia',
    '232': 'Sierra Leone',
    '233': 'Ghana',
    '234': 'Nigeria',
    '235': 'Chad',
    '236': 'Central African Republic',
    '237': 'Cameroon',
    '238': 'Cape Verde',
    '239': 'São Tomé & Príncipe',
    '240': 'Equatorial Guinea',
    '241': 'Gabon',
    '242': 'Congo',
    '243': 'DR Congo',
    '244': 'Angola',
    '245': 'Guinea-Bissau',
    '246': 'British Indian Ocean Territory',
    '248': 'Seychelles',
    '249': 'Sudan',
    '250': 'Rwanda',
    '251': 'Ethiopia',
    '252': 'Somalia',
    '253': 'Djibouti',
    '254': 'Kenya',
    '255': 'Tanzania',
    '256': 'Uganda',
    '257': 'Burundi',
    '258': 'Mozambique',
    '260': 'Zambia',
    '261': 'Madagascar',
    '262': 'Réunion',
    '263': 'Zimbabwe',
    '264': 'Namibia',
    '265': 'Malawi',
    '266': 'Lesotho',
    '267': 'Botswana',
    '268': 'Eswatini',
    '269': 'Comoros',
    '290': 'Saint Helena',
    '291': 'Eritrea',
    '297': 'Aruba',
    '298': 'Faroe Islands',
    '299': 'Greenland',
    '350': 'Gibraltar',
    '351': 'Portugal',
    '352': 'Luxembourg',
    '353': 'Ireland',
    '354': 'Iceland',
    '355': 'Albania',
    '356': 'Malta',
    '357': 'Cyprus',
    '358': 'Finland',
    '359': 'Bulgaria',
    '370': 'Lithuania',
    '371': 'Latvia',
    '372': 'Estonia',
    '373': 'Moldova',
    '374': 'Armenia',
    '375': 'Belarus',
    '376': 'Andorra',
    '377': 'Monaco',
    '378': 'San Marino',
    '379': 'Vatican City',
    '380': 'Ukraine',
    '381': 'Serbia',
    '382': 'Montenegro',
    '383': 'Kosovo',
    '385': 'Croatia',
    '386': 'Slovenia',
    '387': 'Bosnia & Herzegovina',
    '389': 'North Macedonia',
    '420': 'Czech Republic',
    '421': 'Slovakia',
    '423': 'Liechtenstein',
    '500': 'Falkland Islands',
    '501': 'Belize',
    '502': 'Guatemala',
    '503': 'El Salvador',
    '504': 'Honduras',
    '505': 'Nicaragua',
    '506': 'Costa Rica',
    '507': 'Panama',
    '508': 'Saint Pierre & Miquelon',
    '509': 'Haiti',
    '590': 'Guadeloupe',
    '591': 'Bolivia',
    '592': 'Guyana',
    '593': 'Ecuador',
    '594': 'French Guiana',
    '595': 'Paraguay',
    '596': 'Martinique',
    '597': 'Suriname',
    '598': 'Uruguay',
    '599': 'Caribbean Netherlands',
    '670': 'East Timor',
    '672': 'Australian External Territories',
    '673': 'Brunei',
    '674': 'Nauru',
    '675': 'Papua New Guinea',
    '676': 'Tonga',
    '677': 'Solomon Islands',
    '678': 'Vanuatu',
    '679': 'Fiji',
    '680': 'Palau',
    '681': 'Wallis & Futuna',
    '682': 'Cook Islands',
    '683': 'Niue',
    '685': 'Samoa',
    '686': 'Kiribati',
    '687': 'New Caledonia',
    '688': 'Tuvalu',
    '689': 'French Polynesia',
    '690': 'Tokelau',
    '691': 'Micronesia',
    '692': 'Marshall Islands',
    '850': 'North Korea',
    '852': 'Hong Kong',
    '853': 'Macau',
    '855': 'Cambodia',
    '856': 'Laos',
    '880': 'Bangladesh',
    '886': 'Taiwan',
    '960': 'Maldives',
    '961': 'Lebanon',
    '962': 'Jordan',
    '963': 'Syria',
    '964': 'Iraq',
    '965': 'Kuwait',
    '966': 'Saudi Arabia',
    '967': 'Yemen',
    '968': 'Oman',
    '970': 'Palestine',
    '971': 'UAE',
    '972': 'Israel',
    '973': 'Bahrain',
    '974': 'Qatar',
    '975': 'Bhutan',
    '976': 'Mongolia',
    '977': 'Nepal',
    '992': 'Tajikistan',
    '993': 'Turkmenistan',
    '994': 'Azerbaijan',
    '995': 'Georgia',
    '996': 'Kyrgyzstan',
    '998': 'Uzbekistan',
}
def get_country_from_number(number):
    number = str(number)
    if number.startswith('+'):
        number = number[1:]
    for length in [3, 2, 1]:
        prefix = number[:length]
        if prefix in COUNTRY_CODE_MAP:
            return COUNTRY_CODE_MAP[prefix]
    return 'Unknown'

def get_country_from_latlon(lat, lon, geolocator, geocode_cache):
    key = (round(float(lat), 3), round(float(lon), 3))
    if key in geocode_cache:
        return geocode_cache[key]
    try:
        location = geolocator.reverse((lat, lon), language='en', exactly_one=True, timeout=10)
        country = location.raw['address'].get('country', 'Unknown') if location else 'Unknown'
        geocode_cache[key] = country
        return country
    except Exception:
        geocode_cache[key] = 'Unknown'
        return 'Unknown'

def detect_roaming_mismatch(cdr_df):
    suspicious_rows = []
    geolocator = Nominatim(user_agent="cdr_geoip")
    geocode_cache = {}
    rate_limited_reverse = RateLimiter(geolocator.reverse, min_delay_seconds=1, max_retries=2, error_wait_seconds=2.0)

    for idx, row in cdr_df.iterrows():
        home_country = get_country_from_number(row['calling_number'])
        lat, lon = row['latitude'], row['longitude']
        if pd.isnull(lat) or pd.isnull(lon):
            actual_country = 'Unknown'
        else:
            actual_country = get_country_from_latlon(lat, lon, geolocator, geocode_cache)
        status = str(row['roaming_status']).strip().lower()

        if status == 'roaming' and actual_country == home_country and home_country != 'Unknown':
            case = 'roaming_status="roaming", but device is in home country'
            suspicious_rows.append({**row, 'suspicion_case': case, 'geoip_country': actual_country, 'home_country': home_country})
        elif status == 'not_roaming' and actual_country != home_country and actual_country != 'Unknown' and home_country != 'Unknown':
            case = 'roaming_status="not_roaming", but device is outside home country'
            suspicious_rows.append({**row, 'suspicion_case': case, 'geoip_country': actual_country, 'home_country': home_country})
    return pd.DataFrame(suspicious_rows)

def plot_suspicious_on_map(result_df):
    if result_df.empty:
        st.info("No suspicious records to plot.")
        return
    fig = px.scatter_mapbox(
        result_df,
        lat="latitude",
        lon="longitude",
        hover_name="calling_number",
        hover_data={
            "city": True,
            "roaming_status": True,
            "suspicion_case": True,
            "geoip_country": True,
            "home_country": True,
            "start_time": True,
            "end_time": True
        },
        color="suspicion_case",
        zoom=2,
        height=500
    )
    fig.update_layout(mapbox_style="open-street-map")
    fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
    st.plotly_chart(fig, use_container_width=True)

def safe(text):
    return str(text).encode('latin-1', 'replace').decode('latin-1')

def generate_pdf_report(result_df):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Roaming Behavior vs. GeoIP Report", ln=1, align='C')
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Suspicious Roaming Patterns Detected", ln=1)
    pdf.set_font("Arial", "", 9)
    # Table header
    pdf.set_fill_color(220, 220, 220)
    headers = ["MSISDN", "IMEI", "Start", "End", "City", "GeoIP", "Home", "Roaming", "Suspicion"]
    widths = [22, 22, 16, 16, 16, 20, 20, 20, 38]
    for i, h in enumerate(headers):
        pdf.cell(widths[i], 7, h, border=1, fill=True)
    pdf.ln()
    # Table rows
    for _, row in result_df.iterrows():
        pdf.cell(22, 7, str(row['calling_number']), border=1)
        pdf.cell(22, 7, str(row['imei']), border=1)
        pdf.cell(16, 7, str(row['start_time'])[:16], border=1)
        pdf.cell(16, 7, str(row['end_time'])[:16], border=1)
        pdf.cell(16, 7, str(row['city']), border=1)
        pdf.cell(20, 7, str(row['geoip_country']), border=1)
        pdf.cell(20, 7, str(row['home_country']), border=1)
        pdf.cell(20, 7, str(row['roaming_status']), border=1)
        pdf.cell(38, 7, str(row['suspicion_case'])[:32], border=1)
        pdf.ln()
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf.output(tmp_file.name)
    return tmp_file.name

# --- Streamlit UI with Session State Preservation ---
st.set_page_config(page_title="Roaming vs. GeoIP Suspicious Pattern Detector", layout="wide")
st.title("Roaming vs. GeoIP Suspicious Pattern Detector")

st.markdown("""
Upload a single CDR file (CSV or Excel). This tool detects mismatches between declared roaming status and device location using reverse geocoding and country code mapping.
""")

# Session state
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
        df = validate_input(df, REQUIRED_COLUMNS, "Roaming/GeoIP Analysis")
        st.session_state['df'] = df
        st.session_state['analysis_done'] = False  # Reset analysis flag on new upload
    except Exception as e:
        st.error(f"Failed to read file: {e}")
        st.stop()

if st.session_state['df'] is not None and not st.session_state['analysis_done']:
    result = detect_roaming_mismatch(st.session_state['df'])
    st.session_state['result'] = result
    st.session_state['analysis_done'] = True
    completion_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.success(f"Analysis completed at {completion_time}")
    st.write("---")

if st.session_state['result'] is not None:
    result = st.session_state['result']
    if result.empty:
        st.info("No suspicious roaming patterns detected.")
    else:
        st.error(f"Suspicious Roaming Patterns Detected! {result.shape[0]} events flagged.")
        st.dataframe(result)
        st.subheader("Suspicious Patterns Map")
        plot_suspicious_on_map(result)
        if st.button("Generate PDF Report"):
            pdf_path = generate_pdf_report(result)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="Download PDF Report",
                    data=f.read(),
                    file_name="roaming_mismatch_report.pdf",
                    mime="application/pdf"
                )
            try:
                os.remove(pdf_path)
            except Exception:
                pass
else:
    st.info("Please upload a CDR file to begin analysis.")