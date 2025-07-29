import streamlit as st
import os
from streamlit_extras.stylable_container import stylable_container

def show_ipdr_analysis(case_number, investigator_name, case_name, remarks, username="Investigate"):
    # Remove top & bottom spacing
    st.markdown("""
        <style>
            [data-testid="stSidebar"] { display: none !important; }
            [data-testid="collapsedControl"] { display: none !important; }
            header { visibility: hidden; }

            .main .block-container {
                padding-top: 0rem !important;
                padding-bottom: 0rem !important;
            }

            .main {
                padding-top: 0rem !important;
                padding-bottom: 0rem !important;
                margin-top: 0rem !important;
                margin-bottom: 0rem !important;
            }

            section > div:first-child {
                padding-top: 0rem !important;
                margin-top: 0rem !important;
            }

            section {
                padding-bottom: 0rem !important;
                margin-bottom: 0rem !important;
            }

            html, body {
                padding: 0 !important;
                margin: 0 !important;
            }
        </style>
    """, unsafe_allow_html=True)

    # Layout
    col_sidebar, col_main = st.columns([1, 5], gap="small")

    # --- SIDEBAR ---
    with col_sidebar:
        with st.container(border=True):
            st.image("logo1.png", width=180)
            st.markdown(f"#### 👤 {username.capitalize()}")
            st.divider()

            if st.button(" CDR Analysis"):
                st.session_state.page = "cdr_analysis"
                st.rerun()

            if st.button(" CO-Relation Analysis"):
                st.session_state.page = "correlation_analysis"
                st.rerun()

            if st.button(" Firewall Analysis"):
                st.session_state.page = "firewall_analysis"
                st.rerun()

            if st.button(" Back to Dashboard"):
                st.session_state.page = "main"
                st.rerun()

    # --- MAIN CONTENT ---
    with col_main:
        features = [
            {"title": "GeoIP vs WHOIS Mismatch Detector", "summary": "Flags inconsistencies between an IP’s geolocation and its WHOIS registration country.", "file": "geoip"},
            {"title": "VoIP Traffic Identifier", "summary": "Detects and highlights VoIP (Voice over IP) sessions within network traffic.", "file": "voip"},
            {"title": "Shared IP Multi-User Finder", "summary": "Finds cases where a single IP address is used by multiple distinct users.", "file": "sameip"},
            {"title": "IMEI–Multiple MSISDNs Analyzer", "summary": "Identifies devices (IMEIs) associated with more than one subscriber (MSISDN).", "file": "same_imei"},
            {"title": "Port-Protocol Anomaly Detector", "summary": "Detects non-standard or suspicious port and protocol combinations in network sessions.", "file": "port_Proto"},
            {"title": "Frequent Domain Access Analyzer", "summary": "Highlights domains accessed unusually frequently by users or devices.", "file": "freq_acc"},
            {"title": "Blacklisted IP Matcher", "summary": "Checks network activity against known blacklisted IP addresses.", "file": "blacklist_ip"},
            {"title": "DNS Resolution Anomaly Finder", "summary": "Detects suspicious or unexpected DNS query and response patterns.", "file": "dns"},
            {"title": "Data Transfer Pattern Tracking", "summary": "Uses ML to detect anomalous data transfer patterns and classify network traffic.", "file": "data_transfer"},
            {"title": "HTTP Status Code Analysis", "summary": "Monitors logs to detect anomalous HTTP status codes and request patterns.", "file": "status_code"},
            {"title": "Time-Based Access Patterns", "summary": "Detects hourly or protocol-based anomalies in access patterns.", "file": "time_based_access"},
        ]

        if 'selected_ipdr_feature' not in st.session_state:
            st.markdown(f"""
                <div style='background-color:#191970;padding:20px 36px 16px 36px;border-radius:16px 16px 0 0;margin-bottom:1.5rem;'>
                    <div style='flex:1;'>
                        <span style='font-size:2.2rem;font-weight:700;color:#fff;'>Case: {case_number}</span><br>
                        <span style='font-size:1.1rem;color:#eae6f7;'>Investigator: {investigator_name}</span><br>
                        <span style='font-size:1.1rem;color:#eae6f7;'>Case Name: {case_name}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            st.markdown("## IPDR Analysis")
            st.markdown("#### Select a feature to begin analysis")

            cols = st.columns(3)
            for idx, feature in enumerate(features):
                with cols[idx % 3]:
                    with stylable_container(
                        key=f"ipdr_card_{idx}",
                        css_styles="""
                            button {
                                background-color: #43a047;
                                opacity: 0.75;
                                color: white;
                                border-radius: 12px;
                                height: 180px;
                                font-size: 1.1rem;
                                font-weight: bold;
                                width: 100%;
                                margin-bottom: 12px;
                                border: none;
                                box-shadow: 0 4px 10px rgba(0,0,0,0.1);
                                transition: 0.2s ease-in-out;
                            }
                            button:hover {
                                background-color: #2e7d32;
                                color: white;
                                transform: scale(1.02);
                                opacity: 1.0;
                                cursor: pointer;
                            }
                        """
                    ):
                        if st.button(f"{feature['title']}\n\n{feature['summary']}", key=f"ipdr_btn_{idx}"):
                            st.session_state.selected_ipdr_feature = feature['file']
                            st.rerun()

            if remarks:
                st.markdown("---")
                st.markdown(f"**Case Remarks:** {remarks}")

        else:
            # Feature execution
            selected = st.session_state.selected_ipdr_feature
            feature_path = os.path.join("pages", "ipdr_pages", f"{selected}.py")
            st.markdown(f"## {selected.replace('_', ' ')} Analysis")

            if os.path.exists(feature_path):
                try:
                    with open(feature_path, "r") as f:
                        exec(f.read(), globals())
                except Exception as e:
                    st.error(f"Error while executing `{selected}`: {e}")
            else:
                st.error(f"Feature file not found: `{feature_path}`")

            if st.button("⬅️ Back to IPDR Feature Grid"):
                del st.session_state.selected_ipdr_feature
                st.rerun()
