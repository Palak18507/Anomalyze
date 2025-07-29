import streamlit as st
import os
from streamlit_extras.stylable_container import stylable_container

def show_correlation_analysis(case_number, investigator_name, case_name, remarks, username="Investigate"):
    st.markdown("""
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
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

            .sidebar-btn {
                display: flex;
                align-items: center;
                gap: 10px;
                font-weight: 600;
                font-size: 16px;
            }

            .sidebar-btn i {
                width: 18px;
                text-align: center;
            }
        </style>
    """, unsafe_allow_html=True)

    col_sidebar, col_main = st.columns([1, 5], gap="small")

    # --- SIDEBAR ---
    with col_sidebar:
        with st.container(border=True):
            st.image("logo1.png", width=180)
            st.markdown(f"#### 👤 {username.capitalize()}")
            st.divider()

            if st.button(" CDR Analysis", key="nav_cdr"):
                st.session_state.page = "cdr_analysis"
                st.rerun()

            if st.button(" IPDR Analysis", key="nav_ipdr"):
                st.session_state.page = "ipdr_analysis"
                st.rerun()

            if st.button(" Firewall Analysis", key="nav_firewall"):
                st.session_state.page = "firewall_analysis"
                st.rerun()

            if st.button(" Back to Dashboard", key="nav_dash"):
                st.session_state.page = "main"
                st.rerun()

    # --- MAIN CONTENT ---
    with col_main:
        features = [
            {"title": "Credential Misuse", "summary": "Detects leaked or shared credentials from IPDR/CDR.", "file": "cred"},
            {"title": "Dark Web Access", "summary": "Detects access to dark web resources from IP logs.", "file": "dark_web_access"},
            {"title": "Forbidden Resource Access", "summary": "Accessing blacklisted or restricted URLs/resources.", "file": "forbidden_resource"},
            {"title": "Insider Threat Detector", "summary": "Identifies employees accessing suspicious resources.", "file": "Insider_Threat"},
            {"title": "Massive Data Exfiltration", "summary": "Flags high volume outbound transfer over short time.", "file": "massive_data_exfiltration"},
            {"title": "Off-Hour Network Access", "summary": "Finds sessions initiated outside business hours.", "file": "off_hour"},
            {"title": "Prolonged Session Access", "summary": "Unusually long access sessions detected.", "file": "prolonged_access"},
            {"title": "Silent Device Detector", "summary": "Devices idle then suddenly active with large traffic.", "file": "silent_device"},
            {"title": "WebRTC Usage Patterns", "summary": "Detects peer-to-peer (WebRTC) protocol access.", "file": "webrtc"},
            {"title": "Frequent Short Sessions", "summary": "Unusual high count of short bursts of connections.", "file": "freqshort"},
            {"title": "Overlap Session Detector", "summary": "Simultaneous sessions from different devices/users.", "file": "overlap"},
            {"title": "Geo-Location Anomaly", "summary": "Multiple cities/countries used in short intervals.", "file": "geoano"},
            {"title": "Alternate Off-Hour Detector", "summary": "Flags night access from same device/user.", "file": "offhour"},
            {"title": "Device Spoofing Detection", "summary": "Same MAC/IP used by different devices/users.", "file": "devicespoof"},
            {"title": "Same VPN Usage Detector", "summary": "Unusual volume of devices using same VPN provider.", "file": "samevpn"},
            {"title": "SIM Swap Behavior", "summary": "SIM swaps correlating with changes in activity/IP.", "file": "simswap"},
        ]

        if 'selected_correlation_feature' not in st.session_state:
            st.markdown(f"""
                <div style='background-color:#191970;padding:20px 36px 16px 36px;border-radius:16px 16px 0 0;margin-bottom:1.5rem;'>
                    <div style='flex:1;'>
                        <span style='font-size:2.2rem;font-weight:700;color:#fff;'>Case: {case_number}</span><br>
                        <span style='font-size:1.1rem;color:#eae6f7;'>Investigator: {investigator_name}</span><br>
                        <span style='font-size:1.1rem;color:#eae6f7;'>Case Name: {case_name}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            st.markdown("## CO-Relation Analysis")
            st.markdown("#### Select a feature to begin analysis")

            cols = st.columns(3)
            for idx, feature in enumerate(features):
                with cols[idx % 3]:
                    with stylable_container(
                        key=f"correlation_card_{idx}",
                        css_styles="""
                            button {
                                background-color: #539987;
                                opacity: 1.0;
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
                                background-color: #417d70;
                                transform: scale(1.02);
                                cursor: pointer;
                            }
                        """
                    ):
                        if st.button(f"{feature['title']}\n\n{feature['summary']}", key=f"correlation_btn_{idx}"):
                            st.session_state.selected_correlation_feature = feature['file']
                            st.rerun()

            if remarks:
                st.markdown("---")
                st.markdown(f"**Case Remarks:** {remarks}")

        else:
            selected = st.session_state.selected_correlation_feature
            feature_path = os.path.join("pages", "correlation_pages", f"{selected}.py")
            st.markdown(f"## {selected.replace('_', ' ')} Analysis")

            if os.path.exists(feature_path):
                try:
                    with open(feature_path, "r") as f:
                        exec(f.read(), globals())
                except Exception as e:
                    st.error(f"Error while executing `{selected}`: {e}")
            else:
                st.error(f"Feature file not found: `{feature_path}`")

            if st.button(" Back to CO-Relation Feature Grid"):
                del st.session_state.selected_correlation_feature
                st.rerun()
