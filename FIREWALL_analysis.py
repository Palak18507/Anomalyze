import streamlit as st
import os
from streamlit_extras.stylable_container import stylable_container

def show_firewall_analysis(case_number, investigator_name, case_name, remarks, username="Investigate"):
    # Enable spacing & icons
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

            if st.button("   CDR Analysis", key="nav_cdr"):
                st.session_state.page = "cdr_analysis"
                st.rerun()

            if st.button("   IPDR Analysis", key="nav_ipdr"):
                st.session_state.page = "ipdr_analysis"
                st.rerun()

            if st.button("   CO-Relation Analysis", key="nav_correlation"):
                st.session_state.page = "correlation_analysis"
                st.rerun()

            if st.button("  Back to Dashboard", key="nav_dash"):
                st.session_state.page = "main"
                st.rerun()

    # --- MAIN CONTENT ---
    with col_main:
        features = [
            {"title": "Behaviour Baselining", "summary": "Detects deviations from normal user or device behavior over time.", "file": "behaviour_baselining"},
            {"title": "Repeated Failed Logins Analyzer", "summary": "Detects repeated failed logins from the file depicting potenial brute force or types od DDOS attack", "file":   "repeated_failed_logins"},
            {"title": "Firewall Bypass Detection", "summary": "Identifies attempts to bypass firewall using unusual methods.", "file": "firewall_bypass_module"},
            {"title": "MAC-IP Mismatch Detector", "summary": "Flags inconsistencies between MAC addresses and IPs.", "file": "mac_ip_mismatch_dtetctor"},
            {"title": "Non-Server Traffic Monitor", "summary": "Detects non-standard services running on user machines.", "file": "non-server_traffic_module"},
            {"title": "Off-Hour Activity Detection", "summary": "Highlights access during unusual or unauthorized hours.", "file": "off_hour_activity_detection"},
            {"title": "Port/IP Activity Spikes", "summary": "Detects unexpected spikes in port or IP access.", "file": "port_ip_activity_spikes_module"},
            {"title": "IP Clustering Analyzer", "summary": "Clusters IP behavior to flag anomalies in communication.", "file": "ip_clustering"},
            {"title": "DNS Tunneling Detection", "summary": "Identifies covert data exfiltration via DNS queries.", "file": "dns_tunneling"},
            {"title": "Port Analysis Dashboard", "summary": "Provides insights into port access and usage patterns.", "file": "port_analysis_dshboard"},
            {"title": "IP Analysis Dashboard", "summary": "Summarizes IP-wise communication trends and outliers.", "file": "ip_analysis_dashboard"},
            {"title": "Dormant Device Bandwidth Use", "summary": "Flags bandwidth use by previously dormant devices.", "file": "bandwidth_dormant_device"},
            {"title": "Repeated Failed Login Attempts", "summary": "Detects excessive failed login attempts indicating brute-force attempts.", "file": "repeated_failed_logins"},
        ]

        if 'selected_firewall_feature' not in st.session_state:
            st.markdown(f"""
                <div style='background-color:#191970;padding:20px 36px 16px 36px;border-radius:16px 16px 0 0;margin-bottom:1.5rem;'>
                    <div style='flex:1;'>
                        <span style='font-size:2.2rem;font-weight:700;color:#fff;'>Case: {case_number}</span><br>
                        <span style='font-size:1.1rem;color:#eae6f7;'>Investigator: {investigator_name}</span><br>
                        <span style='font-size:1.1rem;color:#eae6f7;'>Case Name: {case_name}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            st.markdown("## Firewall Analysis")
            st.markdown("#### Select a feature to begin analysis")

            cols = st.columns(3)
            for idx, feature in enumerate(features):
                with cols[idx % 3]:
                    with stylable_container(
                        key=f"firewall_card_{idx}",
                        css_styles="""
                            button {
                                background-color: #b71c1c;
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
                                background-color: #7f0000;
                                transform: scale(1.02);
                                cursor: pointer;
                            }
                        """
                    ):
                        if st.button(f"{feature['title']}\n\n{feature['summary']}", key=f"firewall_btn_{idx}"):
                            st.session_state.selected_firewall_feature = feature['file']
                            st.rerun()

            if remarks:
                st.markdown("---")
                st.markdown(f"**Case Remarks:** {remarks}")

        else:
            selected = st.session_state.selected_firewall_feature
            feature_path = os.path.join("pages", "firewall_pages", f"{selected}.py")
            st.markdown(f"## {selected.replace('_', ' ')} Analysis")

            if os.path.exists(feature_path):
                try:
                    with open(feature_path, "r") as f:
                        exec(f.read(), globals())
                except Exception as e:
                    st.error(f"Error while executing `{selected}`: {e}")
            else:
                st.error(f"Feature file not found: `{feature_path}`")

            if st.button(" Back to Firewall Feature Grid"):
                del st.session_state.selected_firewall_feature
                st.rerun()
