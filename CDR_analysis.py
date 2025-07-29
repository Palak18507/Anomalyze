import streamlit as st
import os
from streamlit_extras.stylable_container import stylable_container

def show_cdr_analysis(case_number, investigator_name, case_name, remarks, username="Investigate"):
    # --- Fully remove spacing ---
    st.markdown("""
        <style>
        [data-testid="stSidebar"] { display: none !important; }
        [data-testid="collapsedControl"] { display: none !important; }
        header { visibility: hidden; }

        html, body {
            margin: 0 !important;
            padding: 0 !important;
            height: 100% !important;
        }

        .main {
            padding-top: 0rem !important;
            padding-bottom: 0rem !important;
            margin-top: 0rem !important;
            margin-bottom: 0rem !important;
        }

        .block-container {
            padding-top: 0rem !important;
            padding-bottom: 0rem !important;
        }

        section {
            padding-top: 0rem !important;
            margin-top: 0rem !important;
            padding-bottom: 0rem !important;
            margin-bottom: 0rem !important;
        }

        section > div:first-child {
            padding-top: 0rem !important;
            margin-top: 0rem !important;
        }
        </style>
    """, unsafe_allow_html=True)

    # Layout: sidebar and main content
    col_sidebar, col_main = st.columns([1, 5], gap="small")

    # --- SIDEBAR ---
    with col_sidebar:
        with st.container(border=True):
            st.image("logo1.png", width=180)  # Logo
            st.markdown(f"#### 👤 {username.capitalize()}")
            st.divider()

            if st.button(" IPDR Analysis"):
                st.session_state.page = "ipdr_analysis"
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
            {"title": "Call Spikes", "summary": "Detects excessive international calls or sudden spikes in outgoing volume.", "file": "Call_Spikes"},
            {"title": "Tower Jumping", "summary": "Flags rapid connections to distant towers indicating spoofing.", "file": "Tower_Jumping"},
            {"title": "Strange SIM Use", "summary": "Checks for excessive international outgoing calls.", "file": "Strange_sim_use"},
            {"title": "SIM Swapping", "summary": "Detects different IMSIs with same IMEI or new SIMs showing same pattern.", "file": "SIM_Swapping"},
            {"title": "Toll-Free Abuse", "summary": "Detects frequent calls made to toll-free numbers.", "file": "Toll_Free_Abuse"},
            {"title": "SIM Cloning", "summary": "Same IMSI used simultaneously in distant locations.", "file": "SIM_cloning"},
            {"title": "Unusual Hours", "summary": "Flags calls between 12:00 AM – 6:00 AM.", "file": "Unusual_Call_Hours"},
            {"title": "Scattered Calls", "summary": "Short frequent calls to many numbers.", "file": "Scattered_Calls"},
            {"title": "Repeat Calls", "summary": "Detects repeated call failures and common callees.", "file": "Repeated_Calls"},
            {"title": "Number Morphing", "summary": "Same IMSI used across different phone numbers/devices.", "file": "Number_Morphing"},
            {"title": "Burst Call Detector", "summary": "Detect quick succession call bursts.", "file": "Burst_Call_Detector"},
            {"title": "Roaming Mismatch Detector", "summary": "Mismatch between roaming and location.", "file": "roaming_mismatch"},
        ]

        if 'selected_feature' not in st.session_state:
            st.markdown(f"""
                <div style='background-color:#191970;padding:20px 36px 16px 36px;border-radius:16px 16px 0 0;margin-bottom:1.5rem;'>
                    <div style='flex:1;'>
                        <span style='font-size:2.2rem;font-weight:700;color:#fff;'>Case: {case_number}</span><br>
                        <span style='font-size:1.1rem;color:#eae6f7;'>Investigator: {investigator_name}</span><br>
                        <span style='font-size:1.1rem;color:#eae6f7;'>Case Name: {case_name}</span>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            st.markdown("## CDR Analysis")
            st.markdown("#### Select a feature to begin analysis")

            # Feature cards (3 per row)
            cols = st.columns(3)
            for idx, feature in enumerate(features):
                with cols[idx % 3]:
                    with stylable_container(
                        key=f"card_{idx}",
                        css_styles="""
                            button {
                                background-color: #191970;
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
                                background-color: #f0a73b;
                                color: #191970;
                                transform: scale(1.02);
                                cursor: pointer;
                            }
                        """
                    ):
                        if st.button(f"{feature['title']}\n\n{feature['summary']}", key=f"btn_{idx}"):
                            st.session_state.selected_feature = feature['file']
                            st.rerun()

            if remarks:
                st.markdown("---")
                st.markdown(f"**Case Remarks:** {remarks}")

        else:
            # --- FEATURE EXECUTION ---
            selected = st.session_state.selected_feature
            feature_path = os.path.join("pages", "cdr_pages", f"{selected}.py")
            st.markdown(f"## {selected.replace('_', ' ')} Analysis")

            if os.path.exists(feature_path):
                try:
                    with open(feature_path, "r") as f:
                        exec(f.read(), globals())
                except Exception as e:
                    st.error(f"Error while executing {selected}: {e}")
            else:
                st.error(f"Feature file not found: {feature_path}")

            if st.button("⬅️ Back to CDR Feature Grid"):
                del st.session_state.selected_feature
                st.rerun()