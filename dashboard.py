import streamlit as st
import base64
from streamlit_extras.stylable_container import stylable_container

# Import the analysis modules
from CDR_analysis import show_cdr_analysis
from IPDR_analysis import show_ipdr_analysis
from FIREWALL_analysis import show_firewall_analysis
from CO_Relation_analysis import show_correlation_analysis

def get_base64_image():
    with open("logo1.png", "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

def dashboard_css():
    st.markdown("""
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <style>
    .main .block-container {
        padding: 0 !important;
        max-width: 100% !important;
    }
    body, [data-testid="stAppViewContainer"] {
        background: #e2e2e2 !important;
    }
    .dashboard-header {
        position: fixed;
        left: 0;
        top: 0;
        width: 100vw;
        height: 200px;
        z-index: 10;
        background: #191970;
        padding: 24px 40px 0px 40px;
        display: flex;
        align-items: center;
        border-bottom: 1px solid #dcdcdc;
        box-sizing: border-box;
    }
    .dashboard-title {
        font-size: 3rem;
        font-weight: 700;
        color: #ffff;
        margin-right: 32px;
    }
    .dashboard-header-spacer {
        flex: 1;
    }
    .user-actions {
        display: flex;
        flex-direction: column;
        align-items: flex-end;
        gap: 8px;
        margin-left: auto;
    }
    .user-box {
        font-size: 2rem;
        font-weight: 600;
        color: #ffff;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .user-avatar {
        width: 32px;
        height: 32px;
        background: #eae6f7;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.2rem;
    }
    .dashboard-main {
        display:fle;
        justify-content: flex-end;
        margin-top: 5px;
        padding: 0 24px 24px 250px;
        padding-left: 250px;
        margin-top: 170px;
        width: 100vw;
        box-sizing: border-box;
        max-width: none;
    }
    .dashboard-card {
        background: #191970;
        border-radius: 16px;
        padding: 24px;
        height: 220px;
        max-width: 400px;
        font-size: 2rem;
        font-weight: 700;
        color: #ffff;
        position: relative;
        box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 16px;
    }
    .dashboard-card .icon {
        font-size: 2.2rem;
        margin-left: 0px;
        margin-bottom:8px;
        color: #fff !important;
    }
    [data-testid="stSidebar"] {
        position: relative !important;
        background-color: white !important;
        padding-left: 0 !important;
        width: 250px !important;
        border-right: 1px solid #FAF9F6 !important;
    }
    [data-testid="collapsedControl"] {
        display: none !important;
    }
    </style>
    """, unsafe_allow_html=True)

def dashboard(username):
    dashboard_css()

    if "page" not in st.session_state:
        st.session_state.page = "main"
    if "form_submitted" not in st.session_state:
        st.session_state.form_submitted = False

    st.sidebar.image("logo1.png", use_container_width=True)
    st.sidebar.markdown(f"### 👤 {username}")
    st.sidebar.markdown("---")

    if st.sidebar.button(" Logout"):
        st.session_state.logged_in = False
        st.session_state.current_user = ""
        st.session_state.page = "main"
        st.session_state.form_submitted = False
        st.rerun()

    # Show header on dashboard and forms, but NOT on analysis pages
    if st.session_state.page in ["main", "cdr", "ipdr", "firewall", "correlation"]:
        st.markdown(f'''
            <div class="dashboard-header">
                <div class="dashboard-title">Dashboard</div>
                <div class="dashboard-header-spacer"></div>
                <div class="user-actions">
                    <div class="user-box">
                        {username.upper()}
                        <div class="user-avatar">👤</div>
                    </div>
                </div>
            </div>
        ''', unsafe_allow_html=True)

    st.markdown('<div class="dashboard-main">', unsafe_allow_html=True)

    # MAIN DASHBOARD PAGE
    if st.session_state.page == "main":
        col1, col2 = st.columns([1 , 1])

        with col1:
            st.markdown('''
                <div class="dashboard-card">
                    Marked Cases
                    <span class="icon"><i class="fa-solid fa-star"></i></span>
                </div>
                <div class="dashboard-card">
                    Visit previous cases
                    <span class="icon"><i class="fa-solid fa-clock-rotate-left"></i></span>
                </div>
            ''', unsafe_allow_html=True)

        with col2:
            st.markdown('''
                <div style="font-size: 2rem; font-weight: bold; color: #000; margin-bottom: 24px; background: white; padding: 16px 24px; border-radius: 12px;">
                    Upload a new case:
            ''', unsafe_allow_html=True)

            # CDR Button
            with stylable_container("cdr_button", css_styles="""
                button {
                    background-color: #4CAF50;
                    color: white;
                    border-radius: 12px;
                    height: 60px;
                    font-size: 1.2rem;
                    margin-bottom: 12px;
                    width: 100%;
                    opacity: 50%;
                }
            """):
                if st.button("CDR", key="cdr"):
                    st.session_state.page = "cdr"
                    st.session_state.form_submitted = False
                    st.rerun()

            # IPDR Button
            with stylable_container("ipdr_button", css_styles="""
                button {
                    background-color: #539987;
                    color: white;
                    border-radius: 12px;
                    height: 60px;
                    font-size: 1.2rem;
                    margin-bottom: 12px;
                    width: 100%;
                   opacity:50%;
                }
            """):
                if st.button("IPDR", key="ipdr"):
                    st.session_state.page = "ipdr"
                    st.session_state.form_submitted = False
                    st.rerun()

            # FIREWALL Button
            with stylable_container("firewall_button", css_styles="""
                button {
                    background-color: #FF9800;
                    color: white;
                    border-radius: 12px;
                    height: 60px;
                    font-size: 1.2rem;
                    margin-bottom: 12px;
                    width: 100%;
                    opacity: 50%
                }
            """):
                if st.button("FIREWALL", key="firewall"):
                    st.session_state.page = "firewall"
                    st.session_state.form_submitted = False
                    st.rerun()

            # CO-RELATION Button
            with stylable_container("correlation_button", css_styles="""
                button {
                    background-color: #880808;
                    color: white;
                    border-radius: 12px;
                    height: 60px;
                    font-size: 1.2rem;
                    margin-bottom: 12px;
                    width: 100%;
                    opacity: 50%;
                }
            """):
                if st.button("CO-RELATION", key="correlation"):
                    st.session_state.page = "correlation"
                    st.session_state.form_submitted = False
                    st.rerun()

            st.markdown('</div>', unsafe_allow_html=True)

    # FORM PAGES
    elif st.session_state.page in ["cdr", "ipdr", "firewall", "correlation"]:
        st.markdown(f"### Uploading **{st.session_state.page.upper()}** Case")

        with st.form(f"{st.session_state.page}_form"):
            case_number = st.text_input("Case Number")
            investigator_name = st.text_input("Investigator Name")
            case_name = st.text_input("Case Name")
            remarks = st.text_area("Remarks")
            submit = st.form_submit_button("Submit")
            if submit:
                st.success(
                    f"{st.session_state.page.upper()} Case '{case_name}' (Case No: {case_number}) uploaded by {investigator_name}."
                )
                st.session_state.form_submitted = True
                st.session_state.case_number = case_number
                st.session_state.investigator_name = investigator_name
                st.session_state.case_name = case_name
                st.session_state.remarks = remarks

        # Show the "Start Analysis" button only after successful submit
        if st.session_state.form_submitted:
            analysis_labels = {
                "cdr": "Start CDR Analysis",
                "ipdr": "Start IPDR Analysis",
                "firewall": "Start FIREWALL Analysis",
                "correlation": "Start CO-RELATION Analysis"
            }
            label = analysis_labels.get(st.session_state.page, "Start Analysis")
            if st.button(label):
                st.session_state.page = f"{st.session_state.page}_analysis"
                st.session_state.form_submitted = False
                st.rerun()

        if st.button("⬅ Back to Dashboard"):
            st.session_state.page = "main"
            st.session_state.form_submitted = False
            st.rerun()

    # ANALYSIS PAGES (imported from separate files, NO back button here)
    elif st.session_state.page == "cdr_analysis":
        show_cdr_analysis(
            st.session_state.case_number,
            st.session_state.investigator_name,
            st.session_state.case_name,
            st.session_state.remarks
        )
    elif st.session_state.page == "ipdr_analysis":
        show_ipdr_analysis(
            st.session_state.case_number,
            st.session_state.investigator_name,
            st.session_state.case_name,
            st.session_state.remarks
        )
    elif st.session_state.page == "firewall_analysis":
        show_firewall_analysis(
            st.session_state.case_number,
            st.session_state.investigator_name,
            st.session_state.case_name,
            st.session_state.remarks
        )
    elif st.session_state.page == "correlation_analysis":
        show_correlation_analysis(
            st.session_state.case_number,
            st.session_state.investigator_name,
            st.session_state.case_name,
            st.session_state.remarks
        )

    st.markdown('</div>', unsafe_allow_html=True)

if __name__ == "__main__" or "streamlit" in __name__:
    dashboard("User Name")
