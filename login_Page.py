import streamlit as st
import sqlite3
import bcrypt
from dashboard import dashboard  # Import the dashboard function

# --- SESSION STATE INITIALIZATION ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = ""
if "show_signup" not in st.session_state:
    st.session_state.show_signup = False

# --- DATABASE INITIALIZATION ---
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
init_db()

# --- DATABASE HELPER FUNCTIONS ---
def get_db_connection():
    return sqlite3.connect('users.db')

def add_user(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed.decode()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def check_user(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode(), row[0].encode()):
        return True
    return False

st.set_page_config(page_title="Anomalyze Login", layout="wide")

# --- CUSTOM CSS FOR LOGIN/SIGNUP PAGE ---
st.markdown("""
<style>
body, [data-testid="stAppViewContainer"] {
    background: #191970 !important;
}
.left-panel-custom {
    background-color: #f0a73b;
    border-radius: 24px;
    height: 400px;
    width: 650px;
    box-shadow: 0 8px 40px 0 rgba(25,25,112,0.11);
    padding: 70px 30px 0 30px;
    position: relative;
    backdrop-filter: blur(8px);
    animation: fadeIn 1.2s ease;
    opacity: 0.8;
}
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(-30px);}
    to { opacity: 0.8; transform: translateY(0);}
}
.left-panel-title {
    color: #191970;
    font-size: 6rem;
    font-weight: bold;
    text-align: left;
    line-height: 1.2;
    letter-spacing: 1px;
    text-shadow: 0 2px 12px rgba(0,0,0,0.09);
    margin-left: 70px;
    margin-top: -325px;
    width: 100%;
}
.login-title-custom {
    color: #ffff;
    font-size: 2.5rem;
    font-weight: bold;
    text-align: left;
    margin-bottom: 0.5rem;
    margin-top: 0;
    letter-spacing: 1px;
}
input[type="text"], input[type="password"] {
    color: #111 !important;
    background-color: #f6f8fa !important;
    border: 1.5px solid #bbb !important;
    border-radius: 8px !important;
    transition: border 0.2s, background 0.2s;
}
input[type="text"]::placeholder, input[type="password"]::placeholder {
    color: #888 !important;
    opacity: 0.8 !important;
}
input[type="text"]:hover, input[type="password"]:hover, 
input[type="text"]:focus, input[type="password"]:focus {
    border: 1.5px solid #27408b !important;
    background-color: #e8f0fe !important;
}
.stTextInput label, .stPassword label {
    color: #ffff !important;
}
.stButton>button {
    width: 100%;
    padding: 1.1rem;
    font-size: 1.2rem;
    font-weight: bold;
    border-radius: 10px;
    background:#f0a73b;
    color: #fff;
    box-shadow: 0 4px 16px rgba(43,65,98,0.10);
    margin-top: 1.3rem;
    transition: all 0.2s;
    border: none;
    opacity: 0.8;
}
.stButton>button:hover {
    background: #e8f0fe !important;
    color: #2b4162 !important;
    transform: scale(1.04);
    border: 1.5px solid #27408b !important;
}
/* Style the switch-link buttons to look like links */
.switch-link {
    background: none!important;
    color: #fff!important;
    border: none;
    padding: 0!important;
    font-size: 1.08rem;
    text-decoration: underline;
    cursor: pointer;
    opacity: 0.85;
    margin-top: 1.7rem;
    margin-bottom: 0;
    display: block;
    text-align: center;
}
.switch-link:hover {
    opacity: 1;
    color: #f0a73b!important;
}

/* ---- Reduce top spacing ---- */
.main .block-container {
    padding-top: 0rem !important;
}
section > div:first-child {
    margin-top: 0rem !important;
    padding-top: 0rem !important;
}
</style>
""", unsafe_allow_html=True)

def login_signup_ui():
    st.image("logo.png", width=500)
    left, right = st.columns([1, 1])
    with left:
        st.markdown('<div class="left-panel-custom">', unsafe_allow_html=True)
        st.markdown('<div class="left-panel-title">Welcome to<br>Anomalyze!</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div class="login-box-custom">', unsafe_allow_html=True)
        if not st.session_state.show_signup:
            st.markdown('<div class="login-title-custom">Login</div>', unsafe_allow_html=True)
            st.markdown('<div style="color:#ffff; margin-bottom:20px;">Welcome back! Please login to your account.</div>', unsafe_allow_html=True)
            username = st.text_input("User Name", key="login_user")
            password = st.text_input("Password", type="password", key="login_pass")
            login = st.button("LOGIN")
            if login:
                if username and password:
                    if check_user(username, password):
                        st.success(f"Welcome, {username}!")
                        st.session_state.logged_in = True
                        st.session_state.current_user = username
                        st.rerun()
                    else:
                        st.error("Invalid username or password.")
                else:
                    st.error("Please enter both username and password.")
            if st.button("Create a new account? Sign Up", key="goto_signup", help="Switch to Sign Up", type="secondary"):
                st.session_state.show_signup = True
                st.rerun()
            st.markdown('<style>[data-testid="stButton"][key="goto_signup"] button {all: unset;}</style>', unsafe_allow_html=True)
            st.markdown('<style>[data-testid="stButton"][key="goto_signup"] button{background:none!important;color:#fff!important;border:none;padding:0!important;font-size:1.08rem;text-decoration:underline;cursor:pointer;opacity:0.85;margin-top:1.7rem;display:block;text-align:center;}</style>', unsafe_allow_html=True)
            st.markdown('<style>[data-testid="stButton"][key="goto_signup"] button:hover{opacity:1;color:#f0a73b!important;}</style>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="login-title-custom">Sign Up</div>', unsafe_allow_html=True)
            st.markdown('<div style="color:#ffff; margin-bottom:20px;">Create a new account to get started.</div>', unsafe_allow_html=True)
            new_user = st.text_input("Choose a User Name", key="signup_user")
            new_password = st.text_input("Choose a Password", type="password", key="signup_pass")
            signup = st.button("SIGN UP")
            if signup:
                if new_user and new_password:
                    if add_user(new_user, new_password):
                        st.success("Account created! You can now log in.")
                        st.session_state.show_signup = False
                        st.rerun()
                    else:
                        st.error("Username already exists! Please choose another.")
                else:
                    st.error("Please enter both a username and password.")
            if st.button("Already have an account? Login", key="goto_login", help="Back to Login", type="secondary"):
                st.session_state.show_signup = False
                st.rerun()
            st.markdown('<style>[data-testid="stButton"][key="goto_login"] button {all: unset;}</style>', unsafe_allow_html=True)
            st.markdown('<style>[data-testid="stButton"][key="goto_login"] button{background:none!important;color:#fff!important;border:none;padding:0!important;font-size:1.08rem;text-decoration:underline;cursor:pointer;opacity:0.85;margin-top:1.7rem;display:block;text-align:center;}</style>', unsafe_allow_html=True)
            st.markdown('<style>[data-testid="stButton"][key="goto_login"] button:hover{opacity:1;color:#f0a73b!important;}</style>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

def main():
    if st.session_state.logged_in:
        dashboard(st.session_state.current_user)
    else:
        login_signup_ui()

main()
