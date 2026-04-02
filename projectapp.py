import os
os.environ["PANDAS_USE_PYARROW"] = "0"  

import streamlit as st
from urllib.parse import urlparse
import socket
import ssl
import requests
import pandas as pd


# -----------------------------
# ML MODEL (TRAINED INSIDE)
# -----------------------------
data = {
    "url_length": [20, 100, 150, 30, 200],
    "has_https": [1, 0, 0, 1, 0],
    "num_dots": [2, 5, 6, 2, 8],
    "label": [0, 1, 1, 0, 1]  # 0 = safe, 1 = malicious
}

df = pd.DataFrame(data)
X = df[["url_length", "has_https", "num_dots"]]
y = df["label"]

model = LogisticRegression()
model.fit(X, y)

def extract_features(url):
    return [
        len(url),
        1 if "https" in url else 0,
        url.count('.')
    ]

def predict_url(url):
    features = [extract_features(url)]
    pred = model.predict(features)[0]

    if pred == 0:
        return "✅ Safe Website"
    else:
        return "🚨 Suspicious / Phishing Website"

# -----------------------------
# SECURITY FUNCTIONS
# -----------------------------
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "❌ Unable to fetch IP"

def check_https(url):
    return "✅ HTTPS Secure" if url.startswith("https") else "❌ Not Secure (HTTP)"

def check_headers(url):
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        res = []

        if "Content-Security-Policy" in headers:
            res.append("✅ CSP Present")
        else:
            res.append("❌ CSP Missing")

        if "X-Frame-Options" in headers:
            res.append("✅ Clickjacking Protection")
        else:
            res.append("❌ No Clickjacking Protection")

        return res
    except:
        return ["❌ Header fetch failed"]

def scan_ports(domain):
    open_ports = []
    for port in [21, 22, 80, 443]:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((domain, port))
            open_ports.append(port)
        except:
            pass
        s.close()
    return open_ports

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            return "✅ SSL Valid"
    except:
        return "❌ SSL Issue"

def check_sql_injection(url):
    try:
        r = requests.get(url + "'", timeout=5)
        if "error" in r.text.lower():
            return "🚨 Possible SQL Injection"
        else:
            return "✅ No SQL Injection"
    except:
        return "❌ SQLi Test Failed"

def check_xss(url):
    try:
        payload = "<script>alert(1)</script>"
        r = requests.get(url + payload, timeout=5)
        if payload in r.text:
            return "🚨 Possible XSS"
        else:
            return "✅ No XSS"
    except:
        return "❌ XSS Test Failed"

# -----------------------------
# UI DESIGN
# -----------------------------
st.set_page_config(page_title="Website Security Analyzer", page_icon="🔒")

st.markdown("""
<style>
.stApp {
    background: linear-gradient(to right, #0f172a, #1e293b);
    color: white;
}
h1, h2, h3 {
    color: #38bdf8;
}
button {
    background-color: #38bdf8 !important;
    color: black !important;
    border-radius: 10px;
}
</style>
""", unsafe_allow_html=True)

# -----------------------------
# LOGIN SYSTEM
# -----------------------------
if "users" not in st.session_state:
    st.session_state.users = {}

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "current_user" not in st.session_state:
    st.session_state.current_user = ""

def signup():
    st.subheader("Sign Up")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Create Account"):
        st.session_state.users[u] = p
        st.success("Account created")

def login():
    st.subheader("Login")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login"):
        if u in st.session_state.users and st.session_state.users[u] == p:
            st.session_state.logged_in = True
            st.session_state.current_user = u
            st.success("Login successful")
        else:
            st.error("Invalid credentials")

if not st.session_state.logged_in:
    choice = st.radio("Select", ["Login", "Sign Up"])
    if choice == "Login":
        login()
    else:
        signup()
    st.stop()

# -----------------------------
# MAIN APP
# -----------------------------
st.title("🔒 Website Security Analyzer")
st.write(f"👤 User: {st.session_state.current_user}")

if st.button("Logout"):
    st.session_state.logged_in = False
    st.experimental_rerun()

url = st.text_input("Enter Website URL")

if st.button("Analyze"):
    if url:
        parsed = urlparse(url)

        if not parsed.scheme:
            url = "http://" + url
            parsed = urlparse(url)

        domain = parsed.netloc

        st.subheader("🔍 Results")
        st.write("🌍 Domain:", domain)
        st.write("📌 IP:", get_ip(domain))

        st.subheader("🔐 HTTPS")
        st.write(check_https(url))

        st.subheader("🛡️ Headers")
        for h in check_headers(url):
            st.write(h)

        st.subheader("📡 Ports")
        ports = scan_ports(domain)
        st.write(ports if ports else "No open ports")

        st.subheader("🔏 SSL")
        st.write(check_ssl(domain))

        # 🤖 ML Prediction
        st.subheader("🤖 ML Prediction")
        st.write(predict_url(url))

        st.subheader("🚨 Vulnerabilities")
        st.write(check_sql_injection(url))
        st.write(check_xss(url))

    else:
        st.warning("Enter URL")