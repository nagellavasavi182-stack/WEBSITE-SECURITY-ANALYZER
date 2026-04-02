# utils.py

import socket
import ssl
import requests

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
        result = []

        if "Content-Security-Policy" in headers:
            result.append("✅ CSP Present")
        else:
            result.append("❌ CSP Missing")

        if "X-Frame-Options" in headers:
            result.append("✅ Clickjacking Protection")
        else:
            result.append("❌ No Clickjacking Protection")

        return result
    except:
        return ["❌ Unable to fetch headers"]

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