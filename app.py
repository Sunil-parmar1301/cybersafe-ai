from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

import streamlit as st
import re
import tldextract
import pandas as pd
import plotly.graph_objects as go
from urllib.parse import urlparse
from datetime import datetime
from zoneinfo import ZoneInfo  # Python 3.9+

# -------------------- CONFIG --------------------
st.set_page_config(page_title="CyberSafe AI", layout="centered")

IST = ZoneInfo("Asia/Kolkata")  # Correct IST time in history/CSV

SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "pw"}
SUSPICIOUS_WORDS = [
    "urgent", "immediately", "verify", "kyc", "account", "suspended", "blocked",
    "password", "otp", "pin", "bank", "refund", "reward", "prize", "lottery",
    "click", "login", "confirm", "security alert", "update", "payment"
]
BRAND_WORDS = ["sbi", "hdfc", "icici", "axis", "paypal", "amazon", "flipkart", "google", "microsoft"]


# -------------------- THEME --------------------
def apply_theme():
    st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #0b1220 0%, #111827 50%, #0f172a 100%);
        color: #e5e7eb;
    }

    h1 { text-shadow: 0 0 18px rgba(56,189,248,0.20); }

    .card {
        background: rgba(255,255,255,0.06);
        border: 1px solid rgba(255,255,255,0.10);
        border-radius: 16px;
        padding: 16px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.35);
        margin-bottom: 14px;
    }

    .stTextArea textarea, .stTextInput input {
        border-radius: 12px !important;
    }

    .stButton button {
        border-radius: 12px !important;
        border: 1px solid rgba(255,255,255,0.15) !important;
        background: rgba(59,130,246,0.25) !important;
        color: #e5e7eb !important;
    }
    .stButton button:hover {
        background: rgba(59,130,246,0.35) !important;
    }

    [data-testid="stDataFrame"] {
        border-radius: 14px;
        overflow: hidden;
        border: 1px solid rgba(255,255,255,0.10);
    }
    </style>
    """, unsafe_allow_html=True)

apply_theme()


# -------------------- HELPERS --------------------
def now_ist_string() -> str:
    """Proper time for CSV/history in IST."""
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")


# -------------------- CORE FUNCTIONS --------------------
def extract_urls(s: str):
    return re.findall(r"(https?://[^\s]+)", s)

def domain_from_any(url_or_host: str):
    raw = url_or_host.strip()
    raw2 = "http://" + raw if "://" not in raw else raw
    try:
        u = urlparse(raw2)
        host = u.hostname or ""
    except Exception:
        host = ""
    host = host.strip(".")
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}", ext.suffix
    return host, ext.suffix

def analyze(message: str):
    score = 0
    reasons = []
    low = message.lower()

    hits = [w for w in SUSPICIOUS_WORDS if w in low]
    if hits:
        score += min(35, 5 * len(hits))
        reasons.append(f"Suspicious language detected: {', '.join(hits[:6])}")

    if re.search(r"\b(urgent|immediately|within \d+ (minutes|hours))\b", low):
        score += 10
        reasons.append("Urgency/pressure pattern")

    if re.search(r"\b(otp|one time password|pin|cvv)\b", low):
        score += 15
        reasons.append("Asking for OTP/PIN/CVV (common fraud pattern)")

    urls = extract_urls(message)
    if urls:
        reasons.append(f"Contains {len(urls)} link(s)")
    else:
        if re.search(r"\b[a-z0-9-]+\.[a-z]{2,}\b", low):
            reasons.append("Possible link/domain present")

    for u in urls[:3]:
        if u.lower().startswith("http://"):
            score += 10
            reasons.append("Insecure link (HTTP)")

        dom, tld = domain_from_any(u)

        if tld in SUSPICIOUS_TLDS:
            score += 20
            reasons.append(f"Suspicious TLD: .{tld}")

        if dom.count("-") >= 2:
            score += 7
            reasons.append("Domain has many hyphens (often used in phishing)")

        for b in BRAND_WORDS:
            if b in dom and dom != b and not dom.endswith(b):
                score += 10
                reasons.append(f"Possible brand impersonation: '{b}' in domain")

    if any(x in low for x in ["bit.ly", "tinyurl", "t.co", "cutt.ly", "rb.gy"]):
        score += 15
        reasons.append("Shortened link detected (hides real destination)")

    score = max(0, min(100, score))
    return score, reasons

def risk_label(score: int) -> str:
    if score >= 70:
        return "🚨 Scam"
    if score >= 40:
        return "⚠️ Suspicious"
    return "✅ Safe"

def gauge(score: int):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "red" if score >= 70 else ("orange" if score >= 40 else "green")}
        }
    ))
    fig.update_layout(height=260, margin=dict(l=20, r=20, t=20, b=20))
    return fig

def make_pdf_bytes(title: str, content: str) -> bytes:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    _, height = A4

    y = height - 60
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, title)

    c.setFont("Helvetica", 10)
    y -= 30

    for line in content.splitlines():
        if y < 60:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 60

        while len(line) > 110:
            c.drawString(50, y, line[:110])
            line = line[110:]
            y -= 14
            if y < 60:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 60

        c.drawString(50, y, line)
        y -= 14

    c.save()
    pdf = buffer.getvalue()
    buffer.close()
    return pdf

def complaint_template(message: str, score: int, reasons: list):
    return f"""
CYBER FRAUD / SCAM REPORT (Draft)

1) Incident Summary:
User received a suspicious message/link that appears to be a scam/phishing attempt.

2) Message/Content:
{message}

3) Risk Assessment:
Risk Score: {score}/100
Status: {risk_label(score)}
Reasons: {", ".join(reasons) if reasons else "N/A"}

4) Recommended Action Taken:
- Did NOT share OTP/password
- Did NOT enter banking details
- Reported the link/message for investigation

5) Requested Action:
Please investigate and block the fraudulent domain/link and take necessary legal action.

(Generated by CyberSafe AI)
""".strip()


# -------------------- SESSION STATE --------------------
if "history" not in st.session_state:
    st.session_state["history"] = []

if "saved_hashes" not in st.session_state:
    # store hashes only; we DO NOT show any duplicate message to user
    st.session_state["saved_hashes"] = set()


def msg_hash(s: str) -> str:
    """
    Stable-ish hash for duplicate detection.
    Normalize whitespace so minor spacing changes don't create duplicates.
    """
    normalized = re.sub(r"\s+", " ", (s or "").strip())
    # simple deterministic hash without importing hashlib (but hashlib is fine too)
    # We'll use hashlib for safer collision resistance.
    import hashlib
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# -------------------- HEADER (UPPER) --------------------
st.markdown("""
<div style="
    padding:20px;
    border-radius:16px;
    background: linear-gradient(90deg,#1e3a8a,#2563eb);
    color:white;
    text-align:center;
    margin-bottom:20px;">
    <h1 style="margin:0;">🛡️ CyberSafe AI</h1>
    <p style="margin:0;">Instant Scam / Phishing Detection Tool</p>
</div>
""", unsafe_allow_html=True)

# -------------------- SCAN BOX --------------------
st.markdown(
    '<div class="card"><b>🔎 Scan New Message / Link</b><br/>Paste SMS / Email / WhatsApp message or URL.</div>',
    unsafe_allow_html=True
)

text = st.text_area("Paste here:", value="", height=180)

col1, col2 = st.columns(2)

# -------------------- ANALYZE --------------------
if col1.button("🔍 Analyze"):
    if not text.strip():
        st.warning("Please paste a message or link.")
    else:
        score, reasons = analyze(text)
        status = risk_label(score)
        urls = extract_urls(text)

        # Always update Previous text box
        st.session_state["last_text"] = text

        # Save for report generation
        st.session_state["last_score"] = score
        st.session_state["last_reasons"] = reasons

        # Save history ONLY if not duplicate (silently)
        h = msg_hash(text)
        if h not in st.session_state["saved_hashes"]:
            st.session_state["saved_hashes"].add(h)

            st.session_state["history"].insert(0, {
                "time": now_ist_string(),  # FIXED: proper IST time string
                "risk": score,
                "status": status,
                "links": len(urls),
                "preview": (text[:80] + "...") if len(text) > 80 else text
            })
            st.session_state["history"] = st.session_state["history"][:20]

        # KPIs
        c1, c2, c3 = st.columns(3)
        c1.metric("Risk Score", f"{score}/100")
        c2.metric("Status", status)
        c3.metric("Links Found", str(len(urls)))

        left, right = st.columns([1, 1])
        with left:
            st.subheader("📈 Risk Gauge")
            st.plotly_chart(gauge(score), use_container_width=True)

        with right:
            st.subheader("🧠 Why this looks suspicious")
            if reasons:
                for r in reasons:
                    st.write("•", r)
            else:
                st.write("No obvious scam indicators found.")

        # History + CSV (time will show properly)
        st.subheader("🗂️ Recent Scans (last 20)")
        df_hist = pd.DataFrame(st.session_state["history"])
        st.dataframe(df_hist, use_container_width=True)

        st.download_button(
            "⬇️ Download Scan History (CSV)",
            data=df_hist.to_csv(index=False).encode("utf-8"),
            file_name="cybersafe_ai_history.csv",
            mime="text/csv"
        )

# -------------------- REPORT GENERATION --------------------
if col2.button("📝 Generate Complaint Draft"):
    if not text.strip():
        st.warning("Paste the message first, then generate report.")
    else:
        score = st.session_state.get("last_score")
        reasons = st.session_state.get("last_reasons")
        if score is None or reasons is None:
            score, reasons = analyze(text)

        draft = complaint_template(text, score, reasons)

        st.text_area("Copy this complaint draft:", value=draft, height=260)

        pdf_bytes = make_pdf_bytes("CyberSafe AI – Cyber Fraud Report (Draft)", draft)
        st.download_button(
            label="⬇️ Download Complaint PDF",
            data=pdf_bytes,
            file_name="cybersafe_ai_complaint.pdf",
            mime="application/pdf"
        )

        st.download_button(
            label="⬇️ Download Complaint TXT",
            data=draft.encode("utf-8"),
            file_name="cybersafe_ai_complaint.txt",
            mime="text/plain"
        )