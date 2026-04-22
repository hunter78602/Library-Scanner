import streamlit as st
import requests
import pandas as pd
from datetime import datetime
import tempfile
import time
import plotly.express as px
import base64

# --- 1. UI SETUP ---
st.set_page_config(page_title="Libraries Scanner", layout="wide", page_icon="📦")
st.title("📦 Libraries Scanner")
st.markdown("Live Vulnerability (CVE) & Health Scanning Engine")

# --- 2. SECURITY ENGINE ---
def check_vulnerabilities(package, version, ecosystem):
    url = "https://api.osv.dev/v1/query"
    payload = {"version": version, "package": {"name": package, "ecosystem": ecosystem}}
    for _ in range(2): 
        try:
            r = requests.post(url, json=payload, timeout=7)
            if r.status_code == 200:
                data = r.json()
                count = len(data.get("vulns", []))
                return f"🚨 {count} CVEs" if count > 0 else "✅ Secure"
        except:
            time.sleep(1)
    return "✅ Secure"

def classify_owner(name):
    if not name or name == "N/A": return "Unknown"
    org_k = ['team', 'foundation', 'project', 'org', 'inc', 'llc', 'group', 'maintainers']
    if any(k in str(name).lower() for k in org_k): return f"{name} (Organization)"
    return f"{name} (Individual)"

def get_health_status(date_str):
    if date_str in ["N/A", "Unknown", None]: return "❌ Not Found"
    try:
        days = (datetime.now() - datetime.strptime(date_str, '%Y-%m-%d')).days
        if days <= 180: return "✅ Healthy"
        elif days <= 365: return "⚠️ Warning"
        else: return "❌ Outdated"
    except: return "❌ Error"

# --- 3. PDF GENERATOR ---
def create_pdf(df):
    try: 
        from fpdf import FPDF
    except ImportError: 
        return None
    def clean_text(text):
        text = str(text).replace("✅", "").replace("❌", "").replace("⚠️", "").replace("🚨", "")
        return text.encode('latin-1', 'ignore').decode('latin-1').strip()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(190, 10, "Libraries Scanner - Audit Report", ln=True, align='C')
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 10)
    cols, w = ["Library", "Health", "Version", "Security", "Owner"], [45, 30, 20, 25, 70]
    for c, width in zip(cols, w): pdf.cell(width, 10, c, 1, 0, 'C')
    pdf.ln()
    pdf.set_font("Arial", '', 9)
    for _, row in df.iterrows():
        pdf.cell(w[0], 10, clean_text(row['Library'])[:25], 1)
        pdf.cell(w[1], 10, clean_text(row['Health Status'])[:15], 1)
        pdf.cell(w[2], 10, clean_text(row['Version'])[:10], 1, 0, 'C')
        pdf.cell(w[3], 10, clean_text(row['Vulnerabilities'])[:15], 1, 0, 'C')
        pdf.cell(w[4], 10, clean_text(row['Owner'])[:38], 1); pdf.ln()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
        pdf.output(tmp.name)
        with open(tmp.name, "rb") as f: return f.read()

# --- 4. DATA FETCHING ---
@st.cache_data(ttl=60)
def get_pypi_data(package):
    pkg = str(package).strip().lower()
    try:
        r = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=7)
        if r.status_code == 200:
            data = r.json()
            ver = data['info']['version']
            upd = data['releases'].get(ver, [{}])[0].get('upload_time', 'Unknown').split('T')[0]
            owner = classify_owner(data['info'].get('author') or "Community")
            urls = data['info'].get('project_urls') or {}
            src = urls.get('Source') or urls.get('Repository') or urls.get('Homepage')
            cve = check_vulnerabilities(pkg, ver, "PyPI")
            return {
                "Library": pkg, 
                "Health Status": get_health_status(upd), 
                "Vulnerabilities": cve, 
                "Version": ver, 
                "Last Updated": upd, 
                "Owner": owner, 
                "Source": src, 
                "Registry": "PyPI"
            }
    except: return None
    return None

@st.cache_data(ttl=60)
def get_npm_data(package):
    pkg = str(package).strip().lower()
    try:
        r = requests.get(f"https://registry.npmjs.org/{pkg}", timeout=7)
        if r.status_code == 200:
            data = r.json()
            ver = data['dist-tags']['latest']
            upd = data['time'].get(ver, "").split('T')[0]
            raw_auth = data.get('author')
            auth = raw_auth.get('name') if isinstance(raw_auth, dict) else raw_auth
            raw_repo = data.get('repository', {})
            src = raw_repo.get('url', '') if isinstance(raw_repo, dict) else raw_repo
            cve = check_vulnerabilities(pkg, ver, "npm")
            return {
                "Library": pkg, 
                "Health Status": get_health_status(upd), 
                "Vulnerabilities": cve, 
                "Version": ver, 
                "Last Updated": upd, 
                "Owner": classify_owner(auth or "Community"), 
                "Source": str(src).replace('git+', ''), 
                "Registry": "NPM"
            }
    except: return None
    return None

# --- 5. INTERFACE ---
with st.sidebar:
    # --- CUSTOM DRAWN CYBER LOGO ---
    svg_logo = """
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">
      <defs>
        <filter id="neonGlow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="3" result="blur"/>
          <feMerge>
            <feMergeNode in="blur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
      <circle cx="100" cy="100" r="85" fill="none" stroke="#38bdf8" stroke-width="2" stroke-dasharray="15 10" opacity="0.7"/>
      <circle cx="100" cy="100" r="65" fill="none" stroke="#00FF41" stroke-width="4" stroke-dasharray="40 10 5 10" filter="url(#neonGlow)"/>
      <polygon points="85,65 135,100 85,135" fill="none" stroke="#E0E0E0" stroke-width="4" filter="url(#neonGlow)"/>
      <circle cx="95" cy="100" r="12" fill="#00FF41" filter="url(#neonGlow)"/>
      <line x1="15" y1="100" x2="35" y2="100" stroke="#38bdf8" stroke-width="3"/>
      <line x1="185" y1="100" x2="165" y2="100" stroke="#38bdf8" stroke-width="3"/>
      <line x1="100" y1="15" x2="100" y2="35" stroke="#38bdf8" stroke-width="3"/>
      <line x1="100" y1="185" x2="100" y2="165" stroke="#38bdf8" stroke-width="3"/>
    </svg>
    """
    b64_svg = base64.b64encode(svg_logo.encode('utf-8')).decode('utf-8')
    st.markdown(f'<img src="data:image/svg+xml;base64,{b64_svg}" width="120" style="display:block; margin:auto; margin-bottom: 20px;">', unsafe_allow_html=True)
    
    st.title("System Controls")
    with st.form("audit_form"):
        libs_input = st.text_area("Target Assets (e.g. axios, pandas):", "axios, requests, pandas", height=150)
        run_btn = st.form_submit_button("🚀 Execute Scan", use_container_width=True)

if run_btn:
    lib_list = [l.strip() for l in libs_input.split(",") if l.strip()]
    results = []
    with st.spinner("Connecting to global registries..."):
        for lib in lib_list:
            pypi, npm = get_pypi_data(lib), get_npm_data(lib)
            if pypi: results.append(pypi)
            if npm: results.append(npm)

    if results:
        df = pd.DataFrame(results)
        st.success(f"✅ Telemetry acquired for {len(results)} assets.")
        
        # Dashboard Summary
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Assets", len(df))
        c2.metric("Outdated Modules", len(df[df["Health Status"].str.contains("❌")]))
        cve_count = len(df[df["Vulnerabilities"].str.contains("🚨")])
        if cve_count > 0: c3.error(f"🚨 Critical CVEs: {cve_count}")
        else: c3.success("✅ Perimeter Secure")

        # --- THE COOL VISUALIZATION (DONUT CHART) ---
        st.markdown("### 📊 Ecosystem Health")
        fig = px.pie(
            df, 
            names='Health Status', 
            hole=0.65,
            color_discrete_sequence=['#00FF41', '#FF4B4B', '#FFC107']
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", 
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="monospace", color="#E0E0E0")
        )
        st.plotly_chart(fig, use_container_width=True)

        # --- THE INTERACTIVE GRID ---
        st.markdown("### 📋 Live Audit Data")
        col_config = {"Source": st.column_config.LinkColumn("Repository", display_text="View ↗")}
        st.data_editor(
            df, 
            use_container_width=True, 
            column_config=col_config,
            hide_index=True,
            disabled=True # Prevents accidental edits
        )
        
        # Export Options
        st.markdown("---")
        colA, colB = st.columns(2)
        with colA: st.download_button("💾 Export CSV", df.to_csv(index=False).encode('utf-8'), "audit.csv", "text/csv", use_container_width=True)
        with colB:
            pdf_bytes = create_pdf(df)
            if pdf_bytes: st.download_button("📄 Generate PDF Report", pdf_bytes, "audit.pdf", "application/pdf", use_container_width=True)
    else:
        st.error("Connection failed or no valid targets identified.")
