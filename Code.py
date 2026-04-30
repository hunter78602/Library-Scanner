import streamlit as st, requests, re, pandas as pd, json
from datetime import datetime

# --- Page Setup ---
st.set_page_config(page_title="Lib-Pro Scanner", layout="wide", page_icon="📦")

st.markdown("""
    <style>
    .stMetric { background-color: #1e293b; padding: 15px; border-radius: 10px; border: 1px solid #334155; } 
    div.stForm { 
        background-color: #1e293b; 
        border: 1px solid #334155; 
        border-radius: 12px; 
        padding: 20px;
        max-width: 700px; 
        margin: 0 auto;   
    }
    .stTextArea textarea { background-color: #0f172a; color: #f8fafc; }
    h1 { text-align: center; } 
    </style>
    """, unsafe_allow_html=True)

st.markdown("<h1>📦 Lib-Pro Scanner</h1>", unsafe_allow_html=True)

def check_vuln(pkg, ver, eco):
    try:
        payload = {"package": {"name": pkg, "ecosystem": eco}}
        r = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=5)
        v = r.json().get("vulns", [])
        if not v: return "Secure ✅", "No known CVEs"
        c = list(dict.fromkeys([next((a for a in (x.get("aliases") or []) if a.startswith("CVE")), x.get("id")) for x in v]))
        return f"Vulnerable 🚨 ({len(v)})", ", ".join(c[:3])
    except: return "Error ⚠️", "API Timeout"

def fetch_all_data(pkg_in):
    main_res = []; contrib_res = []; s = str(pkg_in).strip()
    gh_match = re.search(r"github\.com/([^/]+)/([^/]+)", s.lower())
    owner, repo = (gh_match.groups()) if gh_match else (None, None)

    if owner:
        try:
            r = requests.get(f"https://api.github.com/repos/{owner}/{repo}", timeout=5)
            r_u = requests.get(f"https://api.github.com/users/{owner}", timeout=5)
            r_s = requests.get(f"https://api.github.com/users/{owner}/social_accounts", timeout=5)
            r_commits = requests.get(f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=50", timeout=5)
            
            if r.status_code == 200:
                d, du, ds = r.json(), r_u.json() if r_u.status_code==200 else {}, r_s.json() if r_s.status_code==200 else []
                pushed = d.get('pushed_at', '')
                linkedin = "Not Listed"
                for acct in (ds if isinstance(ds, list) else []):
                    if "linkedin.com" in acct.get('url', '').lower(): linkedin = acct.get('url'); break
                
                website = d.get('homepage') or du.get('blog') or "Not Listed"
                if linkedin == "Not Listed" and website.startswith("http"):
                    try:
                        rw = requests.get(website, timeout=5)
                        m_li = re.search(r'href=["\'](https?://(?:www\.)?linkedin\.com/(?:company|in)/[^"\']+)["\']', rw.text, re.I)
                        if m_li: linkedin = m_li.group(1) + " (Scraped from Web)"
                    except: pass

                main_res.append({
                    "Library": f"{owner}/{repo}", "Registry": "GitHub 🐙", "Status": "Manual Audit",
                    "Organization": du.get('name') or owner, "Email": du.get('email') or "Hidden",
                    "Country": du.get('location') or "Unknown", "LinkedIn": linkedin, "Website": website,
                    "Last Update": pushed.split('T')[0] if pushed else "N/A", 
                    "Activity": "🔥 High" if pushed and (datetime.utcnow() - datetime.strptime(pushed, "%Y-%m-%dT%H:%M:%SZ")).days < 30 else "✅ Active",
                    "Stars": d.get('stargazers_count', 0), "Open Issues": d.get('open_issues_count', 0),
                    "Description": d.get('description', 'No desc')
                })

                if r_commits.status_code == 200:
                    seen = {}
                    for c in r_commits.json():
                        auth = c.get('author')
                        if auth:
                            login = auth.get('login')
                            date = c.get('commit', {}).get('author', {}).get('date', '')
                            if login not in seen:
                                seen[login] = {"Repo": f"{owner}/{repo}", "Username": login, "Latest Commit": date.split('T')[0], "Profile": auth.get('html_url'), "Recent Activity": 1}
                            else: seen[login]["Recent Activity"] += 1
                    contrib_res = list(seen.values())
        except: pass
    return main_res, contrib_res

with st.form("moderate_form"):
    st.markdown("### 🔍 Target Acquisition")
    libs_input = st.text_area("", placeholder="Enter GitHub URLs or Libraries...", height=80)
    run_btn = st.form_submit_button("🚀 Run Full Audit", use_container_width=True)

if run_btn:
    targets = [l.strip() for l in libs_input.replace("\n", ",").split(",") if l.strip()]
    if targets:
        final_main, final_contribs = [], []
        with st.status("🕵️‍♂️ Mapping Entity Intelligence...", expanded=True) as status:
            for t in targets:
                m, c = fetch_all_data(t)
                final_main.extend(m); final_contribs.extend(c)
            status.update(label="Complete!", state="complete")

        if final_main:
            df = pd.DataFrame(final_main)
            df_c = pd.DataFrame(final_contribs)
            
            t1, t2 = st.tabs(["📦 Registry Packages", "🐙 GitHub & Organization Intel"])
            
            with t1:
                reg_df = df[df['Registry'] != 'GitHub 🐙']
                if not reg_df.empty:
                    st.data_editor(reg_df, use_container_width=True, hide_index=True)
                else: st.info("No Registry packages found.")
            
            with t2:
                git_df = df[df['Registry'] == 'GitHub 🐙']
                if not git_df.empty:
                    # --- RESTRUCTURED COLUMNS FOR CLARITY ---
                    st.markdown("#### 🏢 Identity & Governance")
                    id_cols = ['Library', 'Organization', 'Country', 'LinkedIn', 'Website', 'Email']
                    st.data_editor(git_df[id_cols], use_container_width=True, hide_index=True)
                    
                    st.markdown("#### 🛠️ Technical Health & Activity")
                    tech_cols = ['Library', 'Activity', 'Last Update', 'Stars', 'Open Issues', 'Description']
                    st.data_editor(git_df[tech_cols], use_container_width=True, hide_index=True)

                    st.download_button("📥 Download Repo Intel JSON", data=git_df.to_json(orient="records", indent=4), file_name="repo_intel.json", mime="application/json")
                    
                    if not df_c.empty:
                        st.markdown("---")
                        st.markdown("#### 👥 Recent Contributor Map")
                        st.data_editor(df_c, use_container_width=True, hide_index=True, height=400)
                        st.download_button("📥 Download Contributors JSON", data=df_c.to_json(orient="records", indent=4), file_name="contributors.json", mime="application/json")

            st.markdown("---")
            c1, c2 = st.columns(2)
            c1.download_button("📄 Download Master CSV", data=df.to_csv(index=False).encode('utf-8'), file_name="audit_report.csv", mime="text/csv", use_container_width=True)
            c2.download_button("🌐 Download Master JSON", data=df.to_json(orient="records", indent=4), file_name="audit_report.json", mime="application/json", use_container_width=True)
