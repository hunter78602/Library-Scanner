import streamlit as st, requests, re, pandas as pd, json

st.set_page_config(page_title="Lib-Pro Scanner", layout="wide", page_icon="📦")
st.markdown("<style>.stMetric { background-color: #1e293b; padding: 15px; border-radius: 10px; border: 1px solid #334155; } div.stForm { background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; }</style>", unsafe_allow_html=True)
st.markdown("<h1 style='text-align: center;'>📦 Lib-Pro Scanner</h1><br>", unsafe_allow_html=True)

def check_vuln(pkg, ver, eco):
    try:
        payload = {"package": {"name": pkg, "ecosystem": eco}}
        if ver and ver != "Unknown": payload["version"] = ver
        r = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=15)
        if r.status_code != 200: return f"API_ERROR_{r.status_code}", ""
        v = r.json().get("vulns", [])
        if not v: return "Secure", "No known CVEs"
        c = list(dict.fromkeys([next((a for a in (x.get("aliases") or []) if a.startswith("CVE")), x.get("id")) for x in v]))
        return f"Vulnerable ({len(v)})", ", ".join(c[:3]) + ("..." if len(c)>3 else "")
    except Exception as e: return "Timeout_Error", str(e)[:20]

def fetch_data(pkg_in):
    res = []; s = str(pkg_in).strip().lower()
    p, tv = (s.rsplit('@', 1)[0], s.rsplit('@', 1)[1]) if '@' in s and not (s.startswith('@') and s.count('@')==1) else (s, None)
    
    if True: # PyPI
        try:
            r = requests.get(f"https://pypi.org/pypi/{p}/json", timeout=10)
            if r.status_code == 200:
                i = r.json().get('info',{}); v = tv if tv else i.get('version','Unknown')
                src = (i.get('project_urls') or {}).get('Source') or f"https://pypi.org/project/{p}/"
                desc = i.get('summary', 'No description provided.')
                vul, vdt = check_vuln(p, tv, "PyPI")
                res.append({"Library": p, "Version": v, "Registry": "PyPI", "Status": vul, "Threat Intel": vdt, "Description": desc, "Source": src})
        except: pass
        
    if True: # NPM
        try:
            r = requests.get(f"https://registry.npmjs.org/{p}", timeout=10)
            if r.status_code == 200:
                d = r.json(); v = tv if tv else d.get('dist-tags',{}).get('latest','Unknown')
                repo = d.get('repository',{}); src = repo.get('url','') if isinstance(repo,dict) else repo
                desc = d.get('description', 'No description provided.')
                vul, vdt = check_vuln(p, tv, "npm")
                res.append({"Library": p, "Version": v, "Registry": "NPM", "Status": vul, "Threat Intel": vdt, "Description": desc, "Source": src})
        except: pass
        
    if True: # NuGet
        try:
            r = requests.get(f"https://azuresearch-usnc.nuget.org/query?q={p}&take=5", timeout=10)
            if r.status_code == 200:
                em = next((x for x in r.json().get('data',[]) if x.get('id','').lower() == p), None)
                if em:
                    v = tv if tv else em.get('version','Unknown'); src = em.get('projectUrl') or f"https://www.nuget.org/packages/{p}"
                    desc = em.get('description', 'No description provided.')
                    vul, vdt = check_vuln(em.get('id'), tv, "NuGet")
                    res.append({"Library": em.get('id'), "Version": v, "Registry": "NuGet", "Status": vul, "Threat Intel": vdt, "Description": desc, "Source": src})
        except: pass
    return res
def parse_uploaded_file(file):
    extracted = []
    try:
        if file.name.endswith(".json"):
            data = json.load(file)
            deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            extracted = [f"{k}@{v.strip('^~><=')}" for k, v in deps.items()]
        elif file.name.endswith(".txt"):
            for line in file.getvalue().decode("utf-8").splitlines():
                clean = line.split('#')[0].split(';')[0].strip()
                m = re.match(r'^([a-zA-Z0-9_\-]+)(?:[=<>~]+([0-9\.]+))?', clean)
                if m: extracted.append(f"{m.group(1)}@{m.group(2)}" if m.group(2) else m.group(1))
    except Exception as e: st.error(f"File Error: {e}")
    return extracted

def fetch_github_repo(url):
    extracted = []
    match = re.search(r"github\.com/([^/]+)/([^/]+)", url)
    if not match: return []
    owner, repo = match.groups()
    repo = repo.replace(".git", "")
    
    try:
        r = requests.get(f"https://api.github.com/repos/{owner}/{repo}", timeout=10)
        if r.status_code != 200: 
            st.warning("⚠️ GitHub Repo not found or API rate limit reached.")
            return []
        branch = r.json().get("default_branch", "main")
        
        req_r = requests.get(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/requirements.txt", timeout=10)
        if req_r.status_code == 200:
            for line in req_r.text.splitlines():
                clean = line.split('#')[0].split(';')[0].strip()
                m = re.match(r'^([a-zA-Z0-9_\-]+)(?:[=<>~]+([0-9\.]+))?', clean)
                if m: extracted.append(f"{m.group(1)}@{m.group(2)}" if m.group(2) else m.group(1))
                
        pkg_r = requests.get(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/package.json", timeout=10)
        if pkg_r.status_code == 200:
            data = pkg_r.json()
            deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
            extracted.extend([f"{k}@{str(v).strip('^~><=')}" for k, v in deps.items()])
            
    except Exception as e: st.error(f"GitHub Error: {e}")
    return extracted

col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    with st.form("audit_form"):
        st.markdown("### 🎯 Target Acquisition")
        github_url = st.text_input("🌐 Paste a public GitHub Repository URL:")
        uploaded_file = st.file_uploader("📂 Drop requirements.txt or package.json:", type=["txt", "json"])
        libs_input = st.text_area("✍️ Or type manually (comma separated):", "lodash, django@1.11.0", height=68)
        run_btn = st.form_submit_button("🚀 Run Lib-Pro Scan", type="primary", use_container_width=True)

if run_btn:
    master_list = [l.strip() for l in libs_input.split(",") if l.strip()]
    
    if uploaded_file:
        parsed_libs = parse_uploaded_file(uploaded_file)
        master_list.extend(parsed_libs)
        st.info(f"📄 Ingested {len(parsed_libs)} packages from {uploaded_file.name}")
        
    if github_url.strip():
        gh_libs = fetch_github_repo(github_url.strip())
        master_list.extend(gh_libs)
        if gh_libs: st.info(f"🌐 Extracted {len(gh_libs)} dependencies from GitHub repository.")
        else: st.warning("🌐 No valid dependency files found in that GitHub repository.")

    master_list = list(dict.fromkeys(master_list))

    if master_list:
        final_data, visited = [], set()
        with st.status(f"🕵️‍♂️ Scanning {len(master_list)} targets...", expanded=True) as status:
            for lib in master_list:
                if lib in visited: continue
                visited.add(lib); st.write(f"Scanning target: `{lib}`...")
                data = fetch_data(lib)
                if data: final_data.extend(data)
            status.update(label="Audit Complete!", state="complete", expanded=False)

        if final_data:
            df = pd.DataFrame(final_data)
            st.markdown("### 📊 Threat Summary")
            m1, m2 = st.columns(2)
            m1.metric("Total Packages Scanned", len(df))
            vuln_df = df[df['Status'].str.contains('Vulnerable|Error|Timeout', case=False, na=False)]
            m2.metric("Critical Alerts", len(vuln_df))
            
            t1, t2 = st.tabs(["🚨 Active Threats", "📋 All Scanned Data"])
            cfg = {"Source": st.column_config.LinkColumn("Repository"), "Description": st.column_config.TextColumn("Description", width="large")}
            
            with t1:
                if not vuln_df.empty: st.data_editor(vuln_df, use_container_width=True, column_config=cfg, hide_index=True)
                else: st.success("🎉 No vulnerabilities or timeouts found!")
            with t2: st.data_editor(df, use_container_width=True, column_config=cfg, hide_index=True)

            st.markdown("<br>", unsafe_allow_html=True)
            with st.expander("📖 Library Profiles", expanded=False):
                for item in final_data:
                    st.markdown(f"**{item['Library']}** (`{item['Version']}`): {item['Description']}")
        else: st.error("No valid registries responded.")
