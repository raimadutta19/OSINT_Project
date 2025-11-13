# dashboard.py
import streamlit as st
import json
import os
import requests
import pandas as pd
from typing import List, Dict, Any

# ---------- Helpers to load files ----------
BASE_DIR = os.path.dirname(__file__)
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

def ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def load_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        return None

def read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        return None

# ---------- Existing loaders ----------
def load_json_report():
    file_path = os.path.join(OUTPUT_DIR, "harvester_mckvie.json")
    data = load_json_file(file_path)
    if data is None:
        st.error("❌ harvester_mckvie.json not found or invalid in output folder.")
        return {}
    return data

def read_static_output(file_name):
    file_path = os.path.join(OUTPUT_DIR, file_name)
    content = read_text_file(file_path)
    if content is None:
        return f"❌ {file_name} not found in output folder."
    return content

def run_nessus_placeholder():
    return "Nessus integration requires authenticated API access. Upload exported report instead."

# ---------- Vulnerability parsing helpers ----------
def parse_wpscan_vulns(wpscan_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Enhanced WPScan parser:
    - extracts 'interesting_findings' as findings (headers, xmlrpc, readme, mu-plugins, etc.)
    - extracts plugin/theme vulnerabilities (if present)
    - extracts top-level 'vulnerabilities' list (if present)
    - normalizes CVE lists into strings
    """
    results = []
    if not wpscan_json:
        return results

    # 0) If scan aborted, add a record so user can see it
    if isinstance(wpscan_json.get("scan_aborted"), str):
        results.append({
            "source": "wpscan",
            "component": "scan_aborted",
            "title": "Scan aborted",
            "details": wpscan_json.get("scan_aborted"),
            "severity": "info",
            "cve": []
        })

    # 1) interesting_findings -> convert to readable records
    if isinstance(wpscan_json.get("interesting_findings"), list):
        for item in wpscan_json.get("interesting_findings", []):
            rec = {
                "source": "wpscan-interesting",
                "component": item.get("type") or item.get("url") or "interesting",
                "title": item.get("to_s") or item.get("type") or item.get("url") or "",
                "details": item.get("interesting_entries") or item.get("references") or {},
                "severity": "info",
                "cve": []
            }
            # include found_by/confidence for context
            found_by = item.get("found_by")
            confidence = item.get("confidence")
            if found_by or confidence:
                rec["title"] = f"{rec['title']}  (found_by: {found_by}, confidence: {confidence})"
            results.append(rec)

    # 2) plugins -> structured vulns
    plugins = wpscan_json.get("plugins") or wpscan_json.get("identified_plugins") or {}
    if isinstance(plugins, dict):
        for plugin_name, pinfo in plugins.items():
            vulns = pinfo.get("vulnerabilities") or pinfo.get("vulns") or []
            for v in vulns:
                record = {
                    "source": "wpscan-plugin",
                    "component": plugin_name,
                    "title": v.get("title") or v.get("name") or v.get("id") or "",
                    "cve": [],
                    "severity": v.get("severity") or v.get("risk") or v.get("cvss") or "",
                    "url": []
                }
                # references: may be dict with 'cve' or 'url'
                refs = v.get("references") or {}
                if isinstance(refs, dict):
                    rawcve = refs.get("cve") or v.get("cve") or []
                    if isinstance(rawcve, list):
                        record["cve"] = [str(x).strip() for x in rawcve if x]
                    elif isinstance(rawcve, str) and rawcve:
                        record["cve"] = [rawcve.strip()]
                    rawurls = refs.get("url") or v.get("references") or []
                    if isinstance(rawurls, list):
                        record["url"] = [str(x).strip() for x in rawurls if x]
                    elif isinstance(rawurls, str) and rawurls:
                        record["url"] = [rawurls.strip()]
                else:
                    rawcve = v.get("cve") or []
                    if isinstance(rawcve, list):
                        record["cve"] = [str(x).strip() for x in rawcve if x]
                    elif isinstance(rawcve, str) and rawcve:
                        record["cve"] = [rawcve.strip()]
                    rawurls = v.get("url") or v.get("references") or []
                    if isinstance(rawurls, list):
                        record["url"] = [str(x).strip() for x in rawurls if x]
                    elif isinstance(rawurls, str) and rawurls:
                        record["url"] = [rawurls.strip()]

                results.append(record)

    # 3) themes -> structured vulns (similar to plugins)
    themes = wpscan_json.get("themes") or wpscan_json.get("identified_themes") or {}
    if isinstance(themes, dict):
        for theme_name, tinfo in themes.items():
            vulns = tinfo.get("vulnerabilities") or []
            for v in vulns:
                record = {
                    "source": "wpscan-theme",
                    "component": theme_name,
                    "title": v.get("title") or v.get("name") or "",
                    "cve": [],
                    "severity": v.get("severity") or v.get("risk") or v.get("cvss") or "",
                    "url": []
                }
                refs = v.get("references") or {}
                if isinstance(refs, dict):
                    rawcve = refs.get("cve") or v.get("cve") or []
                    if isinstance(rawcve, list):
                        record["cve"] = [str(x).strip() for x in rawcve if x]
                    elif isinstance(rawcve, str) and rawcve:
                        record["cve"] = [rawcve.strip()]
                    rawurls = refs.get("url") or v.get("references") or []
                    if isinstance(rawurls, list):
                        record["url"] = [str(x).strip() for x in rawurls if x]
                    elif isinstance(rawurls, str) and rawurls:
                        record["url"] = [rawurls.strip()]
                else:
                    rawcve = v.get("cve") or []
                    if isinstance(rawcve, list):
                        record["cve"] = [str(x).strip() for x in rawcve if x]
                    elif isinstance(rawcve, str) and rawcve:
                        record["cve"] = [rawcve.strip()]
                    rawurls = v.get("url") or v.get("references") or []
                    if isinstance(rawurls, list):
                        record["url"] = [str(x).strip() for x in rawurls if x]
                    elif isinstance(rawurls, str) and rawurls:
                        record["url"] = [rawurls.strip()]
                results.append(record)

    # 4) top-level vulnerabilities list (older/newer WPScan formats)
    top_vulns = wpscan_json.get("vulnerabilities") or wpscan_json.get("found_vulnerabilities") or []
    if isinstance(top_vulns, list):
        for v in top_vulns:
            record = {
                "source": "wpscan",
                "component": v.get("wordpress", "") or v.get("component", ""),
                "title": v.get("title") or v.get("name", ""),
                "cve": [],
                "severity": v.get("severity") or v.get("cvss", ""),
                "url": []
            }
            rawcve = v.get("cve") or v.get("references", {}).get("cve", []) if isinstance(v.get("references"), dict) else v.get("cve")
            if isinstance(rawcve, list):
                record["cve"] = [str(x).strip() for x in rawcve if x]
            elif isinstance(rawcve, str) and rawcve:
                record["cve"] = [rawcve.strip()]
            rawurls = v.get("references", {}).get("url", []) if isinstance(v.get("references"), dict) else v.get("references") or []
            if isinstance(rawurls, list):
                record["url"] = [str(x).strip() for x in rawurls if x]
            elif isinstance(rawurls, str) and rawurls:
                record["url"] = [rawurls.strip()]
            results.append(record)

    return results

def parse_nikto_output(txt: str) -> List[Dict[str, Any]]:
    """
    Quick parse for Nikto text output: extracts lines mentioning 'OSVDB' or 'CVE' or 'Server:'.
    """
    if not txt:
        return []
    vulns = []
    for line in txt.splitlines():
        l = line.strip()
        if not l:
            continue
        if "OSVDB-" in l or "CVE-" in l or "Found the following items" in l or "Server:" in l:
            vulns.append({"source": "nikto", "line": l})
    return vulns

def parse_nmap_output(txt: str) -> List[Dict[str, Any]]:
    """
    Very simple nmap text parser: looks for open ports lines like 'PORT     STATE  SERVICE'
    """
    if not txt:
        return []
    vulns = []
    started = False
    for line in txt.splitlines():
        if line.strip().startswith("PORT"):
            started = True
            continue
        if started:
            if line.strip() == "":
                break
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                state = parts[1]
                service = parts[2]
                vulns.append({"source": "nmap", "port": port, "state": state, "service": service, "raw": line.strip()})
    return vulns

# ---------- CVE details fetch ----------
CVE_API_BASE = "https://cve.circl.lu/api/cve/"

@st.cache_data(ttl=3600)
def fetch_cve_details(cve_id: str) -> Dict[str, Any]:
    if not cve_id or not cve_id.startswith("CVE-"):
        return {}
    try:
        resp = requests.get(CVE_API_BASE + cve_id, timeout=8)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"error": f"API returned {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ---------- UI ----------
def vulnerabilities_tab():
    st.header("🛡️ Vulnerabilities & Scan Summary")

    ensure_output_dir()

    st.info("You can either use the existing static WPScan output (output/wpscan_output.json) or upload a WPScan JSON file produced with `--format json`.")

    col1, col2 = st.columns([2,1])

    with col1:
        # Option to load existing file or upload new
        use_existing = st.checkbox("Use existing output/wpscan_output.json (if present)", value=True)
        uploaded_wpscan = st.file_uploader("Upload WPScan JSON", type=["json"])

        wpscan_data = None
        if use_existing:
            wpscan_path = os.path.join(OUTPUT_DIR, "wpscan_output.json")
            wpscan_data = load_json_file(wpscan_path)
            if wpscan_data is None:
                st.warning("No existing wpscan_output.json found in output folder.")
        if uploaded_wpscan:
            try:
                wpscan_data = json.load(uploaded_wpscan)
                st.success("Uploaded WPScan JSON loaded.")
            except Exception as e:
                st.error(f"Failed to parse uploaded JSON: {e}")
                wpscan_data = None

    # show scan_aborted message if present
    if wpscan_data and isinstance(wpscan_data.get("scan_aborted"), str):
        st.warning("WPScan reported that the scan was aborted: " + wpscan_data.get("scan_aborted"))
        st.info("Suggestion: re-run WPScan with --ignore-main-redirect or point to the effective URL (effective_url).")

    # Nikto and Nmap uploads / existing (moved outside column so they are always accessible)
    nikto_text = None
    nmap_text = None
    with col1:
        if st.checkbox("Use existing output/nikto_output.txt (if present)", value=False):
            nikto_text = read_text_file(os.path.join(OUTPUT_DIR, "nikto_output.txt"))
            if nikto_text is None:
                st.warning("No nikto_output.txt found in output folder.")
        nikto_upload = st.file_uploader("Upload Nikto text output", type=["txt"], key="nikto_upload")
        if nikto_upload:
            nikto_text = nikto_upload.read().decode(errors="ignore")

        if st.checkbox("Use existing output/nmap_output.txt (if present)", value=False):
            nmap_text = read_text_file(os.path.join(OUTPUT_DIR, "nmap_output.txt"))
            if nmap_text is None:
                st.warning("No nmap_output.txt found in output folder.")
        nmap_upload = st.file_uploader("Upload Nmap text output", type=["txt"], key="nmap_upload")
        if nmap_upload:
            nmap_text = nmap_upload.read().decode(errors="ignore")

    with col2:
        st.subheader("Quick actions")
        if st.button("Run quick summary"):
            st.experimental_rerun()

    # Parse vulnerabilities
    records = []
    if wpscan_data:
        st.subheader("WPScan findings (parsed)")
        records = parse_wpscan_vulns(wpscan_data)
        if not records:
            st.info("No structured vulnerabilities found in WPScan JSON (or format not recognized).")
    else:
        st.info("No WPScan data provided.")

    # Parse nikto/nmap
    nikto_records = parse_nikto_output(nikto_text) if nikto_text else []
    nmap_records = parse_nmap_output(nmap_text) if nmap_text else []

    # Show summary metrics
    total_vulns = len(records) + len(nikto_records)
    st.metric("Total vuln records (WPScan + Nikto)", total_vulns)
    st.metric("Nmap findings (open ports)", len(nmap_records))

    # Display WPScan table if present
    if records:
        # create DataFrame
        df_rows = []
        for r in records:
            df_rows.append({
                "Source": r.get("source"),
                "Component": r.get("component"),
                "Title": r.get("title"),
                "Severity": r.get("severity") or "",
                "CVE(s)": ", ".join(r.get("cve") or []),
                "Reference URLs": ", ".join(r.get("url") or []) if isinstance(r.get("url"), list) else r.get("url")
            })
        df = pd.DataFrame(df_rows)
        st.dataframe(df, use_container_width=True)

        # allow selecting a CVE to view details
        all_cves = sorted({c for row in df_rows for c in (row["CVE(s)"].split(", ") if row["CVE(s)"] else []) if c})
        if all_cves:
            st.subheader("CVE Lookup")
            cve_choice = st.selectbox("Select CVE to fetch details", options=["-- choose --"] + all_cves)
            if cve_choice and cve_choice != "-- choose --":
                with st.spinner(f"Fetching details for {cve_choice}"):
                    details = fetch_cve_details(cve_choice)
                if details.get("error"):
                    st.error(f"Error fetching CVE: {details['error']}")
                else:
                    st.write("**Summary**")
                    st.write(details.get("summary") or details.get("description") or "No summary available.")
                    st.write("**CVSS / References (if available)**")
                    st.json({k: details.get(k) for k in ("cvss", "cvssv3", "references") if details.get(k)})

    # Show nikto / nmap parsed results
    if nikto_records:
        st.subheader("Nikto parsed lines")
        for nr in nikto_records:
            st.code(nr.get("line"))

    if nmap_records:
        st.subheader("Nmap parsed open ports")
        st.table(pd.DataFrame(nmap_records))

    # Allow export results as CSV
    if records:
        export_df = pd.DataFrame([{
            "source": r.get("source"),
            "component": r.get("component"),
            "title": r.get("title"),
            "severity": r.get("severity"),
            "cves": ";".join(r.get("cve") or []),
        } for r in records])
        csv = export_df.to_csv(index=False).encode("utf-8")
        st.download_button("Download vulnerabilities CSV", data=csv, file_name="vulnerabilities_summary.csv", mime="text/csv")

    st.markdown("---")
    st.info("Tip: run WPScan with `--format json -o output/wpscan_output.json` to produce compatible JSON for this dashboard.")

# ---------- Main UI combining existing view and new Vulnerabilities tab ----------
def main():
    st.set_page_config(page_title="OSINT Dashboard", layout="wide")
    st.title("🔍 OSINT Dashboard - Harvester Report & Vulnerabilities")

    tabs = st.tabs(["Harvester / Static Viewer", "Vulnerabilities"])
    with tabs[0]:
        # existing static viewer content
        data = load_json_report()

        # Emails Section
        st.header("📧 Emails Found")
        emails = data.get("emails", [])
        if emails:
            for email in emails:
                st.markdown(f"- {email}")
        else:
            st.info("No emails found.")

        # Hosts Section
        st.header("🖥️ Hosts / IPs Found")
        hosts = data.get("hosts", [])
        if hosts:
            for host in hosts:
                st.markdown(f"- {host}")
        else:
            st.info("No hosts/IPs found.")

        # Subdomains Section
        st.header("🌐 Subdomains Found")
        subdomains = data.get("subdomains", [])
        if subdomains:
            for subdomain in subdomains:
                st.markdown(f"- {subdomain}")
        else:
            st.info("No subdomains found.")

        # Additional Recon Tools
        st.header("🛠️ Additional Reconnaissance Tool Outputs (Static)")

        tool_outputs = {
            "📄 nslookup Result": "nslookup_output.txt",
            "📄 WhatWeb Result": "whatweb_output.txt",
            "📄 WPScan Result": "wpscan_output.json",
            "📄 Nikto Result": "nikto_output.txt",
        }

        for section_title, file_name in tool_outputs.items():
            st.subheader(section_title)
            result = read_static_output(file_name)
            st.code(result)

        st.subheader("📄 Nessus")
        st.info(run_nessus_placeholder())

    with tabs[1]:
        vulnerabilities_tab()

if __name__ == "__main__":
    main()
