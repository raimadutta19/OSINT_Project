import streamlit as st
import json
import os
import subprocess

def load_json_report():
    file_path = os.path.join(os.path.dirname(__file__), "output/harvester_mckvie.json")
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        st.error("❌ harvester_mckvie.json not found in output folder.")
        return {}
    except json.JSONDecodeError:
        st.error("❌ JSON decoding error. Please check the file format.")
        return {}

def run_nslookup(domain):
    try:
        output = subprocess.check_output(["output/nslookup", domain], text=True)
        return output
    except Exception as e:
        return str(e)

def run_whatweb(domain):
    try:
        output = subprocess.check_output(["output/whatweb", domain], text=True)
        return output
    except Exception as e:
        return str(e)

def run_wpscan(domain):
    try:
        output = subprocess.check_output(["output/wpscan", "--url", f"http://{domain}", "--no-update"], text=True)
        return output
    except Exception as e:
        return str(e)

def run_nikto(domain):
    try:
        output = subprocess.check_output(["output/nikto", "-host", domain], text=True)
        return output
    except Exception as e:
        return str(e)

def run_nessus_placeholder():
    return "Nessus integration is not CLI-based and requires authenticated API access, so manual analysis results can be uploaded instead."

def main():
    st.set_page_config(page_title="OSINT Dashboard", layout="wide")
    st.title("🔍 OSINT Dashboard - Harvester Report")

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
    st.header("🛠️ Additional Reconnaissance Tools")

    domain = st.text_input("Enter domain for additional recon tools", "mckvie.edu.in")

    if st.button("Run Recon Tools"):
        with st.spinner("Running nslookup..."):
            nslookup_result = run_nslookup(domain)
            st.subheader("📄 nslookup Result")
            st.code(nslookup_result)

        with st.spinner("Running WhatWeb..."):
            whatweb_result = run_whatweb(domain)
            st.subheader("📄 WhatWeb Result")
            st.code(whatweb_result)

        with st.spinner("Running WPScan..."):
            wpscan_result = run_wpscan(domain)
            st.subheader("📄 WPScan Result")
            st.code(wpscan_result)

        with st.spinner("Running Nikto..."):
            nikto_result = run_nikto(domain)
            st.subheader("📄 Nikto Result")
            st.code(nikto_result)

        st.subheader("📄 Nessus")
        st.info(run_nessus_placeholder())

if __name__ == "__main__":
    main()
