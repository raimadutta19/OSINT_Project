import streamlit as st
import json
import os

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

def read_static_output(file_name):
    file_path = os.path.join(os.path.dirname(__file__), f"output/{file_name}")
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        return f"❌ {file_name} not found in output folder."
    except Exception as e:
        return f"❌ Error reading {file_name}: {str(e)}"

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

if __name__ == "__main__":
    main()
