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

if __name__ == "__main__":
    main()
