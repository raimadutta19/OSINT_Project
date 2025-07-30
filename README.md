# 🕵️‍♀️ OSINT Dashboard using Streamlit

This project is a lightweight, educational **Open Source Intelligence (OSINT) Dashboard** built using **Python** and **Streamlit**. It visualizes pre-generated output from popular reconnaissance tools to simulate how real-world OSINT investigations are presented in a centralized interface.

> 📌 **Live Demo:** [osintproject-raimadutta.streamlit.app](https://osintproject-raimadutta.streamlit.app)

---

## 🔧 Tools Integrated (Outputs Visualized)

The following OSINT tools have been simulated via their **static output files**:

| Tool        | Description |
|-------------|-------------|
| 🕵️ theHarvester | Gathers emails, subdomains, hosts, and employee names from public sources |
| 🌐 nslookup     | Queries DNS records for a given domain (A, MX, CNAME, etc.) |
| 🧰 WhatWeb      | Identifies web technologies used by websites |
| 🔐 WPScan       | Scans WordPress sites for known vulnerabilities |
| 🛡️ Nikto        | Performs basic web server vulnerability scans |

> ⚠️ **Note:** These tools were run offline. Streamlit only reads their outputs; it does not execute any reconnaissance operations live.

---

## 🖥️ Tech Stack

| Component     | Details |
|---------------|---------|
| 🐍 Language     | Python 3.x |
| 🎨 Frontend    | Streamlit |
| 📁 Output Data | JSON / TXT files from OSINT tools |
| ☁️ Deployment | Streamlit Cloud |
| 📦 Packages Used | `pandas`, `streamlit`, `json`, `os`, `re`, `subprocess` (for offline use only) |

---

## ⚙️ Folder Structure

OSINT_Project/
│
├── dashboard.py # Main Streamlit application
├── requirements.txt # Required Python libraries
├── output/ # Pre-generated output files
│ ├── harvester_mckvie.json
│ ├── nslookup_output.txt
│ ├── whatweb_output.txt
│ ├── wpscan_output.json
│ ├── nikto_output.txt


---

## 🌟 Key Features

- ✅ Read and display OSINT tool outputs in a clean dashboard
- ✅ Easy to deploy using Streamlit Cloud
- ✅ Modular code with readable layout
- ✅ No real-time scanning — safe for hosting on public platforms

---

## 🧪 How to Run Locally

```bash
git clone https://github.com/your-username/OSINT_Project.git
cd OSINT_Project
pip install -r requirements.txt
streamlit run dashboard.py

🚀 Deployment
This app is deployed using Streamlit Cloud.
Feel free to fork this repo and deploy your own version.

Live Link:
🔗 https://osintproject-raimadutta.streamlit.app

📚 Educational Use Case
This project is intended solely for educational and demonstration purposes.
No live scanning or probing of domains occurs within this app. It’s designed to help students understand how OSINT works using simulated outputs.

📸 Screenshots
(Add screenshots of your dashboard here)

🙋‍♀️ Author
Raima Dutta
LinkedIn
💬 For any queries, feel free to reach out!

📜 License
This project is for academic and educational purposes. You can reuse or adapt it, but please provide proper attribution.
