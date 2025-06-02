# SecAgent
AI Agent for SIEM search and more
# 🛡️ Cybersecurity Multi-SIEM AI Agent

This project is an AI-powered cybersecurity tool that integrates with SIEM platforms (currently supports Splunk) to convert **natural language queries into SPL (Splunk Processing Language)**, execute them, and enrich the results using external threat intelligence sources like **VirusTotal** and **AbuseIPDB**. It also provides anomaly detection and LLM-powered interpretation of results.

---

## ✨ Features

- 🔍 **Natural Language to SPL**: Converts human-readable questions into Splunk queries using a local LLM (`Ollama`).
- 📊 **Query Execution**: Runs the generated SPL against your Splunk instance.
- 🧠 **LLM-Powered Interpretation**: Uses an LLM to interpret the meaning and security implications of the results.
- 🧪 **Anomaly Detection**: Detects numeric outliers and rare categorical values.
- 🌐 **Threat Intel Enrichment**:
  - [x] VirusTotal (IP lookup)
  - [x] AbuseIPDB
  - [ ] (Pluggable for additional sources)

---

## 🧱 Project Structure

.
├── connectors/
│ ├── splunk_connector.py # Splunk API interaction
│ └── intel_connector.py # VirusTotal & AbuseIPDB connectors
├── llm/
│ └── ollama_helper.py # LLM interface using Ollama
├── main.py # CLI entry point (this script)
├── config.yaml # Configuration for Splunk, LLM, API keys
└── README.md

## ⚙️ Setup

### 1. Clone the Repo

```bash
git clone https://github.com/your_org/siem-agent.git
cd siem-agent

2. Install Dependencies
Ensure you have Python 3.8+ and pip installed.

bash
Copy
Edit
pip install -r requirements.txt
Sample requirements.txt:

txt
Copy
Edit
requests
pyyaml
Optional: Include ollama, pyjwt, etc., based on your llm or connector implementations.

3. Configure
Edit the config.yaml file:

yaml
Copy
Edit
splunk:
  host: https://splunk.company.com:8089
  username: your_username
  password: your_password

ollama:
  model: mistral
  endpoint: http://localhost:11434

virustotal:
  api_key: YOUR_VIRUSTOTAL_API_KEY

abuseipdb:
  api_key: YOUR_ABUSEIPDB_API_KEY
🚀 Usage
Natural Language to SPL
bash
Copy
Edit
python main.py --query "Show failed login attempts in the last 24 hours"
Explain SPL
bash
Copy
Edit
python main.py --explain 'index=auth sourcetype=linux_secure "Failed password"'
