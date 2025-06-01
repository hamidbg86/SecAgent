import argparse
import re
import yaml
from connectors.splunk_connector import SplunkConnector
from connectors.intel_connector import VirusTotalConnector
from connectors.intel_connector import AbuseIPDBConnector
from llm import OllamaHelper
import statistics

def extract_spl_from_llm_response(llm_response):
    """
    Extracts the SPL query from LLM output that may include explanations or markdown.
    """
    # Try to extract code block
    match = re.search(r"```(?:spl|)\s*([\s\S]+?)```", llm_response, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    # Try to extract from single backticks
    match = re.search(r"`([^`]+)`", llm_response)
    if match:
        return match.group(1).strip()
    # Fallback: take the first line that looks like SPL
    for line in llm_response.splitlines():
        if "index=" in line or line.strip().startswith("|") or line.strip().startswith("search"):
            return line.strip()
    # Fallback: return the whole response
    return llm_response.strip()

class SIEMAgent:
    def __init__(self, siem_type, config):
        self.siem_type = siem_type
        self.config = config
        if siem_type == "splunk":
            self.connector = SplunkConnector(config["splunk"])
        else:
            raise NotImplementedError(f"SIEM type {siem_type} not implemented")
        self.llm = OllamaHelper(config["ollama"])

    def nl_to_spl(self, nl_query):
        prompt = f"Convert this natural language request to a Splunk SPL query: '{nl_query}'"
        spl_query = self.llm.nl_to_spl(prompt)
        return extract_spl_from_llm_response(spl_query)

    def explain_spl(self, spl_query):
        prompt = f"Explain the following Splunk SPL query: '{spl_query}'"
        return self.llm.explain_spl(prompt)

    def run_query(self, spl_query):
        return self.connector.run_query(spl_query)

def print_table(results):
    if not results:
        print("No results found.")
        return
    # Get all unique keys from all result rows
    keys = set()
    for row in results:
        keys.update(row.keys())
    keys = list(keys)
    # Print header
    print("\t".join(keys))
    print("-" * (8 * len(keys)))
    # Print rows
    for row in results:
        print("\t".join(str(row.get(k, "")) for k in keys))

def interpret_with_llm(results, llm):
    if not results:
        print("No results to interpret.")
        return
    # Convert results to a markdown table for LLM context
    keys = list({k for row in results for k in row.keys()})
    table = ["\t".join(keys)]
    for row in results:
        table.append("\t".join(str(row.get(k, "")) for k in keys))
    table_str = "\n".join(table)
    prompt = (
        "You are a cybersecurity analyst. Here are Splunk search results:\n"
        f"{table_str}\n"
        "Analyze these results. Are there any notable findings, similar IOCs, or security conclusions you can draw? "
        "If you see patterns, anomalies, or known indicators of compromise, summarize them."
    )
    print("\nLLM Interpretation:")
    print(llm.explain_spl(prompt))

def extract_entities(results):
    ips, domains, hashes, emails = set(), set(), set(), set()
    for row in results:
        for v in row.values():
            if isinstance(v, str):
                ips.update(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", v))
                domains.update(re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", v))
                hashes.update(re.findall(r"\b[a-fA-F0-9]{32,64}\b", v))
                emails.update(re.findall(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", v))
    return {
        "ips": list(ips),
        "domains": list(domains),
        "hashes": list(hashes),
        "emails": list(emails)
    }
def detect_outliers(results):
    if not results:
        print("No results for anomaly detection.")
        return

    # Detect outliers in truly numeric fields
    candidate_fields = set()
    for row in results:
        candidate_fields.update(row.keys())
    numeric_fields = []
    for field in candidate_fields:
        is_numeric = True
        for row in results:
            v = row.get(field)
            if v is None:
                continue
            try:
                float(v)
            except (ValueError, TypeError):
                is_numeric = False
                break
        if is_numeric:
            numeric_fields.append(field)

    for field in numeric_fields:
        values = []
        for row in results:
            try:
                values.append(float(row[field]))
            except (KeyError, ValueError, TypeError):
                continue
        if len(values) < 3:
            continue
        mean = statistics.mean(values)
        stdev = statistics.stdev(values)
        outliers = [row for row in results if field in row and abs(float(row[field]) - mean) > 2 * stdev]
        if outliers:
            print(f"\n[Anomaly Detection] Outliers detected in '{field}':")
            for row in outliers:
                print(row)

    # Detect rare categorical values (e.g., rare status codes, new users)
    for field in ['status', 'user', 'sourcetype', 'file']:
        freq = {}
        for row in results:
            val = row.get(field)
            if val:
                freq[val] = freq.get(val, 0) + 1
        rare = [k for k, v in freq.items() if v == 1]
        if rare:
            print(f"\n[Anomaly Detection] Rare values in '{field}': {rare}")

    # Detect rare categorical values (e.g., rare status codes, new users)
    for field in ['status', 'user', 'sourcetype', 'file']:
        freq = {}
        for row in results:
            val = row.get(field)
            if val:
                freq[val] = freq.get(val, 0) + 1
        rare = [k for k, v in freq.items() if v == 1]
        if rare:
            print(f"\n[Anomaly Detection] Rare values in '{field}': {rare}")
def enrich_with_virustotal(results, vt_api_key):
    vt = VirusTotalConnector(vt_api_key)
    entities = extract_entities(results)
    # Enrich IPs
    for ip in entities["ips"]:
        vt_result = vt.ip_lookup(ip)
        print(f"VirusTotal for IP {ip}: {vt_result}")
    # Enrich domains (if you add vt.domain_lookup)
    # for domain in entities["domains"]:
    #     vt_result = vt.domain_lookup(domain)
    #     print(f"VirusTotal for domain {domain}: {vt_result}")
    # Enrich hashes (if you add vt.hash_lookup)
    # for h in entities["hashes"]:
    #     vt_result = vt.hash_lookup(h)
    #     print(f"VirusTotal for hash {h}: {vt_result}")

def enrich_with_abuseipdb(results, api_key):
    from connectors.intel_connector import AbuseIPDBConnector
    entities = extract_entities(results)
    abuse = AbuseIPDBConnector(api_key)
    for ip in entities["ips"]:
        abuse_result = abuse.ip_lookup(ip)
        print(f"AbuseIPDB for {ip}: {abuse_result}")

def enrich_with_all_sources(results, config):
    # VirusTotal
    if "virustotal" in config and "api_key" in config["virustotal"]:
        print("\n--- VirusTotal Enrichment ---")
        enrich_with_virustotal(results, config["virustotal"]["api_key"])
    # AbuseIPDB (example, needs AbuseIPDBConnector)
    if "abuseipdb" in config and "api_key" in config["abuseipdb"]:
        print("\n--- AbuseIPDB Enrichment ---")
        enrich_with_abuseipdb(results, config["abuseipdb"]["api_key"])
    # Add more sources here as you implement them

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Multi-SIEM AI Agent")
    parser.add_argument("--siem", default="splunk", help="SIEM type (default: splunk)")
    parser.add_argument("--query", help="Natural language query to convert and run")
    parser.add_argument("--explain", help="SPL query to explain")
    args = parser.parse_args()

    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    agent = SIEMAgent(args.siem, config)

    if args.query:
        spl = agent.nl_to_spl(args.query)
        print(f"SPL Query: {spl}")
        results = agent.run_query(spl)
        print("Results:")
        print_table(results)
        interpret_with_llm(results, agent.llm)
        enrich_with_all_sources(results, config)
        detect_outliers(results)
    elif args.explain:
        explanation = agent.explain_spl(args.explain)
        print("Explanation:")
        print(explanation)
    else:
        print("Please provide either --query or --explain.")

if __name__ == "__main__":
    main()