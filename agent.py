import argparse
import re
from connectors.splunk_connector import SplunkConnector
from llm import OllamaHelper
import yaml
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
    elif args.explain:
        explanation = agent.explain_spl(args.explain)
        print("Explanation:")
        print(explanation)
    else:
        print("Please provide either --query or --explain.")

if __name__ == "__main__":
    main()