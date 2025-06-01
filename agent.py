import argparse
from connectors.splunk_connector import SplunkConnector
from llm import OpenAIHelper

class SIEMAgent:
    def __init__(self, siem_type, config):
        self.siem_type = siem_type
        self.config = config
        if siem_type == "splunk":
            self.connector = SplunkConnector(config["splunk"])
        # Future: Add other SIEMs here (e.g. Elastic, QRadar)
        else:
            raise NotImplementedError(f"SIEM type {siem_type} not implemented")
        self.llm = OpenAIHelper(config["openai"])

    def nl_to_spl(self, nl_query):
        prompt = f"Convert this natural language request to a Splunk SPL query: '{nl_query}'"
        spl_query = self.llm.nl_to_spl(prompt)
        return spl_query

    def explain_spl(self, spl_query):
        prompt = f"Explain the following Splunk SPL query: '{spl_query}'"
        return self.llm.explain_spl(prompt)

    def run_query(self, spl_query):
        return self.connector.run_query(spl_query)

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Multi-SIEM AI Agent")
    parser.add_argument("--siem", default="splunk", help="SIEM type (default: splunk)")
    parser.add_argument("--query", help="Natural language query to convert and run")
    parser.add_argument("--explain", help="SPL query to explain")
    args = parser.parse_args()

    import yaml
    config = yaml.safe_load(open("config.yaml"))
    agent = SIEMAgent(args.siem, config)

    if args.query:
        spl = agent.nl_to_spl(args.query)
        print(f"SPL Query: {spl}")
        results = agent.run_query(spl)
        print(f"Results:\n{results}")
    elif args.explain:
        explanation = agent.explain_spl(args.explain)
        print(f"Explanation:\n{explanation}")
    else:
        print("Provide --query or --explain argument.")

if __name__ == "__main__":
    main()