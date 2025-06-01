import requests
import json

class OllamaHelper:
    def __init__(self, config):
        self.model = config.get("model", "llama3")
        self.base_url = config.get("ollama_url", "http://localhost:11434")

    def _ask_ollama(self, prompt, system="You are a helpful assistant."):
        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt}
                ]
            },
            stream=True
        )
        response.raise_for_status()
        content = ""
        for line in response.iter_lines():
            if line:
                data = line.decode("utf-8")
                try:
                    msg = json.loads(data)
                    if "message" in msg and "content" in msg["message"]:
                        content += msg["message"]["content"]
                except Exception:
                    continue
        return content.strip()

    def explain_spl(self, prompt):
        system = "You are a helpful assistant for explaining Splunk SPL queries."
        return self._ask_ollama(prompt, system=system)

    def nl_to_spl(self, prompt):
        system = "You are a helpful assistant for converting natural language to Splunk SPL queries."
        return self._ask_ollama(prompt, system=system)