import openai

class OpenAIHelper:
    def __init__(self, config):
        openai.api_key = config["api_key"]
        self.model = config.get("model", "gpt-3.5-turbo")

    def nl_to_spl(self, prompt):
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert in Splunk SPL."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150,
            temperature=0.2
        )
        return response["choices"][0]["message"]["content"].strip()

    def explain_spl(self, prompt):
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are an expert in Splunk SPL."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=250,
            temperature=0.2
        )
        return response["choices"][0]["message"]["content"].strip()