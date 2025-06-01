import requests

class VirusTotalConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def ip_lookup(self, ip):
        headers = {"x-apikey": self.api_key}
        resp = requests.get(f"{self.base_url}/ip_addresses/{ip}", headers=headers)
        if resp.status_code == 200:
            return resp.json()
        return None

class AbuseIPDBConnector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def ip_lookup(self, ip):
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip}
        resp = requests.get(f"{self.base_url}/check", headers=headers, params=params)
        if resp.status_code == 200:
            return resp.json()
        return None