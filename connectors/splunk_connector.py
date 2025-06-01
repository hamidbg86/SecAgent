import splunklib.client as client
import splunklib.results as results

class SplunkConnector:
    def __init__(self, config):
        self.service = client.connect(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            password=config["password"],
            scheme="https",      # Use HTTPS for Docker Splunk
            verify=False         # Skip SSL verification for local dev
        )

    def run_query(self, spl_query, earliest="-24h", latest="now"):
        query = spl_query.strip()
        # Always prepend 'search' if query starts with 'index='
        if query.lower().startswith("index="):
            query = f"search {query}"
        elif not (query.lower().startswith("search") or query.startswith("|")):
            query = f"search {query}"
        # Fallback to a safe SPL if the query looks suspicious
        if "rest" in query or "splunk_server" in query or "services" in query:
            query = 'search index=_internal | stats count by sourcetype'
        print(f"DEBUG: Running SPL: {query}")
        job = self.service.jobs.create(query, earliest_time=earliest, latest_time=latest)
        job.refresh()
        while not job.is_done():
            job.refresh()
        reader = results.ResultsReader(job.results())
        out = []
        for item in reader:
            if isinstance(item, dict):
                out.append(item)
        return out