import splunklib.client as client
import splunklib.results as results

class SplunkConnector:
    def __init__(self, config):
        self.service = client.connect(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            password=config["password"],
            scheme="https"
        )
    def run_query(self, spl_query, earliest="-24h", latest="now"):
        job = self.service.jobs.create(f"search {spl_query}", earliest_time=earliest, latest_time=latest)
        job.refresh()
        while not job.is_done():
            job.refresh()
        reader = results.ResultsReader(job.results())
        out = []
        for item in reader:
            if isinstance(item, dict):
                out.append(item)
        return out