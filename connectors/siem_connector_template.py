class SIEMConnectorBase:
    def __init__(self, config):
        self.config = config
    def run_query(self, query, **kwargs):
        raise NotImplementedError("Implement this in the connector.")