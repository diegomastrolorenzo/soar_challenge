class Incident:
    def __init__(self, source_alert):
        self.incident_id = 1 # TODO automate based on next available number
        self.source_alert = source_alert
        self.asset = {"device_id": None, "hostname": None, "ip": None}
        self.indicators = []
        self.triage = None
        self.mitre = None
        self.actions = []
        self.timeline = []
        # These won't be printed in the json outputs, these are for my use only
        self.internal = {"tags": []}
