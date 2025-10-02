import os

class Incident:
    def __init__(self, source_alert):
        self.incident_id = self.calculate_next_id()
        self.source_alert = source_alert
        self.asset = {"device_id": None, "hostname": None, "ip": None}
        self.indicators = []
        self.triage = None
        self.mitre = None
        self.actions = []
        self.timeline = []
        # These won't be printed in the json outputs, these are for my use only
        self.internal = {"tags": []}

    def calculate_next_id(self):
        if not os.path.isdir("out/incidents"):
            return 1
        else:
            all_incidents = os.listdir("out/incidents")
            if len(all_incidents) == 0:
                return 1
            else:
                all_incident_numbers = [int(i.split(".json")[0]) for i in all_incidents]
                return max(all_incident_numbers) + 1