class Incident:
    def __init__(self):
        self.incident_id = 1 # TODO automate based on next available number
        self.source_alert = None
        self.asset = {"device_id": None, "hostname": None, "ip": None}
        self.indicators = []
        self.triage = None
        self.mitre = None
        self.actions = None
        self.timeline = None


'''

{
"incident_id": "...",
"source_alert": { "...original..." },
"asset": { "device_id": "...", "hostname": "...", "ip": "..." },
"indicators": [
{ "type":"ipv4","value":"1.2.3.4","risk":{},"allowlisted": false }
],
"triage": { "severity": 0-100, "bucket":"Low|Medium|High|Critical|Suppressed", "tags":
["..."], "suppressed": true|false },
"mitre": { "techniques": ["T1059", ...] },
"actions": [ { "type":"isolate","target":"device:<ID>","result":"isolated","ts":"..."} ],
"timeline": [ { "stage":"ingest|enrich|triage|respond", "ts":"...", "details":"..." } ]
}


'''
