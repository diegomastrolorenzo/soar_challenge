import json
import sys
import os
from stringprep import in_table_c9

from incident import Incident

def run_ti_for_ioc(ioc_type, ioc_value):
    # Assumes that all the mocks/it files ever will come with this format: provider_type_value.json
    ti_base_path = "mocks/it/"
    all_files = os.listdir(ti_base_path)
    hits = []

    providers = ["anomali", "defender_ti", "reversinglabs"]
    type_mapping = {
        "ipv4": "ip",
        "domains": "domain",
        "urls": "url", # I can only assume this one since it wasn't given
        "sha256": "sha256",
    }

    # it might seem clunky doing it this way but what if a domain has an underscore
    for i in all_files:
        for j in providers:
            if i.startswith(j + "_" + type_mapping[ioc_type] + "_" + ioc_value):
                with open(ti_base_path + i) as f:
                    ti_source_json = json.load(f)
                    hits.append((j, ti_source_json)) # I'll bring the whole json out, will process it after

    return hits

def calculate_risk(ioc_type, ioc_value, ti_hits):


### Ingestion ###

# Arg parsing

if len(sys.argv) != 2:
    print("Error: Please provide a single file path as an argument.")
    print("Usage: python main.py path/to/alert.json")
    sys.exit(1)

alert_path = sys.argv[1]

# Assuming well-formed jsons because in a real scenario they come from a SIEM
try:
    with open(alert_path) as f:
        alert_json = json.load(f)
except FileNotFoundError:
    print(f"Error: {alert_path} does not exist.")
    sys.exit(1)

### Normalization ###

incident = Incident()


# Indicator loading
for ioc_type, ioc_list in alert_json["indicators"].items():
    for ioc in ioc_list:
        incident.indicators.append({"type": ioc_type, "value": ioc})

# Asset loading
if alert_json.get("asset", None):
    incident.asset["device_id"] = alert_json["asset"].get("device_id", None)
    incident.asset["hostname"] = alert_json["asset"].get("hostname", None)
    incident.asset["ip"] = alert_json["asset"].get("ip", None)


for i in incident.indicators:
    print("-------", i, "------------")
    ti_hits = run_ti_for_ioc(i["type"], i["value"]) # in real life these would be api calls with the artifact name and type
    calculate_risk(i["type"], i["value"], ti_hits)

