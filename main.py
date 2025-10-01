import json
import yaml
import sys
import os
from stringprep import in_table_c9

from incident import Incident


def run_ti_for_ioc(ioc_type, ioc_value):
    # The folder you gave me was called mocks/it; i renamed it to mocks/ti to fit with the connectors config
    # Assumes that all the mocks/ti files ever will come with this format: provider_type_value.json

    type_mapping = {
        "ipv4": "ip",
        "domains": "domain",
        "urls": "url",  # I can only assume this one since it wasn't given
        "sha256": "sha256",
    }

    provider_score_mapping = {
        "anomali": "confidence",
        "defender_ti": "score",
        "reversinglabs": "score",
    }

    provider_verdict_mapping = {
        "anomali": "risk",
        "defender_ti": "reputation",
        "reversinglabs": "classification",
    }

    with open("configs/connectors.yml") as f:
        connector_info = yaml.safe_load(f)

    providers = []
    base_urls = set()
    for k, v in connector_info["providers"].items():
        providers.append(k)
        base_urls.add(v["base_url"].split("file://")[1])  # Remove the file:// part

    hits = []
    # This for loop will only run once since all providers are on the same folder, I could have hardcoded the path
    # it's just to showcase that I could get the data from the config
    for base_url in base_urls:
        all_files = os.listdir(base_url)

        for i in all_files:
            for provider in providers:
                if i.startswith(provider + "_" + type_mapping[ioc_type] + "_" + ioc_value):
                    with open(base_url + "/" + i) as f:
                        ti_source_json = json.load(f)
                        clean_data = {
                            "provider": provider,
                            "verdict": ti_source_json[provider_verdict_mapping[provider]],
                            "score": ti_source_json[provider_score_mapping[provider]],
                        }
                        hits.append(clean_data)

    return hits


def calculate_risk(ti_hits):
    """
    You asked to produce a merged risk per indicator. Since it wasn't specified how,
    If there are multiple, I'm going to take the most severe, to err in the side of caution.

    :param: ti_hits is a tuple of the form (provider, ti_source_json). It's the result of the fn run_ti_for_ioc(...)
    """

    if not ti_hits:
        return {"verdict": "unknown",
                "score": 0,  # I assumed score 0 because it said 0-100
                "sources": []
                }

    severity_mapping = {
        "malicious": 3,
        "suspicious": 2,
        "clean": 1,
        "unknown": 0
    }

    most_severe_one = max(ti_hits, key=lambda x: severity_mapping[x["verdict"]])
    sources = list({i["provider"] for i in ti_hits})

    return {"verdict": most_severe_one["verdict"],
            "score": most_severe_one["score"],
            "sources": sources
            }


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
        incident.indicators.append({"type": ioc_type, "value": ioc, "allowlisted": None, "risk": None})

# Asset loading
if alert_json.get("asset", None):
    incident.asset["device_id"] = alert_json["asset"].get("device_id", None)
    incident.asset["hostname"] = alert_json["asset"].get("hostname", None)
    incident.asset["ip"] = alert_json["asset"].get("ip", None)

### Enrichment ###
# doing TI for the artifacts and setting risk scores
for i in incident.indicators:
    print("----", i, "----")
    ti_hits = run_ti_for_ioc(i["type"], i["value"])  # in real life these would be api calls with the ioc name and type
    i["risk"] = calculate_risk(ti_hits)

### Triage ###

