import datetime
import json
import yaml
import sys
import os
import jinja2

from incident import Incident


def parse_arguments():
    if len(sys.argv) != 2:
        print("Error: Please provide a single file path as an argument.")
        print("Usage: python main.py path/to/alert.json")
        sys.exit(1)

    if not os.path.isfile(sys.argv[1]):
        print(f"Error: {sys.argv[1]} is not a file")
        print("Usage: python main.py path/to/alert.json")

    alert_path = sys.argv[1]

    # Assuming well-formed jsons because in a real scenario they come from a SIEM
    try:
        with open(alert_path) as f:
            alert_json = json.load(f)
    except FileNotFoundError:
        print(f"Error: {alert_path} does not exist.")
        sys.exit(1)

    return alert_json


def load_indicators(incident):
    for ioc_type, ioc_list in incident.source_alert["indicators"].items():
        for ioc in ioc_list:
            incident.indicators.append({"type": ioc_type, "value": ioc, "allowlisted": None, "risk": None})


def load_assets(incident):
    if incident.source_alert.get("asset", None):
        incident.asset["device_id"] = incident.source_alert["asset"].get("device_id", None)
        incident.asset["hostname"] = incident.source_alert["asset"].get("hostname", None)
        incident.asset["ip"] = incident.source_alert["asset"].get("ip", None)


def indicator_enrichment(incident):
    for i in incident.indicators:
        ti_hits = run_ti_for_ioc(i["type"],
                                 i["value"])  # in real life these would be api calls with the ioc name and type

        i["risk"] = calculate_risk(ti_hits)


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


def get_iso_ts_now():
    date_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    date_str = date_str.split("+")[0] + "Z"

    # I kept up to the millisecond because in my machine all the stages (ingest|enrich|triage|respond) were done in the
    # same second, in a real scenario this is not needed and you would remove the milliseconds also
    return date_str


def calculate_triage_score(incident):
    base_score = {
        "Malware": 70,
        "Phishing": 60,
        "Beaconing": 65,
        "CredentialAccess": 75,
        "C2": 80,
        "Unknown": 40
    }
    triage_score = base_score.get(incident.source_alert.get("type", "Unknown"), 40)

    flagged_ioc_count = {"malicious": 0, "suspicious": 0}
    extra_flagged_count = 0  # The ones flagged after the first, worth 5 points each

    # There's definitely a cleaner way to do this score calculation but this is good enough
    for i in incident.indicators:
        if i["risk"]["verdict"] in flagged_ioc_count:
            flagged_ioc_count[i["risk"]["verdict"]] += 1

    if flagged_ioc_count["malicious"]:
        triage_score += 20
        extra_flagged_count += flagged_ioc_count["malicious"] - 1

    if flagged_ioc_count["suspicious"]:
        triage_score += 10
        extra_flagged_count += flagged_ioc_count["suspicious"] - 1

    if extra_flagged_count >= 4:
        triage_score += 20
    else:
        triage_score += extra_flagged_count * 5

    with open("configs/allowlists.yml") as f:
        allowlist = yaml.safe_load(f)

    for i in incident.indicators:
        if i["value"] in allowlist["indicators"][i["type"]]:
            i["allowlisted"] = True
        else:
            i["allowlisted"] = False

    all_allowlisted = True
    at_least_one_allowlisted = False
    for i in incident.indicators:
        if i["allowlisted"]:
            at_least_one_allowlisted = True
        if not i["allowlisted"]:
            all_allowlisted = False

    if at_least_one_allowlisted:
        triage_score -= 25
        incident.internal["tags"].append("allowlisted")

    if all_allowlisted:
        triage_score = 0
        incident.internal["tags"].append("supressed=true")

    if triage_score > 100:
        triage_score = 100
    if triage_score < 0:
        triage_score = 0

    return triage_score


def build_triage_object(incident, triage_score):
    if triage_score == 0:
        bucket = "Suppresed"
    elif 1 <= triage_score <= 39:
        bucket = "Low"
    elif 40 <= triage_score <= 69:
        bucket = "Medium"
    elif 70 <= triage_score <= 89:
        bucket = "High"
    else:
        bucket = "Critical"

    return {
        "severity": triage_score,
        "bucket": bucket,
        "tags": incident.internal["tags"],
        "suppressed": bool(triage_score == 0),  # It's a bool anyways, type casting for clarity
    }


def build_mitre_object(incident):
    with open("configs/mitre_map.yml") as f:
        mitre_map = yaml.safe_load(f)

    alert_type = incident.source_alert.get("type", "Unknown")

    if alert_type in mitre_map["types"]:
        techniques = mitre_map["types"][alert_type]
    else:
        techniques = mitre_map["defaults"]

    return {"techniques": techniques}


def should_isolate(incident):
    with open("configs/allowlists.yml") as f:
        allowlist = yaml.safe_load(f)

    asset_allowlisted = incident.asset.get("device_id", "Unknown") in allowlist["assets"]["device_ids"]

    return incident.triage["severity"] >= 70 and not asset_allowlisted


def isolate(incident):
    if not os.path.isdir("out"):
        os.mkdir("out")

    ts_now = get_iso_ts_now()
    dev_id = incident.asset.get("device_id", "Unknown")  # Should never be unknown but this doesn't hurt
    inc_id = incident.incident_id
    text_to_write = f"{ts_now} isolate device_id={dev_id} incident={inc_id} result=isolated"

    with open("out/isolation.log", "a") as f:
        f.write(text_to_write + "\n")

    action = {"type": "isolate", "target": f"device:{dev_id}", "result": "isolated", "ts": ts_now}
    incident.actions.append(action)


def start_new_stage(incident, stage):
    ts_now = get_iso_ts_now()
    obj = {"stage": stage, "ts": ts_now, "details": f"Starting {stage} stage"}
    incident.timeline.append(obj)


def create_summary(incident):
    with open("summary_template.j2") as f:
        markdown_template = f.read()

    template = jinja2.Template(markdown_template)
    rendered_markdown = template.render(**vars(incident))

    return rendered_markdown


def main():
    alert_json = parse_arguments()
    incident = Incident(alert_json)

    start_new_stage(incident, "ingest")
    load_indicators(incident)
    load_assets(incident)

    start_new_stage(incident, "enrich")
    indicator_enrichment(incident)

    start_new_stage(incident, "triage")
    triage_score = calculate_triage_score(incident)
    incident.triage = build_triage_object(incident, triage_score)
    incident.mitre = build_mitre_object(incident)

    start_new_stage(incident, "respond")
    if should_isolate(incident):
        isolate(incident)

    # since I finished processing these internal things are no longer needed.
    # I remove them so I can just dump the whole incident object into the output file
    del incident.internal

    os.makedirs("out/incidents", exist_ok=True)
    with open(f"out/incidents/{incident.incident_id}.json", "w") as f:
        json.dump(vars(incident), f, indent=4)

    jinja_summary = create_summary(incident)
    os.makedirs("out/summaries", exist_ok=True)
    with open(f"out/summaries/{incident.incident_id}.md", "w") as f:
        f.write(jinja_summary)


if __name__ == "__main__":
    main()
