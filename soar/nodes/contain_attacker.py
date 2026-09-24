# Shuffle node "Contain_Attacker" (execute_python), added after Enrich_With_Cortex.
#
# On a high-severity, MISP-confirmed alert with a source IP, blocks that IP on OPNsense
# (BLOCKED_ATTACKERS alias, rule 395 on the purple interface — see
# firewall/segmentation-policy.json and firewall/contain_attacker.py) and records the
# action on the TheHive alert itself: a tag and a line appended to the description, with
# a UTC timestamp. Idempotent (blocking an already-blocked IP is a no-op) and reversible
# by hand with firewall/uncontain_attacker.py.
#
# Placeholders __THEHIVE__, __THEHIVE_KEY__, __OPN_URL__, __OPN_KEY__, __OPN_SECRET__,
# __LAB_CA__ are filled in by soar/create_wazuh_webhook_workflow.py at deploy time from
# environment variables; nothing here is a secret at rest.
#
# Threshold: TheHive severity 3 (Build_TheHive_Alert sets this for Wazuh level >= 12) AND
# tag misp:match (set synchronously by Enrich_With_Cortex, which runs first in the chain).

CODE = r'''import json, tempfile, datetime, requests

THEHIVE, TH_KEY = "__THEHIVE__", "__THEHIVE_KEY__"
OPN_URL, OPN_KEY, OPN_SECRET = "__OPN_URL__", "__OPN_KEY__", "__OPN_SECRET__"
TH = {"Authorization": "Bearer " + TH_KEY, "Content-Type": "application/json"}
ca_file = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False)
ca_file.write("""__LAB_CA__""")
ca_file.close()

alert_id = "$create_thehive_alert.body._id"
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
out = {"alert": alert_id, "contained": False}

alert = requests.get(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30).json()
tags = alert.get("tags", [])
out["severity"] = alert.get("severity")
out["misp_match"] = "misp:match" in tags

if alert.get("severity", 0) < 3 or "misp:match" not in tags:
    out["skipped"] = "severity below threshold or no misp:match"
    print(json.dumps(out))
    raise SystemExit(0)

obs = requests.post(THEHIVE + "/api/v1/query", headers=TH, timeout=30, json={
    "query": [{"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}]}).json()
ip = next((o["data"] for o in obs if o["dataType"] == "ip"), None)

if not ip:
    out["skipped"] = "no ip observable on this alert"
    print(json.dumps(out))
    raise SystemExit(0)

def opn(method, path, body=None):
    def form(d, prefix=""):
        flat = {}
        for k, v in d.items():
            key = "%s[%s]" % (prefix, k) if prefix else k
            flat.update(form(v, key)) if isinstance(v, dict) else flat.update({key: v})
        return flat
    r = requests.request(method, OPN_URL.rstrip("/") + "/api" + path, auth=(OPN_KEY, OPN_SECRET),
                         data=form(body) if body else None, verify=ca_file.name, timeout=30)
    r.raise_for_status()
    return r.json()

added = opn("POST", "/firewall/alias_util/add/BLOCKED_ATTACKERS", {"address": ip})
opn("POST", "/firewall/alias/reconfigure")
applied = opn("POST", "/firewall/filter/apply")

out.update({"ip": ip, "contained": True, "opnsense_add": added.get("status", added),
            "opnsense_apply": applied.get("status", applied)})

requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30, json={
    "tags": sorted(set(tags + ["auto-contained"])),
    "description": alert.get("description", "") +
        "\n\n[SOAR] %s: %s added to OPNsense alias BLOCKED_ATTACKERS (rule 395, purple "
        "zone) after a MISP-confirmed, high-severity alert. Reversible by hand with "
        "firewall/uncontain_attacker.py." % (now, ip)})

print(json.dumps(out))
'''
