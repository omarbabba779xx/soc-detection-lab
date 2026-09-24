"""Apply segmentation-policy.json to OPNsense 24.7 through its REST API.

Usage:  OPN_URL=https://10.10.10.1 OPN_KEY=... OPN_SECRET=... python apply_policy.py
Idempotent: aliases, rules and the syslog destination are matched by name/description.
See opnsense_client.py for the connection (TLS, credentials) and the shared HTTP helpers.

An alias marked "dynamic": true in the policy (BLOCKED_ATTACKERS) is created once, with
empty content, and never touched again here: its content is managed live by
contain_attacker.py / uncontain_attacker.py, and re-running this script must not erase it.
"""
import json, pathlib
from opnsense_client import api, existing, apply_filter

HERE = pathlib.Path(__file__).resolve().parent
POLICY = json.loads((HERE / "segmentation-policy.json").read_text())

# aliases
have = existing("/firewall/alias/searchItem", "name")
for a in POLICY["aliases"]:
    if a.get("dynamic") and a["name"] in have:
        print(a["name"], "dynamic, left as-is")
        continue
    item = {"alias": {"enabled": "1", "name": a["name"], "type": a["type"],
                      "content": "\n".join(a["content"]), "description": a["description"]}}
    if a["name"] in have:
        api("POST", f"/firewall/alias/setItem/{have[a['name']]}", item)
    else:
        api("POST", "/firewall/alias/addItem", item)
api("POST", "/firewall/alias/reconfigure")

# filter rules
have = existing("/firewall/filter/searchRule", "description")
for r in POLICY["rules"]:
    rule = {"rule": {"enabled": "1", "sequence": str(r["seq"]), "action": r["action"], "quick": "1",
                     "interface": r["if"], "direction": "in", "ipprotocol": "inet",
                     "protocol": r["proto"], "source_net": r.get("src", r["if"]),
                     "destination_net": r["dst"], "destination_port": r["port"],
                     "log": str(r["log"]), "description": r["desc"]}}
    if r["desc"] in have:
        print(r["desc"], api("POST", f"/firewall/filter/setRule/{have[r['desc']]}", rule)["result"])
    else:
        print(r["desc"], api("POST", "/firewall/filter/addRule", rule)["result"])
print("filter apply:", apply_filter()["status"])

# remote syslog
s = POLICY["syslog"]
have = existing("/syslog/settings/searchDestinations", "description")
dest = {"destination": {"enabled": "1", "transport": s["transport"], "hostname": s["hostname"],
                        "port": s["port"], "program": s["program"], "rfc5424": "0",
                        "description": s["description"]}}
if s["description"] in have:
    api("POST", f"/syslog/settings/setDestination/{have[s['description']]}", dest)
else:
    api("POST", "/syslog/settings/addDestination", dest)
print("syslog reconfigure:", api("POST", "/syslog/service/reconfigure").get("status"))
