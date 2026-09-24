"""Apply segmentation-policy.json to OPNsense 24.7 through its REST API.

Usage:  OPN_URL=https://10.10.10.1 OPN_KEY=... OPN_SECRET=... python apply_policy.py
The API key is created in System > Access > Users > root > API keys and never stored here.
Idempotent: aliases, rules and the syslog destination are matched by name/description.

TLS is always verified against the lab CA (pki/socforge-lab-ca.crt, or OPN_CA). When the
firewall is reached through a port forward (OPN_URL=https://127.0.0.1:28443), set
OPN_TLS_NAME=10.10.10.1: the certificate is then checked against the firewall's own name
instead of the forwarded address.
"""
import json, os, pathlib, requests
from requests.adapters import HTTPAdapter

HERE = pathlib.Path(__file__).resolve().parent
BASE = os.environ.get("OPN_URL", "https://10.10.10.1").rstrip("/") + "/api"
AUTH = (os.environ["OPN_KEY"], os.environ["OPN_SECRET"])
CA = os.environ.get("OPN_CA", str(HERE.parent / "pki" / "socforge-lab-ca.crt"))
POLICY = json.loads((HERE / "segmentation-policy.json").read_text())


class ExpectedName(HTTPAdapter):
    """Verify the server certificate against a fixed name (SNI and hostname check)."""

    def __init__(self, name):
        self.name = name
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs.update(server_hostname=self.name, assert_hostname=self.name)
        super().init_poolmanager(*args, **kwargs)


SESSION = requests.Session()
SESSION.verify = CA
if os.environ.get("OPN_TLS_NAME"):
    SESSION.mount("https://", ExpectedName(os.environ["OPN_TLS_NAME"]))


def form(body, prefix=""):
    """Flatten {"rule": {"a": "1"}} into {"rule[a]": "1"}. On this appliance a JSON body
    is ignored by the MVC controllers (every add/set returns "failed" with no validation
    message); the same payload sent as a form is accepted."""
    out = {}
    for k, v in body.items():
        key = f"{prefix}[{k}]" if prefix else k
        if isinstance(v, dict):
            out.update(form(v, key))
        else:
            out[key] = v
    return out


def api(method, path, body=None):
    r = SESSION.request(method, BASE + path, auth=AUTH, data=form(body) if body else None,
                        timeout=60)
    r.raise_for_status()
    out = r.json()
    if isinstance(out, dict) and out.get("result") == "failed":
        raise RuntimeError(f"{path}: {out}")
    return out


def existing(path, key):
    return {row[key]: row["uuid"] for row in api("GET", path)["rows"]}


# aliases
have = existing("/firewall/alias/searchItem", "name")
for a in POLICY["aliases"]:
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
                     "protocol": r["proto"], "source_net": r["if"], "destination_net": r["dst"],
                     "destination_port": r["port"], "log": str(r["log"]), "description": r["desc"]}}
    if r["desc"] in have:
        print(r["desc"], api("POST", f"/firewall/filter/setRule/{have[r['desc']]}", rule)["result"])
    else:
        print(r["desc"], api("POST", "/firewall/filter/addRule", rule)["result"])
print("filter apply:", api("POST", "/firewall/filter/apply")["status"])

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
