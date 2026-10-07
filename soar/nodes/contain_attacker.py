# Shuffle node "Contain_Attacker" (execute_python), added after Enrich_With_Cortex.
#
# On a high-severity, MISP-confirmed alert with a source IP, blocks that IP on OPNsense
# (BLOCKED_ATTACKERS alias, blocked on every zone interface — see
# firewall/segmentation-policy.json and firewall/contain_attacker.py) and records the
# action on the TheHive alert itself: tags and a line appended to the description, with
# a UTC timestamp. Idempotent (blocking an already-blocked IP is a no-op) and reversible
# by hand with firewall/uncontain_attacker.py.
#
# Guardrails:
#   - the observable must parse as an IP address, nothing else reaches the firewall API;
#   - an address inside __NEVER_BLOCK__ (SOC network, gateways, domain controller) is
#     never blocked: the alert is tagged containment:refused-protected instead, for an
#     analyst to decide;
#   - the block is temporary: the tags contained-ip:<ip> and contained-at:<epoch> let
#     Expire_Containment (soar/nodes/housekeeping.py) lift it after __BLOCK_TTL_HOURS__ h.
#
# Placeholders __THEHIVE__, __THEHIVE_KEY__, __OPN_URL__, __OPN_KEY__, __OPN_SECRET__,
# __LAB_CA__, __NEVER_BLOCK__, __BLOCK_TTL_HOURS__ are filled in by
# soar/create_wazuh_webhook_workflow.py at deploy time; nothing here is a secret at rest.
#
# Threshold: TheHive severity 3 (Build_TheHive_Alert sets this for Wazuh level >= 12) AND
# tag misp:match (set synchronously by Enrich_With_Cortex, which runs first in the chain).

CODE = r'''import json, tempfile, datetime, ipaddress, time, requests

THEHIVE, TH_KEY = "__THEHIVE__", "__THEHIVE_KEY__"
OPN_URL, OPN_KEY, OPN_SECRET = "__OPN_URL__", "__OPN_KEY__", "__OPN_SECRET__"
TH = {"Authorization": "Bearer " + TH_KEY, "Content-Type": "application/json"}
ca_file = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False)
ca_file.write("""__LAB_CA__""")
ca_file.close()
NEVER_BLOCK = [ipaddress.ip_network(n.strip()) for n in "__NEVER_BLOCK__".split(",") if n.strip()]
TTL_HOURS = float("__BLOCK_TTL_HOURS__")

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

try:
    addr = ipaddress.ip_address(ip.strip())
except ValueError:
    out["skipped"] = "ip observable is not a valid address"
    print(json.dumps(out))
    raise SystemExit(0)
ip = str(addr)

if any(addr in net for net in NEVER_BLOCK):
    out.update({"ip": ip, "skipped": "protected address, never blocked automatically"})
    requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30, json={
        "tags": sorted(set(tags + ["containment:refused-protected"])),
        "description": alert.get("description", "") +
            "\n\n[SOAR] %s: %s is on the never-block list (protected address); not "
            "blocked, left to an analyst." % (now, ip)})
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
    "tags": sorted(set(tags + ["auto-contained", "contained-ip:" + ip,
                               "contained-at:%d" % time.time()])),
    "description": alert.get("description", "") +
        "\n\n[SOAR] %s: %s added to OPNsense alias BLOCKED_ATTACKERS (blocked on every "
        "zone interface) after a MISP-confirmed, high-severity alert. Lifted automatically "
        "after %g h, or by hand with firewall/uncontain_attacker.py." % (now, ip, TTL_HOURS)})

print(json.dumps(out))
'''
