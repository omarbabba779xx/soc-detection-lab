"""Create or update the Shuffle workflow "Wazuh alert -> TheHive alert" with a webhook trigger.

Usage: SHUFFLE_URL=http://10.10.10.30:3001 SHUFFLE_KEY=... THEHIVE_KEY=... MISP_KEY=...
       OPN_KEY=... OPN_SECRET=... VELO_SSH_KEY_FILE=... VELO_HOST_KEY=...
       python create_wazuh_webhook_workflow.py
Prints the webhook URL to put in the Wazuh <integration> block (see
wazuh/manager/integration-shuffle.xml). MISP_KEY, OPN_KEY/OPN_SECRET, VELO_SSH_KEY_FILE
(private key of the account "soar" on the Velociraptor server) and VELO_HOST_KEY (base64
ed25519 host key of that server, as in known_hosts) are only needed to (re)deploy
Contain_Attacker / Quarantine_Host / Trigger_DFIR_Hunt; the rest of the chain works
without them.

Guardrail settings: NEVER_BLOCK (comma-separated networks Contain_Attacker must never
block; default: SOC network, zone gateways, domain controller) and BLOCK_TTL_HOURS
(default 24), after which Expire_Containment lifts a block.

With SHUFFLE_WORKFLOW_ID=<id>, the existing workflow is updated in place: every node
below is created if missing, or has its code refreshed if already present. The webhook,
and so the Wazuh integration, is left untouched either way.

Chain: Wazuh_Webhook -> Build_TheHive_Alert -> Create_TheHive_Alert -> Enrich_With_Cortex
       -> Contain_Attacker -> Quarantine_Host -> Trigger_DFIR_Hunt
See soar/nodes/*.py for what Contain_Attacker, Quarantine_Host and Trigger_DFIR_Hunt do
and why.

With HOUSEKEEPING=1, the script handles the second workflow instead, "SOAR housekeeping"
(Follow_DFIR_Hunt -> Expire_Containment, see soar/nodes/housekeeping.py), run on a
schedule every HOUSEKEEPING_SECONDS (default 300). HOUSEKEEPING_WORKFLOW_ID=<id> updates
it in place.
"""
import os, pathlib, uuid, requests

HERE = pathlib.Path(__file__).resolve().parent
BASE = os.environ.get("SHUFFLE_URL", "http://10.10.10.30:3001").rstrip("/") + "/api/v1"
H = {"Authorization": "Bearer " + os.environ.get("SHUFFLE_KEY", "")}
THEHIVE_KEY = os.environ.get("THEHIVE_KEY", "")
THEHIVE = os.environ.get("THEHIVE_URL", "http://10.10.10.20:9000")
MISP = os.environ.get("MISP_URL", "https://10.10.10.22")
OPNSENSE = os.environ.get("OPN_URL", "https://10.10.10.1")
LAB_CA = (HERE.parent / "pki" / "socforge-lab-ca.crt").read_text()
TOOLS = ("Shuffle Tools", "1.2.0", "41f94d2b-eee9-466b-97ef-1b7348961e84")
HTTP = ("http", "1.4.0", "60bcf2f6-aafb-43bc-b9f2-63ae340fb296")


NEVER_BLOCK = os.environ.get(
    "NEVER_BLOCK", "10.10.10.0/24,10.10.20.1,10.10.30.1,10.10.40.1,10.10.50.1,10.10.60.1,10.10.20.10")
BLOCK_TTL_HOURS = os.environ.get("BLOCK_TTL_HOURS", "24")


def load_node_code(filename, name="CODE"):
    """Load a NAME = r'''...''' string from a soar/nodes/*.py file."""
    ns = {}
    exec(compile((HERE / "nodes" / filename).read_text(encoding="utf-8"), filename, "exec"), ns)
    return ns[name]


def fill(code):
    """Replace the deploy-time placeholders of a node."""
    key_file = os.environ.get("VELO_SSH_KEY_FILE")
    values = {
        "__THEHIVE__": THEHIVE, "__THEHIVE_KEY__": THEHIVE_KEY,
        "__MISP_URL__": MISP, "__MISP_KEY__": os.environ.get("MISP_KEY", ""),
        "__OPN_URL__": OPNSENSE, "__OPN_KEY__": os.environ.get("OPN_KEY", ""),
        "__OPN_SECRET__": os.environ.get("OPN_SECRET", ""), "__LAB_CA__": LAB_CA,
        "__NEVER_BLOCK__": NEVER_BLOCK, "__BLOCK_TTL_HOURS__": BLOCK_TTL_HOURS,
        "__VELO_SSH_HOST__": os.environ.get("VELO_SSH_HOST", "10.10.10.61"),
        "__VELO_SSH_PORT__": os.environ.get("VELO_SSH_PORT", "22"),
        "__VELO_SSH_USER__": os.environ.get("VELO_SSH_USER", "soar"),
        "__VELO_SSH_KEY__": pathlib.Path(key_file).read_text() if key_file else "",
        "__VELO_HOST_KEY__": os.environ.get("VELO_HOST_KEY", ""),
    }
    for placeholder, value in values.items():
        code = code.replace(placeholder, value)
    return code


# Wazuh's shuffle.py posts {"severity", "title", "rule_id", "all_fields": <alert>, ...}
BUILD_ALERT = r'''import json
evt = json.loads(r"""$exec""")
a = evt.get("all_fields", evt)
# Anything that is not a Wazuh alert stops here: no rule id or no alert id, no TheHive alert
# (the next node then posts this message, which TheHive rejects).
if not isinstance(a, dict) or not a.get("id") or not a.get("rule", {}).get("id"):
    print(json.dumps({"rejected": "not a Wazuh alert"}))
    raise SystemExit(0)
rule, data = a.get("rule", {}), a.get("data", {})
win, fim = data.get("win", {}).get("eventdata", {}), a.get("syscheck", {})
src = data.get("srcip") or data.get("src_ip") or win.get("ipAddress")
mitre = rule.get("mitre", {}).get("id", [])
level = int(rule.get("level", 0))

# Every indicator the alert carries becomes a TheHive observable, so that the
# case is not empty and Cortex has something to analyse.
observables, seen = [], set()
def add(data_type, value, message):
    value = str(value or "").strip()
    if value and value not in ("-", "::1", "127.0.0.1") and (data_type, value) not in seen:
        seen.add((data_type, value))
        observables.append({"dataType": data_type, "data": value, "message": message})
add("ip", src, "Source IP")
add("hostname", a.get("agent", {}).get("name"), "Wazuh agent")
add("hostname", data.get("win", {}).get("system", {}).get("computer"), "Windows computer name")
add("filename", fim.get("path"), "File changed (FIM, %s)" % fim.get("event", ""))
add("hash", fim.get("sha256_after"), "SHA-256 of the file after the change (FIM)")
add("filename", win.get("image"), "Process image (Sysmon)")
add("filename", win.get("targetFilename"), "File written (Sysmon)")
add("registry", win.get("targetObject"), "Registry key (Sysmon)")
add("other", win.get("commandLine"), "Command line")
for h in (win.get("hashes") or "").split(","):
    if h.startswith("SHA256="):
        add("hash", h.split("=", 1)[1], "SHA-256 of the process image (Sysmon)")
add("other", win.get("targetUserName") or data.get("dstuser"), "Account")
alert = {
    "type": "wazuh", "source": "wazuh-manager", "sourceRef": str(a.get("id", "")),
    "title": rule.get("description", "Wazuh alert"),
    "description": "Wazuh rule %s (level %s) on agent %s at %s\n\n%s" % (
        rule.get("id"), level, a.get("agent", {}).get("name"), a.get("timestamp"), (a.get("full_log") or "")[:2000]),
    "severity": 3 if level >= 12 else 2,
    "tags": ["wazuh", "rule-%s" % rule.get("id")] + mitre,
    "observables": observables,
}
print(json.dumps(alert))
'''

# Runs right after the TheHive alert is created, in the same execution: TheHive asks
# Cortex to run the MISP analyzer on every observable it supports, the reports land on
# the observables in TheHive, and a MISP hit tags the alert "misp:match".
ENRICH = r'''import json, time, requests
THEHIVE, KEY, ANALYZER = "__THEHIVE__", "__THEHIVE_KEY__", "MISP_SocForge"
H = {"Authorization": "Bearer " + KEY, "Content-Type": "application/json"}
alert_id = "$create_thehive_alert.body._id"
out = {"alert": alert_id, "analyzer": ANALYZER, "jobs": []}
analyzers = requests.get(THEHIVE + "/api/connector/cortex/analyzer", headers=H, timeout=30).json()
an = next((a for a in analyzers if a.get("name") == ANALYZER), None)
if not an:
    out["error"] = "analyzer %s not available in TheHive" % ANALYZER
    print(json.dumps(out)); raise SystemExit(0)
observables = requests.post(THEHIVE + "/api/v1/query", headers=H, timeout=30, json={
    "query": [{"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}]}).json()
for o in observables:
    if o["dataType"] in an.get("dataTypeList", []):
        job = requests.post(THEHIVE + "/api/connector/cortex/job", headers=H, timeout=30, json={
            "analyzerId": an["id"], "cortexId": an["cortexIds"][0], "artifactId": o["_id"]}).json()
        out["jobs"].append({"observable": o["data"], "dataType": o["dataType"], "job": job.get("_id")})
deadline = time.time() + 180
for j in out["jobs"]:
    while j["job"] and time.time() < deadline:
        s = requests.get(THEHIVE + "/api/connector/cortex/job/" + j["job"], headers=H, timeout=30).json()
        j["status"] = s.get("status")
        if j["status"] in ("Success", "Failure"):
            # full.results[].result[] are the MISP events the value was found in
            full = (s.get("report") or {}).get("full") or {}
            events = [e for r in full.get("results", []) for e in r.get("result", [])]
            j["misp_hits"] = len(events)
            j["misp_events"] = sorted({str(e.get("id")) for e in events})
            break
        time.sleep(5)
out["misp_match"] = any(j.get("misp_hits") for j in out["jobs"])
if out["misp_match"]:
    alert = requests.get(THEHIVE + "/api/v1/alert/" + alert_id, headers=H, timeout=30).json()
    requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=H, timeout=30,
                   json={"tags": sorted(set(alert.get("tags", []) + ["misp:match"]))})
print(json.dumps(out))
'''

ENRICH = fill(ENRICH)
CONTAIN = fill(load_node_code("contain_attacker.py"))
QUARANTINE = fill(load_node_code("quarantine_host.py"))
TRIGGER_HUNT = fill(load_node_code("trigger_dfir_hunt.py"))
FOLLOW_HUNT = fill(load_node_code("housekeeping.py", "FOLLOW_HUNT"))
EXPIRE = fill(load_node_code("housekeeping.py", "EXPIRE"))


def action(label, app, fn, params, x, y):
    return {"id": str(uuid.uuid4()), "label": label, "app_name": app[0], "app_version": app[1],
            "app_id": app[2], "name": fn, "environment": "Shuffle", "is_valid": True,
            "position": {"x": x, "y": y},
            "parameters": [{"name": k, "value": v, "required": False, "multiline": "\n" in v}
                           for k, v in params.items()]}


# The chain, in order. Each entry beyond the first names the node it follows.
CHAIN = [
    ("Build_TheHive_Alert", TOOLS, "execute_python", {"code": BUILD_ALERT}, 300, None),
    ("Create_TheHive_Alert", HTTP, "POST", {
        "url": THEHIVE + "/api/v1/alert", "body": "$build_thehive_alert.message",
        "headers": "Content-Type: application/json\nAuthorization: Bearer " + THEHIVE_KEY,
        "username": "", "password": "", "verify": "", "http_proxy": "", "https_proxy": "", "timeout": ""},
     600, "Build_TheHive_Alert"),
    ("Enrich_With_Cortex", TOOLS, "execute_python", {"code": ENRICH}, 900, "Create_TheHive_Alert"),
    ("Contain_Attacker", TOOLS, "execute_python", {"code": CONTAIN}, 1200, "Enrich_With_Cortex"),
    ("Quarantine_Host", TOOLS, "execute_python", {"code": QUARANTINE}, 1500, "Contain_Attacker"),
    ("Trigger_DFIR_Hunt", TOOLS, "execute_python", {"code": TRIGGER_HUNT}, 1800, "Quarantine_Host"),
]


HOUSEKEEPING = [
    ("Follow_DFIR_Hunt", TOOLS, "execute_python", {"code": FOLLOW_HUNT}, 300, None),
    ("Expire_Containment", TOOLS, "execute_python", {"code": EXPIRE}, 600, "Follow_DFIR_Hunt"),
]


def ensure_chain(wf, hook_id=None, chain=None):
    """Create or refresh every node in CHAIN, and every branch between consecutive ones
    (including from the webhook to the first node, when hook_id is given). Existing code
    is replaced in place. Every node of a chain has exactly one predecessor by design (it's a
    linear chain, not a DAG): any existing branch that lands on a CHAIN node from
    somewhere other than its current "after" is removed first, so that re-running this
    after CHAIN's order changes (as when Quarantine_Host was inserted before
    Trigger_DFIR_Hunt) can't leave a stale second path into that node and fire it twice."""
    chain = chain or CHAIN
    by_label = {n["label"]: n for n in wf.get("actions", [])}
    for label, app, fn, params, x, after in chain:
        node = by_label.get(label)
        if node is None:
            node = action(label, app, fn, params, x, 0)
            wf.setdefault("actions", []).append(node)
            by_label[label] = node
        else:
            for k, v in params.items():
                p = next((p for p in node["parameters"] if p["name"] == k), None)
                if p:
                    p["value"] = v
                else:
                    node["parameters"].append({"name": k, "value": v, "required": False,
                                               "multiline": "\n" in str(v)})
        src_id = hook_id if after is None else by_label[after]["id"]
        wf["branches"] = [b for b in wf.get("branches", [])
                          if not (b["destination_id"] == node["id"] and b["source_id"] != src_id)]
        if src_id and not any(b["source_id"] == src_id and b["destination_id"] == node["id"]
                              for b in wf.get("branches", [])):
            wf.setdefault("branches", []).append({"id": str(uuid.uuid4()), "source_id": src_id,
                                                   "destination_id": node["id"]})
    return by_label[chain[0][0]]["id"]


def housekeeping():
    """Create or update the scheduled workflow "SOAR housekeeping"."""
    seconds = os.environ.get("HOUSEKEEPING_SECONDS", "300")
    wf_id = os.environ.get("HOUSEKEEPING_WORKFLOW_ID")
    if wf_id:
        wf = requests.get(BASE + "/workflows/" + wf_id, headers=H, timeout=30).json()
    else:
        wf = requests.post(BASE + "/workflows", headers=H, timeout=30, json={
            "name": "SOAR housekeeping",
            "description": "Runs on a schedule. Writes the outcome of the DFIR hunts asked for "
                           "by the alert chain on their TheHive alert, and lifts the OPNsense "
                           "blocks that have reached their time limit."}).json()
        wf["triggers"], wf["actions"], wf["branches"] = [], [], []
    start_id = ensure_chain(wf, chain=HOUSEKEEPING)
    wf["start"] = start_id
    for a in wf["actions"]:
        a["isStartNode"] = a["id"] == start_id
    r = requests.put(BASE + "/workflows/" + wf["id"], headers=H, json=wf, timeout=30)
    print("workflow", wf["id"], r.status_code, [l for l, *_ in HOUSEKEEPING])
    if not wf_id:
        r = requests.post(BASE + "/workflows/" + wf["id"] + "/schedule", headers=H, timeout=30, json={
            "name": "SOAR housekeeping", "frequency": seconds, "execution_argument": "",
            "start": start_id, "environment": "Shuffle", "id": str(uuid.uuid4())})
        print("schedule every", seconds, "s:", r.status_code, r.text[:200])


def main():
    if not os.environ.get("SHUFFLE_KEY") or not THEHIVE_KEY:
        raise SystemExit("SHUFFLE_KEY and THEHIVE_KEY are required")
    if os.environ.get("HOUSEKEEPING"):
        housekeeping()
        return 0

    if os.environ.get("SHUFFLE_WORKFLOW_ID"):
        wf = requests.get(BASE + "/workflows/" + os.environ["SHUFFLE_WORKFLOW_ID"], headers=H, timeout=30).json()
        hook = next((t for t in wf.get("triggers", []) if t.get("name") == "Webhook"), None)
        ensure_chain(wf, hook_id=hook["id"] if hook else None)
        r = requests.put(BASE + "/workflows/" + wf["id"], headers=H, json=wf, timeout=30)
        print("workflow", wf["id"], "updated:", r.status_code, [l for l, *_ in CHAIN])
        return 0 if r.ok else 1

    wf = requests.post(BASE + "/workflows", headers=H, timeout=30, json={
        "name": "Wazuh alert to TheHive (webhook)",
        "description": "Triggered by the Wazuh shuffle integration (alerts level >= 10). Turns "
                       "the Wazuh alert into a TheHive alert with MITRE tags and observables, "
                       "runs the Cortex MISP analyzer on them, contains a confirmed high-severity "
                       "source IP on OPNsense, and triggers the matching Velociraptor hunt."}).json()

    hook_id = str(uuid.uuid4())
    trigger = {"id": hook_id, "label": "Wazuh_Webhook", "name": "Webhook", "trigger_type": "WEBHOOK",
               "app_name": "Webhook", "status": "uninitialized", "environment": "Shuffle",
               "position": {"x": 0, "y": 0}, "parameters": [
                   {"name": "url", "value": ""}, {"name": "tmp", "value": ""}, {"name": "auth_headers", "value": ""}]}
    wf["triggers"], wf["actions"], wf["branches"] = [trigger], [], []
    start_id = ensure_chain(wf, hook_id=hook_id)
    wf["start"] = start_id
    r = requests.put(BASE + f"/workflows/{wf['id']}", headers=H, json=wf, timeout=30)
    print("workflow", wf["id"], r.status_code, [l for l, *_ in CHAIN])

    r = requests.post(BASE + "/hooks/new", headers=H, timeout=30, json={
        "name": "Wazuh_Webhook", "type": "webhook", "id": hook_id, "workflow": wf["id"],
        "start": start_id, "environment": "Shuffle", "auth": "", "custom_response": "", "version": ""})
    print("hook", r.status_code, r.text[:200])
    print("webhook url:", BASE.replace("/api/v1", "") + f"/api/v1/hooks/webhook_{hook_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
