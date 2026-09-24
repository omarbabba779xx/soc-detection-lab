"""Create the Shuffle workflow "Wazuh alert -> TheHive alert" with a webhook trigger.

Usage: SHUFFLE_URL=http://10.10.10.30:3001 SHUFFLE_KEY=... THEHIVE_KEY=... python create_wazuh_webhook_workflow.py
Prints the webhook URL to put in the Wazuh <integration> block (see wazuh/manager/integration-shuffle.xml).

With SHUFFLE_WORKFLOW_ID=<id>, only the code of the Build_TheHive_Alert node of that
existing workflow is replaced: the webhook, and so the Wazuh integration, stay as they are.
"""
import json, os, uuid, requests

BASE = os.environ.get("SHUFFLE_URL", "http://10.10.10.30:3001").rstrip("/") + "/api/v1"
H = {"Authorization": "Bearer " + os.environ["SHUFFLE_KEY"]}
THEHIVE = os.environ.get("THEHIVE_URL", "http://10.10.10.20:9000")
TOOLS = ("Shuffle Tools", "1.2.0", "41f94d2b-eee9-466b-97ef-1b7348961e84")
HTTP = ("http", "1.4.0", "60bcf2f6-aafb-43bc-b9f2-63ae340fb296")

# Wazuh's shuffle.py posts {"severity", "title", "rule_id", "all_fields": <alert>, ...}
BUILD_ALERT = r'''import json
evt = json.loads(r"""$exec""")
a = evt.get("all_fields", evt)
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
            full = (s.get("report") or {}).get("full") or {}
            j["misp_hits"] = sum(len(r.get("result", [])) for r in full.get("results", []))
            break
        time.sleep(5)
out["misp_match"] = any(j.get("misp_hits") for j in out["jobs"])
if out["misp_match"]:
    alert = requests.get(THEHIVE + "/api/v1/alert/" + alert_id, headers=H, timeout=30).json()
    requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=H, timeout=30,
                   json={"tags": sorted(set(alert.get("tags", []) + ["misp:match"]))})
print(json.dumps(out))
'''


def action(label, app, fn, params, x, y):
    return {"id": str(uuid.uuid4()), "label": label, "app_name": app[0], "app_version": app[1],
            "app_id": app[2], "name": fn, "environment": "Shuffle", "is_valid": True,
            "position": {"x": x, "y": y},
            "parameters": [{"name": k, "value": v, "required": False, "multiline": "\n" in v}
                           for k, v in params.items()]}


ENRICH = ENRICH.replace("__THEHIVE__", THEHIVE).replace("__THEHIVE_KEY__", os.environ["THEHIVE_KEY"])

if os.environ.get("SHUFFLE_WORKFLOW_ID"):
    wf = requests.get(BASE + "/workflows/" + os.environ["SHUFFLE_WORKFLOW_ID"], headers=H, timeout=30).json()
    node = next(n for n in wf["actions"] if n["label"] == "Build_TheHive_Alert")
    next(p for p in node["parameters"] if p["name"] == "code")["value"] = BUILD_ALERT
    enrich = next((n for n in wf["actions"] if n["label"] == "Enrich_With_Cortex"), None)
    if enrich:
        next(p for p in enrich["parameters"] if p["name"] == "code")["value"] = ENRICH
    else:
        create = next(n for n in wf["actions"] if n["label"] == "Create_TheHive_Alert")
        enrich = action("Enrich_With_Cortex", TOOLS, "execute_python", {"code": ENRICH}, 900, 0)
        wf["actions"].append(enrich)
        wf["branches"].append({"id": str(uuid.uuid4()), "source_id": create["id"], "destination_id": enrich["id"]})
    r = requests.put(BASE + "/workflows/" + wf["id"], headers=H, json=wf, timeout=30)
    print("workflow", wf["id"], "updated (Build_TheHive_Alert, Enrich_With_Cortex):", r.status_code)
    raise SystemExit(0 if r.ok else 1)

wf = requests.post(BASE + "/workflows", headers=H, timeout=30, json={
    "name": "Wazuh alert to TheHive (webhook)",
    "description": "Triggered by the Wazuh shuffle integration (alerts level >= 10). "
                   "Turns the Wazuh alert into a TheHive alert with MITRE tags and observables, "
                   "then has TheHive run the Cortex MISP analyzer on them."}).json()

build = action("Build_TheHive_Alert", TOOLS, "execute_python", {"code": BUILD_ALERT}, 300, 0)
create = action("Create_TheHive_Alert", HTTP, "POST", {
    "url": THEHIVE + "/api/v1/alert",
    "body": "$build_thehive_alert.message",
    "headers": "Content-Type: application/json\nAuthorization: Bearer " + os.environ["THEHIVE_KEY"],
    "username": "", "password": "", "verify": "", "http_proxy": "", "https_proxy": "", "timeout": ""}, 600, 0)
hook_id = str(uuid.uuid4())
trigger = {"id": hook_id, "label": "Wazuh_Webhook", "name": "Webhook", "trigger_type": "WEBHOOK",
           "app_name": "Webhook", "status": "uninitialized", "environment": "Shuffle",
           "position": {"x": 0, "y": 0}, "parameters": [
               {"name": "url", "value": ""}, {"name": "tmp", "value": ""}, {"name": "auth_headers", "value": ""}]}

enrich = action("Enrich_With_Cortex", TOOLS, "execute_python", {"code": ENRICH}, 900, 0)
wf.update({"actions": [build, create, enrich], "triggers": [trigger], "start": build["id"],
           "branches": [{"id": str(uuid.uuid4()), "source_id": hook_id, "destination_id": build["id"]},
                        {"id": str(uuid.uuid4()), "source_id": build["id"], "destination_id": create["id"]},
                        {"id": str(uuid.uuid4()), "source_id": create["id"], "destination_id": enrich["id"]}]})
r = requests.put(BASE + f"/workflows/{wf['id']}", headers=H, json=wf, timeout=30)
print("workflow", wf["id"], r.status_code)

r = requests.post(BASE + "/hooks/new", headers=H, timeout=30, json={
    "name": "Wazuh_Webhook", "type": "webhook", "id": hook_id, "workflow": wf["id"],
    "start": build["id"], "environment": "Shuffle", "auth": "", "custom_response": "", "version": ""})
print("hook", r.status_code, r.text[:200])
print("webhook url:", BASE.replace("/api/v1", "") + f"/api/v1/hooks/webhook_{hook_id}")
