"""Create the Shuffle workflow "Wazuh alert -> TheHive alert" with a webhook trigger.

Usage: SHUFFLE_URL=http://10.10.10.30:3001 SHUFFLE_KEY=... THEHIVE_KEY=... python create_wazuh_webhook_workflow.py
Prints the webhook URL to put in the Wazuh <integration> block (see wazuh/manager/integration-shuffle.xml).
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
src = data.get("srcip") or data.get("src_ip") or data.get("win", {}).get("eventdata", {}).get("ipAddress")
mitre = rule.get("mitre", {}).get("id", [])
level = int(rule.get("level", 0))
alert = {
    "type": "wazuh", "source": "wazuh-manager", "sourceRef": str(a.get("id", "")),
    "title": rule.get("description", "Wazuh alert"),
    "description": "Wazuh rule %s (level %s) on agent %s at %s\n\n%s" % (
        rule.get("id"), level, a.get("agent", {}).get("name"), a.get("timestamp"), (a.get("full_log") or "")[:2000]),
    "severity": 3 if level >= 12 else 2,
    "tags": ["wazuh", "rule-%s" % rule.get("id")] + mitre,
    "observables": [{"dataType": "ip", "data": src, "message": "Source IP from the Wazuh alert"}] if src else [],
}
print(json.dumps(alert))
'''


def action(label, app, fn, params, x, y):
    return {"id": str(uuid.uuid4()), "label": label, "app_name": app[0], "app_version": app[1],
            "app_id": app[2], "name": fn, "environment": "Shuffle", "is_valid": True,
            "position": {"x": x, "y": y},
            "parameters": [{"name": k, "value": v, "required": False, "multiline": "\n" in v}
                           for k, v in params.items()]}


wf = requests.post(BASE + "/workflows", headers=H, timeout=30, json={
    "name": "Wazuh alert to TheHive (webhook)",
    "description": "Triggered by the Wazuh shuffle integration (alerts level >= 10). "
                   "Turns the Wazuh alert into a TheHive alert with MITRE tags and the source IP as observable."}).json()

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

wf.update({"actions": [build, create], "triggers": [trigger], "start": build["id"],
           "branches": [{"id": str(uuid.uuid4()), "source_id": hook_id, "destination_id": build["id"]},
                        {"id": str(uuid.uuid4()), "source_id": build["id"], "destination_id": create["id"]}]})
r = requests.put(BASE + f"/workflows/{wf['id']}", headers=H, json=wf, timeout=30)
print("workflow", wf["id"], r.status_code)

r = requests.post(BASE + "/hooks/new", headers=H, timeout=30, json={
    "name": "Wazuh_Webhook", "type": "webhook", "id": hook_id, "workflow": wf["id"],
    "start": build["id"], "environment": "Shuffle", "auth": "", "custom_response": "", "version": ""})
print("hook", r.status_code, r.text[:200])
print("webhook url:", BASE.replace("/api/v1", "") + f"/api/v1/hooks/webhook_{hook_id}")
