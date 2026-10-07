# Shuffle node "Trigger_DFIR_Hunt" (execute_python), the last node of the chain (after Quarantine_Host).
#
# Closes the loop between the SOAR chain and DFIR: on a misp:match alert, republishes
# the matched MISP event(s), which Custom.Server.MISP.AutoHunt (Velociraptor, polling
# MISP every 60 s, see velociraptor/artifacts/) picks up as a new publication and hunts
# for on the endpoints; Custom.Server.MISP.Sightings then reports back to MISP as soon
# as the hunt's flow finishes (see SC-15). This node does not talk to Velociraptor
# directly — it reuses the two artifacts above, already proven end to end.
#
# The node only asks for the hunt and returns. A hunt takes at least one AutoHunt poll
# (60 s) plus the collection itself, and longer when the endpoint is offline: waiting
# for it here would exceed the 120 s Shuffle gives an action (the first version waited
# 150 s and was cut off by that timeout on every run without a fast sighting).
# The outcome is picked up later by Follow_DFIR_Hunt (soar/nodes/housekeeping.py), which
# finds this alert through the tags set here: dfir:hunt-triggered, hunt-requested:<epoch>
# and misp-event:<id>.
#
# Republishing an event MISP already had published, unchanged, still bumps
# publish_timestamp (checked live on 2026-09-24): AutoHunt's dedup key is
# (event_id, publish_timestamp), so this reliably produces a new hunt even for an event
# hunted before, rather than silently doing nothing.
#
# Placeholders filled in by soar/create_wazuh_webhook_workflow.py at deploy time.

CODE = r'''import json, tempfile, time, datetime, requests

THEHIVE, TH_KEY = "__THEHIVE__", "__THEHIVE_KEY__"
MISP, MISP_KEY = "__MISP_URL__", "__MISP_KEY__"
TH = {"Authorization": "Bearer " + TH_KEY, "Content-Type": "application/json"}
MH = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}
ca_file = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False)
ca_file.write("""__LAB_CA__""")
ca_file.close()

alert_id = "$create_thehive_alert.body._id"
out = {"alert": alert_id, "event_ids": [], "triggered": False}

alert = requests.get(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30).json()
if "misp:match" not in alert.get("tags", []):
    out["skipped"] = "no misp:match tag"
    print(json.dumps(out))
    raise SystemExit(0)

# Re-read the MISP_SocForge job reports already produced by Enrich_With_Cortex: no new
# analysis is run here, only the matched event ids are collected. The "jobs" query only
# gives a summary (status, analyzer name) with no report; the report itself is fetched
# per job from the same endpoint Enrich_With_Cortex polls while the job runs.
obs = requests.post(THEHIVE + "/api/v1/query", headers=TH, timeout=30, json={
    "query": [{"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}]}).json()
event_ids = set()
for o in obs:
    jobs = requests.post(THEHIVE + "/api/v1/query", headers=TH, timeout=30, json={
        "query": [{"_name": "getObservable", "idOrName": o["_id"]}, {"_name": "jobs"}]}).json()
    for j in jobs:
        if j.get("analyzerName") != "MISP_SocForge" or j.get("status") != "Success":
            continue
        report = requests.get(THEHIVE + "/api/connector/cortex/job/" + j["_id"], headers=TH, timeout=30).json()
        full = (report.get("report") or {}).get("full") or {}
        for r in full.get("results", []):
            for ev in r.get("result", []):
                if str(ev.get("id") or "").isdigit():
                    event_ids.add(str(ev["id"]))
out["event_ids"] = sorted(event_ids)

if not event_ids:
    out["skipped"] = "misp:match set but no event id found in the stored reports"
    print(json.dumps(out))
    raise SystemExit(0)

requested = int(time.time())
published = []
for eid in sorted(event_ids):
    r = requests.post(MISP + "/events/publish/" + eid, headers=MH, timeout=30, verify=ca_file.name)
    if r.ok:
        published.append(eid)
out.update({"triggered": bool(published), "published": published, "requested_at": requested})

if not published:
    out["skipped"] = "MISP refused the publication"
    print(json.dumps(out))
    raise SystemExit(0)

stamp = datetime.datetime.fromtimestamp(requested, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30, json={
    "tags": sorted(set(alert.get("tags", []) + ["dfir:hunt-triggered", "hunt-requested:%d" % requested] +
                       ["misp-event:" + e for e in published])),
    "description": alert.get("description", "") +
        "\n\n[SOAR] %s: republished MISP event(s) %s to trigger Custom.Server.MISP.AutoHunt "
        "(Velociraptor). The result is added to this alert when the hunt reports back." %
        (stamp, ", ".join(published))})

print(json.dumps(out))
'''
