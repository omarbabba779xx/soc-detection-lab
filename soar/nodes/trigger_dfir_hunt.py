# Shuffle node "Trigger_DFIR_Hunt" (execute_python), added after Contain_Attacker.
#
# Closes the loop between the SOAR chain and DFIR: on a misp:match alert, republishes
# the matched MISP event(s), which Custom.Server.MISP.AutoHunt (Velociraptor, polling
# MISP every 60 s, see velociraptor/artifacts/) picks up as a new publication and hunts
# for on the Windows endpoints; Custom.Server.MISP.Sightings then reports back to MISP as
# soon as the hunt's flow finishes (see SC-15). This node does not talk to Velociraptor
# directly — it reuses the two artifacts above, already proven end to end — and instead
# waits a little and reads the resulting sightings back from MISP, so the TheHive alert
# carries the outcome, not just the fact that a hunt was asked for.
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
now = lambda: datetime.datetime.now(datetime.timezone.utc)
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
                if ev.get("id"):
                    event_ids.add(str(ev["id"]))
out["event_ids"] = sorted(event_ids)

if not event_ids:
    out["skipped"] = "misp:match set but no event id found in the stored reports"
    print(json.dumps(out))
    raise SystemExit(0)

trigger_time = now()
for eid in event_ids:
    r = requests.post(MISP + "/events/publish/" + eid, headers=MH, timeout=30, verify=ca_file.name)
    out["triggered"] = True

# Give AutoHunt its poll interval plus a short hunt window, then look for sightings that
# landed after this node asked for them. Not finding one yet is not an error: the hunt
# may still be running when this node's own timeout is reached.
sightings_seen = []
deadline = time.time() + 150
while time.time() < deadline and not sightings_seen:
    time.sleep(15)
    for eid in event_ids:
        r = requests.get(MISP + "/sightings/index/" + eid, headers=MH, timeout=30, verify=ca_file.name)
        for row in (r.json() if r.ok else []):
            s = row.get("Sighting", row)
            if "Velociraptor" in (s.get("source") or "") and \
               datetime.datetime.fromtimestamp(int(s["date_sighting"]), datetime.timezone.utc) >= trigger_time:
                sightings_seen.append({"event_id": eid, "source": s["source"],
                                       "at": s["date_sighting"]})
out["sightings"] = sightings_seen

note = "\n\n[SOAR] %s: republished MISP event(s) %s to trigger Custom.Server.MISP.AutoHunt " \
       "(Velociraptor)." % (now().strftime("%Y-%m-%d %H:%M:%S UTC"), ", ".join(event_ids))
tag = "dfir:hunt-triggered"
if sightings_seen:
    note += " Hunt completed: %d sighting(s) back from Velociraptor within the wait window." % len(sightings_seen)
    tag = "dfir:hunted"
else:
    note += " No sighting yet within this node's wait window; check SC-15 / MISP for the " \
            "hunt this triggers within the next poll cycle."

requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30, json={
    "tags": sorted(set(alert.get("tags", []) + [tag])),
    "description": alert.get("description", "") + note})

print(json.dumps(out))
'''
