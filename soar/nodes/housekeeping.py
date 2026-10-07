# Shuffle workflow "SOAR housekeeping" (schedule trigger): two execute_python nodes that
# finish, later, what the alert chain started. Neither depends on the alert that
# triggered the chain still being "in flight": both find their work through tags on the
# TheHive alerts, so they survive a restart and a slow or offline endpoint.
#
#   Follow_DFIR_Hunt    alerts tagged dfir:hunt-triggered (Trigger_DFIR_Hunt) but not yet
#                       dfir:hunted: reads the sightings Velociraptor sent to MISP after
#                       the hunt was requested and writes the outcome on the alert.
#   Expire_Containment  alerts tagged auto-contained (Contain_Attacker) whose block is
#                       older than __BLOCK_TTL_HOURS__ h: removes the IP from the OPNsense
#                       alias BLOCKED_ATTACKERS, unless a more recent alert still holds
#                       it, and tags the alert containment:expired.
#
# Placeholders filled in by soar/create_wazuh_webhook_workflow.py at deploy time.

FOLLOW_HUNT = r'''import json, tempfile, time, datetime, requests

THEHIVE, TH_KEY = "__THEHIVE__", "__THEHIVE_KEY__"
MISP, MISP_KEY = "__MISP_URL__", "__MISP_KEY__"
GIVE_UP_HOURS = 24
TH = {"Authorization": "Bearer " + TH_KEY, "Content-Type": "application/json"}
MH = {"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"}
ca_file = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False)
ca_file.write("""__LAB_CA__""")
ca_file.close()

def tagged(tag, *without):
    conds = [{"_field": "tags", "_value": tag}] + [{"_not": {"_field": "tags", "_value": t}} for t in without]
    return requests.post(THEHIVE + "/api/v1/query", headers=TH, timeout=30, json={"query": [
        {"_name": "listAlert"}, {"_name": "filter", "_and": conds},
        {"_name": "page", "from": 0, "to": 50}]}).json()

def value(tags, prefix):
    return [t[len(prefix):] for t in tags if t.startswith(prefix)]

out = {"checked": 0, "hunted": [], "gave_up": []}
for alert in tagged("dfir:hunt-triggered", "dfir:hunted", "dfir:hunt-no-sighting"):
    tags = alert.get("tags", [])
    requested = value(tags, "hunt-requested:")
    events = [e for e in value(tags, "misp-event:") if e.isdigit()]
    if not requested or not requested[0].isdigit() or not events:
        continue
    requested = int(requested[0])
    out["checked"] += 1
    seen = []
    for eid in events:
        r = requests.get(MISP + "/sightings/index/" + eid, headers=MH, timeout=30, verify=ca_file.name)
        for row in (r.json() if r.ok else []):
            s = row.get("Sighting", row)
            if "Velociraptor" in (s.get("source") or "") and int(s["date_sighting"]) >= requested:
                seen.append({"event": eid, "source": s["source"], "at": int(s["date_sighting"])})
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if seen:
        first = min(s["at"] for s in seen)
        note = "\n\n[SOAR] %s: hunt completed, %d sighting(s) back from Velociraptor on MISP " \
               "event(s) %s, first one %d s after the request (%s)." % (
                   now, len(seen), ", ".join(sorted({s["event"] for s in seen})),
                   first - requested, "; ".join(sorted({s["source"] for s in seen})))
        tag = "dfir:hunted"
        out["hunted"].append({"alert": alert["_id"], "sightings": len(seen), "delay_s": first - requested})
    elif time.time() - requested > GIVE_UP_HOURS * 3600:
        note = "\n\n[SOAR] %s: no sighting from Velociraptor %d h after the hunt request; " \
               "nothing found on the endpoints, or the hunt did not run (see SC-15)." % (now, GIVE_UP_HOURS)
        tag = "dfir:hunt-no-sighting"
        out["gave_up"].append(alert["_id"])
    else:
        continue
    requests.patch(THEHIVE + "/api/v1/alert/" + alert["_id"], headers=TH, timeout=30, json={
        "tags": sorted(set(tags + [tag])), "description": alert.get("description", "") + note})

print(json.dumps(out))
'''

EXPIRE = r'''import json, tempfile, time, datetime, ipaddress, requests

THEHIVE, TH_KEY = "__THEHIVE__", "__THEHIVE_KEY__"
OPN_URL, OPN_KEY, OPN_SECRET = "__OPN_URL__", "__OPN_KEY__", "__OPN_SECRET__"
TTL = float("__BLOCK_TTL_HOURS__") * 3600
TH = {"Authorization": "Bearer " + TH_KEY, "Content-Type": "application/json"}
ca_file = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False)
ca_file.write("""__LAB_CA__""")
ca_file.close()

def opn(path, address=None):
    r = requests.post(OPN_URL.rstrip("/") + "/api" + path, auth=(OPN_KEY, OPN_SECRET),
                      data={"address": address} if address else None, verify=ca_file.name, timeout=30)
    r.raise_for_status()
    return r.json()

def value(tags, prefix):
    return next((t[len(prefix):] for t in tags if t.startswith(prefix)), "")

active = requests.post(THEHIVE + "/api/v1/query", headers=TH, timeout=30, json={"query": [
    {"_name": "listAlert"},
    {"_name": "filter", "_and": [{"_field": "tags", "_value": "auto-contained"},
                                 {"_not": {"_field": "tags", "_value": "containment:expired"}}]},
    {"_name": "page", "from": 0, "to": 100}]}).json()

blocks = []
for a in active:
    tags = a.get("tags", [])
    ip, at = value(tags, "contained-ip:"), value(tags, "contained-at:")
    try:
        blocks.append((a, str(ipaddress.ip_address(ip)), int(at)))
    except ValueError:
        continue

limit = time.time() - TTL
still_held = {ip for _, ip, at in blocks if at > limit}
out = {"active": len(blocks), "expired": [], "ttl_hours": TTL / 3600}
removed = set()
for a, ip, at in blocks:
    if at > limit:
        continue
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if ip in still_held:
        note = "\n\n[SOAR] %s: block of %s kept, a more recent alert still holds it." % (now, ip)
    else:
        if ip not in removed:
            opn("/firewall/alias_util/delete/BLOCKED_ATTACKERS", ip)
            removed.add(ip)
        note = "\n\n[SOAR] %s: block of %s lifted after %g h (removed from OPNsense alias " \
               "BLOCKED_ATTACKERS)." % (now, ip, TTL / 3600)
    out["expired"].append({"alert": a["_id"], "ip": ip, "removed": ip in removed})
    requests.patch(THEHIVE + "/api/v1/alert/" + a["_id"], headers=TH, timeout=30, json={
        "tags": sorted(set(a.get("tags", []) + ["containment:expired"])),
        "description": a.get("description", "") + note})

if removed:
    opn("/firewall/alias/reconfigure")
    opn("/firewall/filter/apply")

print(json.dumps(out))
'''
