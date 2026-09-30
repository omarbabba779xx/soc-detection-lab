# Shuffle node "Quarantine_Host" (execute_python), added after Contain_Attacker.
#
# Endpoint counterpart to Contain_Attacker (network-level): isolates the compromised
# Windows host itself via Velociraptor's built-in Windows.Remediation.Quarantine
# artifact (IPSec/WFP policy — blocks all traffic except DNS/DHCP and the channel back to
# the Velociraptor frontend, so the response team keeps control of an isolated host).
# Mechanism proven live on WIN01, 2026-09-25 — see dfir/quarantine_host.py and
# dfir/unquarantine_host.py, the CLI scripts this node's logic mirrors.
#
# Deliberately gated one step further than Contain_Attacker: it only acts when
# Contain_Attacker has *already* contained the source IP (tag auto-contained present) —
# defense in depth, not a parallel independent trigger. A host is only isolated once the
# chain is already confident enough to have blocked its network path out. It also needs
# a hostname/fqdn observable that resolves to a known Velociraptor client — most alerts
# won't have one (Wazuh's Build_TheHive_Alert only adds a hostname observable for
# FIM/Sysmon-sourced events), so this stays a narrow, deliberate action, not a default.
#
# Placeholders __THEHIVE__, __THEHIVE_KEY__, __VELO_SSH_HOST__, __VELO_SSH_PORT__,
# __VELO_SSH_USER__, __VELO_SSH_PASSWORD__ are filled in by
# soar/create_wazuh_webhook_workflow.py at deploy time from environment variables;
# nothing here is a secret at rest.

CODE = r'''import json, datetime, subprocess, sys, requests

try:
    import paramiko
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "paramiko"], check=True)
    import paramiko

THEHIVE, TH_KEY = "__THEHIVE__", "__THEHIVE_KEY__"
VELO_HOST, VELO_PORT = "__VELO_SSH_HOST__", int("__VELO_SSH_PORT__")
VELO_USER, VELO_PASSWORD = "__VELO_SSH_USER__", "__VELO_SSH_PASSWORD__"
TH = {"Authorization": "Bearer " + TH_KEY, "Content-Type": "application/json"}

alert_id = "$create_thehive_alert.body._id"
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
out = {"alert": alert_id, "quarantined": False}

alert = requests.get(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30).json()
tags = alert.get("tags", [])

if "auto-contained" not in tags:
    out["skipped"] = "no network containment on this alert (Contain_Attacker did not act)"
    print(json.dumps(out))
    raise SystemExit(0)

obs = requests.post(THEHIVE + "/api/v1/query", headers=TH, timeout=30, json={
    "query": [{"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}]}).json()
hostnames = [o["data"] for o in obs if o["dataType"] == "hostname"]

if not hostnames:
    out["skipped"] = "no hostname observable on this alert"
    print(json.dumps(out))
    raise SystemExit(0)

def vql(query):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(VELO_HOST, port=VELO_PORT, username=VELO_USER, password=VELO_PASSWORD,
              timeout=30, banner_timeout=60)
    try:
        sftp = c.open_sftp()
        with sftp.open("/tmp/q.vql", "w") as f:
            f.write(query)
        sftp.close()
        cmd = ("echo '%s' | sudo -S -p '' sh -c "
               "'velociraptor --api_config /home/socadmin/api.config.yaml query --format json "
               '"$(cat /tmp/q.vql)"\'') % VELO_PASSWORD
        text = c.exec_command(cmd, timeout=120)[1].read().decode(errors="replace")
        return json.loads(text[text.index("["):])
    finally:
        c.close()

# Wazuh names an agent "WIN01", Velociraptor knows the same machine by its Windows name
# ("DESKTOP-75LAKDV", FQDN "DESKTOP-75LAKDV.socforge.lab"): Build_TheHive_Alert attaches
# both as hostname observables, and any of them may match a Velociraptor client, compared
# on the short name, case-insensitively.
def short(name):
    return str(name or "").split(".")[0].lower()

wanted = {short(h) for h in hostnames}
known = vql("SELECT client_id, os_info.hostname AS hostname, os_info.fqdn AS fqdn FROM clients()")
match = next((c for c in known
              if short(c.get("hostname")) in wanted or short(c.get("fqdn")) in wanted), None)

if not match:
    out["skipped"] = "no Velociraptor client matches hostnames %s" % sorted(wanted)
    print(json.dumps(out))
    raise SystemExit(0)

client_id, hostname = match["client_id"], match.get("hostname") or hostnames[0]
flow_id = vql("SELECT collect_client(client_id='%s', "
              "artifacts='Windows.Remediation.Quarantine', "
              "env=dict(MessageBox='SocForge SOC - host isole par la reponse automatisee'))"
              ".flow_id AS f FROM scope()" % client_id)[0]["f"]

out.update({"hostname": hostname, "client_id": client_id, "quarantined": True, "flow_id": flow_id})

requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30, json={
    "tags": sorted(set(tags + ["auto-quarantined"])),
    "description": alert.get("description", "") +
        "\n\n[SOAR] %s: hote %s (%s) isole du reseau par Velociraptor "
        "(Windows.Remediation.Quarantine, flow %s) - canal Velociraptor conserve pour "
        "l'investigation. Reversible avec dfir/unquarantine_host.py." %
        (now, hostname, client_id, flow_id)})

print(json.dumps(out))
'''
