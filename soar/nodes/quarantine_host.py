# Shuffle node "Quarantine_Host" (execute_python), added after Contain_Attacker.
#
# Endpoint counterpart to Contain_Attacker (network-level): isolates the compromised
# host itself via Velociraptor's built-in quarantine artifact for its OS
# (Windows.Remediation.Quarantine: IPSec/WFP policy; Linux.Remediation.Quarantine:
# nftables). Both block all traffic except DNS/DHCP and the channel back to the
# Velociraptor frontend, so the response team keeps control of an isolated host.
# Mechanism proven live on WIN01, 2026-09-25 — see dfir/quarantine_host.py and
# dfir/unquarantine_host.py, the CLI scripts this node's logic mirrors.
#
# Deliberately gated one step further than Contain_Attacker: it only acts when
# Contain_Attacker has *already* contained the source IP (tag auto-contained present) —
# defense in depth, not a parallel independent trigger. A host is only isolated once the
# chain is already confident enough to have blocked its network path out. It also needs
# a hostname/fqdn observable that resolves to a known Velociraptor client — Build_TheHive_Alert
# attaches the Wazuh agent name and, for Windows events, the Windows computer name.
#
# Guardrail: a client carrying the Velociraptor label "no-auto-quarantine" (the domain
# controller) is never isolated by the chain. The alert is tagged
# quarantine:approval-required and the decision goes to an analyst, who can run
# dfir/quarantine_host.py by hand. The list of protected assets lives in Velociraptor,
# next to the inventory, not in this node.
#
# Access to Velociraptor: SSH with a dedicated key to the account "soar" on the server,
# whose only allowed command pipes a VQL query to the Velociraptor API (see
# dfir/velociraptor_client.py). The server's host key is pinned: an unknown key aborts.
#
# Placeholders __THEHIVE__, __THEHIVE_KEY__, __VELO_SSH_HOST__, __VELO_SSH_PORT__,
# __VELO_SSH_USER__, __VELO_SSH_KEY__, __VELO_HOST_KEY__ are filled in by
# soar/create_wazuh_webhook_workflow.py at deploy time from environment variables;
# nothing here is a secret at rest.

CODE = r'''import base64, io, json, datetime, subprocess, sys, requests

try:
    import paramiko
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "paramiko"], check=True)
    import paramiko

THEHIVE, TH_KEY = "__THEHIVE__", "__THEHIVE_KEY__"
VELO_HOST, VELO_PORT, VELO_USER = "__VELO_SSH_HOST__", int("__VELO_SSH_PORT__"), "__VELO_SSH_USER__"
VELO_KEY = """__VELO_SSH_KEY__"""
VELO_HOST_KEY = "__VELO_HOST_KEY__"
TH = {"Authorization": "Bearer " + TH_KEY, "Content-Type": "application/json"}
ARTIFACTS = {"windows": "Windows.Remediation.Quarantine", "linux": "Linux.Remediation.Quarantine"}
PROTECTED_LABEL = "no-auto-quarantine"

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
    name = VELO_HOST if VELO_PORT == 22 else "[%s]:%d" % (VELO_HOST, VELO_PORT)
    c.get_host_keys().add(name, "ssh-ed25519",
                          paramiko.Ed25519Key(data=base64.b64decode(VELO_HOST_KEY)))
    c.set_missing_host_key_policy(paramiko.RejectPolicy())
    c.connect(VELO_HOST, port=VELO_PORT, username=VELO_USER,
              pkey=paramiko.Ed25519Key.from_private_key(io.StringIO(VELO_KEY)),
              allow_agent=False, look_for_keys=False, timeout=30, banner_timeout=60)
    try:
        stdin, stdout, _ = c.exec_command("vql", timeout=90)
        stdin.write(query)
        stdin.channel.shutdown_write()
        text = stdout.read().decode(errors="replace")
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
known = vql("SELECT client_id, os_info.hostname AS hostname, os_info.fqdn AS fqdn, "
            "os_info.system AS system, labels FROM clients()")
match = next((c for c in known
              if short(c.get("hostname")) in wanted or short(c.get("fqdn")) in wanted), None)

if not match:
    out["skipped"] = "no Velociraptor client matches hostnames %s" % sorted(wanted)
    print(json.dumps(out))
    raise SystemExit(0)

client_id, hostname = match["client_id"], match.get("hostname") or hostnames[0]
out.update({"hostname": hostname, "client_id": client_id})

if PROTECTED_LABEL in (match.get("labels") or []):
    out["skipped"] = "protected host (label %s): analyst approval required" % PROTECTED_LABEL
    requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30, json={
        "tags": sorted(set(tags + ["quarantine:approval-required"])),
        "description": alert.get("description", "") +
            "\n\n[SOAR] %s: host %s (%s) is a protected asset (label %s): not isolated "
            "automatically, approval required (dfir/quarantine_host.py)." %
            (now, hostname, client_id, PROTECTED_LABEL)})
    print(json.dumps(out))
    raise SystemExit(0)

artifact = ARTIFACTS.get(str(match.get("system") or "").lower())
if not artifact:
    out["skipped"] = "no quarantine artifact for OS %r" % match.get("system")
    print(json.dumps(out))
    raise SystemExit(0)

env = "env=dict(MessageBox='SocForge SOC - host isole par la reponse automatisee')" \
    if artifact.startswith("Windows") else "env=dict()"
flow_id = vql("SELECT collect_client(client_id='%s', artifacts='%s', %s).flow_id AS f "
              "FROM scope()" % (client_id, artifact, env))[0]["f"]

out.update({"quarantined": True, "artifact": artifact, "flow_id": flow_id})

requests.patch(THEHIVE + "/api/v1/alert/" + alert_id, headers=TH, timeout=30, json={
    "tags": sorted(set(tags + ["auto-quarantined"])),
    "description": alert.get("description", "") +
        "\n\n[SOAR] %s: hote %s (%s) isole du reseau par Velociraptor "
        "(%s, flow %s) - canal Velociraptor conserve pour "
        "l'investigation. Reversible avec dfir/unquarantine_host.py." %
        (now, hostname, client_id, artifact, flow_id)})

print(json.dumps(out))
'''
