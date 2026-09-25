"""Isolate one Windows host at the network level via Velociraptor: automated host-level
response for the SOAR workflow (SC-14), the endpoint counterpart to
firewall/contain_attacker.py (network-level).

Usage:  VELO_SSH_PASSWORD=... python quarantine_host.py <client_id> ["message"]

Runs the built-in `Windows.Remediation.Quarantine` artifact on the host: an IPSec-based
Windows Filtering Platform policy that blocks all traffic except DNS/DHCP and the
connection back to the Velociraptor frontend, so the agent stays reachable for
investigation and for reversal — an infected host is cut off from the network, not from
the response team. Proven live on WIN01 (2026-09-25): ping to the host goes from 0 % to
100 % loss within the flow's completion, while a fresh artifact collection through the
same channel still succeeds — the isolation is real, the control channel isn't.

Reversible with unquarantine_host.py (same artifact, RemovePolicy=Y), which lifts
exactly this policy and nothing else on the host.

Printed as one JSON line, so a caller (the Shuffle node) can parse the result.
"""
import json
import sys

from velociraptor_client import collect, flow_state

ARTIFACT = "Windows.Remediation.Quarantine"


def quarantine(client_id, message=""):
    flow_id = collect(client_id, ARTIFACT, env={"MessageBox": message} if message else None)
    state = flow_state(client_id, flow_id)
    return {"client_id": client_id, "artifact": ARTIFACT, "flow_id": flow_id, "state": state}


if __name__ == "__main__":
    client_id = sys.argv[1]
    message = sys.argv[2] if len(sys.argv) > 2 else ""
    print(json.dumps(quarantine(client_id, message)))
