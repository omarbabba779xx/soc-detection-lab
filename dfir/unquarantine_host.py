"""Lift a host-level quarantine applied by quarantine_host.py.

Usage:  VELO_SSH_PASSWORD=... python unquarantine_host.py <client_id>
"""
import json
import sys

from velociraptor_client import collect, flow_state

ARTIFACT = "Windows.Remediation.Quarantine"


def unquarantine(client_id):
    flow_id = collect(client_id, ARTIFACT, env={"RemovePolicy": "Y"})
    state = flow_state(client_id, flow_id)
    return {"client_id": client_id, "artifact": ARTIFACT, "flow_id": flow_id, "state": state, "removed": True}


if __name__ == "__main__":
    client_id = sys.argv[1]
    print(json.dumps(unquarantine(client_id)))
