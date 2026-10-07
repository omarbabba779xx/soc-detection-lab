"""Lift a host-level quarantine applied by quarantine_host.py.

Usage:  VELO_SSH_KEY_FILE=... VELO_KNOWN_HOSTS=... python unquarantine_host.py <client_id>
"""
import json
import sys

from quarantine_host import ARTIFACTS
from velociraptor_client import client_os, collect, flow_state


def unquarantine(client_id):
    artifact = ARTIFACTS[client_os(client_id)]
    flow_id = collect(client_id, artifact, env={"RemovePolicy": "Y"})
    state = flow_state(client_id, flow_id)
    return {"client_id": client_id, "artifact": artifact, "flow_id": flow_id, "state": state, "removed": True}


if __name__ == "__main__":
    client_id = sys.argv[1]
    print(json.dumps(unquarantine(client_id)))
