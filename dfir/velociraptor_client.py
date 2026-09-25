"""Small VQL client for the Velociraptor server, shared by quarantine_host.py and
unquarantine_host.py.

The server API is gRPC + mTLS (api_config.yaml, generated per API user) — no plain REST
endpoint exists for collecting artifacts. The lab's own tooling therefore runs the
`velociraptor query` CLI over SSH on the server itself, using the API config already
provisioned there (`/home/socadmin/api.config.yaml`, user `socforge-api`). This mirrors
`firewall/opnsense_client.py`'s role for OPNsense: one small client, reused everywhere a
script needs to talk to Velociraptor.

Env vars: VELO_SSH_HOST (default 127.0.0.1), VELO_SSH_PORT (default 18022),
VELO_SSH_USER / VELO_SSH_PASSWORD (SF-VM08-DFIR-HUNT console credentials),
VELO_API_CONFIG (default /home/socadmin/api.config.yaml, on the server).
"""
import json
import os

import paramiko

HOST = os.environ.get("VELO_SSH_HOST", "127.0.0.1")
PORT = int(os.environ.get("VELO_SSH_PORT", "18022"))
USER = os.environ.get("VELO_SSH_USER", "socadmin")
PASSWORD = os.environ.get("VELO_SSH_PASSWORD")
API_CONFIG = os.environ.get("VELO_API_CONFIG", "/home/socadmin/api.config.yaml")


def _connect():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASSWORD, timeout=30, banner_timeout=60)
    return c


def vql(query):
    """Run one VQL query on the server, return the parsed JSON rows."""
    c = _connect()
    try:
        sftp = c.open_sftp()
        with sftp.open("/tmp/q.vql", "w") as f:
            f.write(query)
        sftp.close()
        cmd = (
            "echo '%s' | sudo -S -p '' sh -c 'velociraptor --api_config %s query --format json "
            '"$(cat /tmp/q.vql)"\'' % (PASSWORD, API_CONFIG)
        )
        out = c.exec_command(cmd, timeout=120)[1].read().decode(errors="replace")
        return json.loads(out[out.index("["):])
    finally:
        c.close()


def collect(client_id, artifact, env=None):
    """Launch `artifact` on `client_id`, return the flow id."""
    env_vql = ""
    if env:
        pairs = ", ".join(f"{k}='{v}'" for k, v in env.items())
        env_vql = f", env=dict({pairs})"
    rows = vql(
        f"SELECT collect_client(client_id='{client_id}', artifacts='{artifact}'{env_vql})"
        ".flow_id AS f FROM scope()"
    )
    return rows[0]["f"]


def flow_state(client_id, flow_id):
    rows = vql(f"SELECT state FROM flows(client_id='{client_id}', flow_id='{flow_id}')")
    return rows[0]["state"] if rows else None
