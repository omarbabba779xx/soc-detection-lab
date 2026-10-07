"""Small VQL client for the Velociraptor server, shared by quarantine_host.py and
unquarantine_host.py.

The server API is gRPC + mTLS (api_config.yaml, generated per API user) — no plain REST
endpoint exists for collecting artifacts. The lab's own tooling therefore reaches the
`velociraptor query` CLI over SSH, as the account `soar` on the server. That account has
no password and no shell: its SSH key is bound to a single command that reads one VQL
query on standard input and runs it with the API user `soar-api` (see
`dfir/server/soar-vql.sh` and `dfir/server/README.md`). This mirrors
`firewall/opnsense_client.py`'s role for OPNsense: one small client, reused everywhere a
script needs to talk to Velociraptor.

The server's host key is checked against a known_hosts file; an unknown or changed key
aborts the connection.

Env vars: VELO_SSH_HOST (default 127.0.0.1), VELO_SSH_PORT (default 18022),
VELO_SSH_USER (default soar), VELO_SSH_KEY_FILE (private key, kept out of the
repository), VELO_KNOWN_HOSTS (known_hosts file holding the server's host key).
"""
import json
import os

import paramiko

HOST = os.environ.get("VELO_SSH_HOST", "127.0.0.1")
PORT = int(os.environ.get("VELO_SSH_PORT", "18022"))
USER = os.environ.get("VELO_SSH_USER", "soar")
KEY_FILE = os.environ.get("VELO_SSH_KEY_FILE")
KNOWN_HOSTS = os.environ.get("VELO_KNOWN_HOSTS")


def quote(value):
    """A value as a VQL string literal."""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _connect():
    c = paramiko.SSHClient()
    c.load_host_keys(KNOWN_HOSTS)
    c.set_missing_host_key_policy(paramiko.RejectPolicy())
    c.connect(HOST, port=PORT, username=USER, key_filename=KEY_FILE, allow_agent=False,
              look_for_keys=False, timeout=30, banner_timeout=60)
    return c


def vql(query):
    """Run one VQL query on the server, return the parsed JSON rows."""
    c = _connect()
    try:
        stdin, stdout, _ = c.exec_command("vql", timeout=120)
        stdin.write(query)
        stdin.channel.shutdown_write()
        out = stdout.read().decode(errors="replace")
        return json.loads(out[out.index("["):])
    finally:
        c.close()


def collect(client_id, artifact, env=None):
    """Launch `artifact` on `client_id`, return the flow id."""
    pairs = ", ".join(f"{k}={quote(v)}" for k, v in (env or {}).items())
    rows = vql(
        f"SELECT collect_client(client_id={quote(client_id)}, artifacts={quote(artifact)}, "
        f"env=dict({pairs})).flow_id AS f FROM scope()"
    )
    return rows[0]["f"]


def flow_state(client_id, flow_id):
    rows = vql(f"SELECT state FROM flows(client_id={quote(client_id)}, flow_id={quote(flow_id)})")
    return rows[0]["state"] if rows else None


def client_os(client_id):
    rows = vql(f"SELECT os_info.system AS system FROM clients(client_id={quote(client_id)})")
    return str(rows[0]["system"]).lower() if rows else None
