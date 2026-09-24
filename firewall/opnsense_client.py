"""Small REST client for the OPNsense 24.7 API, shared by apply_policy.py and
contain_attacker.py / uncontain_attacker.py.

Env vars: OPN_URL (default https://10.10.10.1), OPN_KEY, OPN_SECRET (System > Access >
Users > root > API keys, never stored here), OPN_CA (default pki/socforge-lab-ca.crt),
OPN_TLS_NAME (set to 10.10.10.1 when OPN_URL is a port-forwarded 127.0.0.1 address, so the
certificate is checked against the firewall's own name instead of the forwarded one).
"""
import os, pathlib, requests
from requests.adapters import HTTPAdapter

HERE = pathlib.Path(__file__).resolve().parent
BASE = os.environ.get("OPN_URL", "https://10.10.10.1").rstrip("/") + "/api"
AUTH = (os.environ["OPN_KEY"], os.environ["OPN_SECRET"])
CA = os.environ.get("OPN_CA", str(HERE.parent / "pki" / "socforge-lab-ca.crt"))


class ExpectedName(HTTPAdapter):
    """Verify the server certificate against a fixed name (SNI and hostname check)."""

    def __init__(self, name):
        self.name = name
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs.update(server_hostname=self.name, assert_hostname=self.name)
        super().init_poolmanager(*args, **kwargs)


SESSION = requests.Session()
SESSION.verify = CA
if os.environ.get("OPN_TLS_NAME"):
    SESSION.mount("https://", ExpectedName(os.environ["OPN_TLS_NAME"]))


def form(body, prefix=""):
    """Flatten {"rule": {"a": "1"}} into {"rule[a]": "1"}. On this appliance a JSON body
    is ignored by the MVC controllers (every add/set returns "failed" with no validation
    message); the same payload sent as a form is accepted."""
    out = {}
    for k, v in body.items():
        key = f"{prefix}[{k}]" if prefix else k
        if isinstance(v, dict):
            out.update(form(v, key))
        else:
            out[key] = v
    return out


def api(method, path, body=None):
    r = SESSION.request(method, BASE + path, auth=AUTH, data=form(body) if body else None,
                        timeout=60)
    r.raise_for_status()
    out = r.json()
    if isinstance(out, dict) and out.get("result") == "failed":
        raise RuntimeError(f"{path}: {out}")
    return out


def existing(path, key):
    return {row[key]: row["uuid"] for row in api("GET", path)["rows"]}


def apply_filter():
    api("POST", "/firewall/alias/reconfigure")
    return api("POST", "/firewall/filter/apply")
