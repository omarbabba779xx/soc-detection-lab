"""Reverse of contain_attacker.py: remove one IP from the BLOCKED_ATTACKERS alias.

Usage:  OPN_URL=... OPN_KEY=... OPN_SECRET=... python uncontain_attacker.py <ip>
Removes exactly <ip>; every other IP the alias may hold is untouched. Not called by any
workflow — this is the manual undo, run by hand once an incident is closed.
"""
import json, sys
from opnsense_client import api, apply_filter

ALIAS = "BLOCKED_ATTACKERS"

if __name__ == "__main__":
    ip = sys.argv[1]
    removed = api("POST", f"/firewall/alias_util/delete/{ALIAS}", {"address": ip})
    apply_filter()
    print(json.dumps({"ip": ip, "alias": ALIAS, "result": removed.get("status", removed)}))
