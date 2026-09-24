"""Block one IP on OPNsense: automated containment for the SOAR workflow (SC-14).

Usage:  OPN_URL=... OPN_KEY=... OPN_SECRET=... python contain_attacker.py <ip> ["reason"]
Adds <ip> to the BLOCKED_ATTACKERS alias (firewall/segmentation-policy.json, rule 395 on
the purple interface) and applies the filter. Idempotent: adding an IP already in the
alias is a no-op. Reversible with uncontain_attacker.py, which removes exactly this IP
and nothing else declared in the policy.

Printed as one JSON line, so a caller (the Shuffle node) can parse the result without
scraping text.
"""
import json, sys
from opnsense_client import api, apply_filter

ALIAS = "BLOCKED_ATTACKERS"


def contain(ip):
    before = api("GET", f"/firewall/alias_util/list/{ALIAS}")
    already = ip in [row.get("ip", row) if isinstance(row, dict) else row for row in before.get("rows", [])]
    added = api("POST", f"/firewall/alias_util/add/{ALIAS}", {"address": ip})
    apply_filter()
    return {"ip": ip, "alias": ALIAS, "already_blocked": already, "result": added.get("status", added)}


if __name__ == "__main__":
    ip = sys.argv[1]
    reason = sys.argv[2] if len(sys.argv) > 2 else ""
    out = contain(ip)
    out["reason"] = reason
    print(json.dumps(out))
