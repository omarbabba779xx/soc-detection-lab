"""Replay one Wazuh alert into the Shuffle webhook, exactly as Wazuh's native `shuffle`
integration (/var/ossec/integrations/shuffle.py) would have sent it.

Usage:  SHUFFLE_WEBHOOK=http://<shuffle>:3001/api/v1/hooks/webhook_<id> python replay_alert.py <alert.json>

<alert.json> is one line of /var/ossec/logs/alerts/alerts.json. The webhook URL stays in the
environment, out of the repository: its id is the shared secret between Wazuh and Shuffle.

Why this exists: the SOAR chain needs SHUFFLE, THEHIVE, CORTEX, MISP, FW and DFIR-HUNT up at
once, and the attack needs WAZUH, WIN01, PURPLE and FW. On a 16 GB host these two groups
cannot run together. The attack runs first; the alert Wazuh raised for it is then delivered to
Shuffle afterwards, byte for byte what the integration would have posted (same keys, same
severity mapping), so that the chain runs as one real execution on the real alert. Only the
delivery is deferred: the Wazuh -> Shuffle webhook itself is proven live in SC-14.
"""
import json
import os
import sys

import requests


def message(alert):
    """Same object as generate_msg() in Wazuh's shuffle.py."""
    level = alert["rule"]["level"]
    severity = 1 if level <= 4 else 2 if level <= 7 else 3
    return {
        "severity": severity,
        "pretext": "WAZUH Alert",
        "title": alert["rule"].get("description", "N/A"),
        "text": alert.get("full_log"),
        "rule_id": alert["rule"]["id"],
        "timestamp": alert["timestamp"],
        "id": alert["id"],
        "all_fields": alert,
    }


if __name__ == "__main__":
    alert = json.loads(open(sys.argv[1], encoding="utf-8").read().strip().splitlines()[-1])
    msg = message(alert)
    r = requests.post(os.environ["SHUFFLE_WEBHOOK"], data=json.dumps(msg),
                      headers={"content-type": "application/json", "Accept-Charset": "UTF-8"}, timeout=30)
    print(json.dumps({"alert_id": alert["id"], "rule": alert["rule"]["id"], "level": alert["rule"]["level"],
                      "http": r.status_code, "response": r.text[:300]}))
    sys.exit(0 if r.ok else 1)
