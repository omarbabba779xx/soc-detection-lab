#!/usr/bin/env python3
"""Validate SocForge custom Wazuh rules XML structure and content."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RULES_FILE = Path(__file__).parent.parent / "wazuh" / "rules" / "socforge_sigma_rules.xml"
CUSTOM_ID_MIN = 100000
CUSTOM_ID_MAX = 109999
LEVEL_MIN = 0
LEVEL_MAX = 15

errors = []
warnings = []


def err(msg):
    errors.append(f"  ERROR: {msg}")


def warn(msg):
    warnings.append(f"  WARN:  {msg}")


def validate():
    # 1. XML syntax
    try:
        tree = ET.parse(RULES_FILE)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"FAIL — XML syntax error: {e}")
        sys.exit(1)

    rules = root.findall(".//rule")
    if not rules:
        print("FAIL — no <rule> elements found")
        sys.exit(1)

    seen_ids = {}

    for rule in rules:
        # 2. Required attribute: id
        rule_id_str = rule.get("id")
        if rule_id_str is None:
            err("rule missing 'id' attribute")
            continue

        if not rule_id_str.isdigit():
            err(f"rule id '{rule_id_str}' is not an integer")
            continue

        rule_id = int(rule_id_str)

        # 3. Duplicate IDs
        if rule_id in seen_ids:
            err(f"duplicate rule id {rule_id}")
        seen_ids[rule_id] = True

        # 4. ID in custom range
        if not (CUSTOM_ID_MIN <= rule_id <= CUSTOM_ID_MAX):
            warn(f"rule {rule_id} outside custom range {CUSTOM_ID_MIN}–{CUSTOM_ID_MAX}")

        # 5. Required attribute: level
        level_str = rule.get("level")
        if level_str is None:
            err(f"rule {rule_id} missing 'level' attribute")
        elif not level_str.isdigit() or not (LEVEL_MIN <= int(level_str) <= LEVEL_MAX):
            err(f"rule {rule_id} has invalid level '{level_str}' (must be {LEVEL_MIN}–{LEVEL_MAX})")

        # 6. Required child: description
        desc = rule.find("description")
        if desc is None or not (desc.text or "").strip():
            err(f"rule {rule_id} missing or empty <description>")

        # 7. MITRE tag if group mentions mitre_
        group_el = rule.find("group")
        if group_el is not None and "mitre_" in (group_el.text or ""):
            if rule.find("mitre") is None:
                warn(f"rule {rule_id} has mitre_ group but no <mitre> block")

    # Report
    print(f"\nSocForge Wazuh Rules Validator")
    print(f"File   : {RULES_FILE}")
    print(f"Rules  : {len(rules)} found\n")

    if warnings:
        for w in warnings:
            print(w)

    if errors:
        for e in errors:
            print(e)
        print(f"\nFAIL — {len(errors)} error(s) found")
        sys.exit(1)
    else:
        print(f"PASS — all {len(rules)} rules valid")
        if warnings:
            print(f"       {len(warnings)} warning(s) — review above")


if __name__ == "__main__":
    validate()
