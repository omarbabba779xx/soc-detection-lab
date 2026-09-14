#!/usr/bin/env python3
"""Validate SocForge custom Wazuh rules XML structure and content."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RULES_DIR = Path(__file__).parent.parent / "wazuh" / "rules"
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
    rules_files = sorted(RULES_DIR.glob("*.xml"))
    if not rules_files:
        print(f"FAIL — no XML files found in {RULES_DIR}")
        sys.exit(1)

    seen_ids = {}
    total_rules = 0

    for rules_file in rules_files:
        try:
            tree = ET.parse(rules_file)
            root = tree.getroot()
        except ET.ParseError as e:
            err(f"{rules_file.name}: XML syntax error: {e}")
            continue

        rules = root.findall(".//rule")
        if not rules:
            warn(f"{rules_file.name}: no <rule> elements found")
            continue

        total_rules += len(rules)

        for rule in rules:
            # Required attribute: id
            rule_id_str = rule.get("id")
            if rule_id_str is None:
                err(f"{rules_file.name}: rule missing 'id' attribute")
                continue

            if not rule_id_str.isdigit():
                err(f"{rules_file.name}: rule id '{rule_id_str}' is not an integer")
                continue

            rule_id = int(rule_id_str)

            # Duplicate IDs (across all files, not just within one)
            if rule_id in seen_ids:
                err(f"duplicate rule id {rule_id} in {rules_file.name} (already defined in {seen_ids[rule_id]})")
            seen_ids[rule_id] = rules_file.name

            # ID in custom range
            if not (CUSTOM_ID_MIN <= rule_id <= CUSTOM_ID_MAX):
                warn(f"{rules_file.name}: rule {rule_id} outside custom range {CUSTOM_ID_MIN}–{CUSTOM_ID_MAX}")

            # Required attribute: level
            level_str = rule.get("level")
            if level_str is None:
                err(f"{rules_file.name}: rule {rule_id} missing 'level' attribute")
            elif not level_str.isdigit() or not (LEVEL_MIN <= int(level_str) <= LEVEL_MAX):
                err(f"{rules_file.name}: rule {rule_id} has invalid level '{level_str}' (must be {LEVEL_MIN}–{LEVEL_MAX})")

            # Required child: description
            desc = rule.find("description")
            if desc is None or not (desc.text or "").strip():
                err(f"{rules_file.name}: rule {rule_id} missing or empty <description>")

            # MITRE tag if group mentions mitre_
            group_el = rule.find("group")
            if group_el is not None and "mitre_" in (group_el.text or ""):
                if rule.find("mitre") is None:
                    warn(f"{rules_file.name}: rule {rule_id} has mitre_ group but no <mitre> block")

    # Report
    print(f"\nSocForge Wazuh Rules Validator")
    print(f"Files  : {', '.join(f.name for f in rules_files)}")
    print(f"Rules  : {total_rules} found\n")

    if warnings:
        for w in warnings:
            print(w)

    if errors:
        for e in errors:
            print(e)
        print(f"\nFAIL — {len(errors)} error(s) found")
        sys.exit(1)
    else:
        print(f"PASS — all {total_rules} rules valid")
        if warnings:
            print(f"       {len(warnings)} warning(s) — review above")


if __name__ == "__main__":
    validate()
