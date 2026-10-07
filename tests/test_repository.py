"""Static checks on what the repository ships: rules, policy, artifacts, SOAR nodes, docs.

None of these tests needs the lab. They catch what breaks silently at deploy time: a rule
file Wazuh refuses to load, a zone left without its default deny, a node that no longer
compiles once its placeholders are filled, a dead link in the documentation.
"""
import ipaddress
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "soar"), str(ROOT / "firewall"), str(ROOT / "dfir")]

RULE_FILES = sorted((ROOT / "wazuh" / "rules").glob("socforge_*.xml"))
ARTIFACTS = sorted((ROOT / "velociraptor" / "artifacts").glob("*.yaml"))
MARKDOWN = [p for p in ROOT.rglob("*.md") if not {"secrets", "tmp", ".git"} & set(p.parts)]


def rules():
    for path in RULE_FILES:
        root = ET.fromstring("<root>" + path.read_text(encoding="utf-8") + "</root>")
        for rule in root.iter("rule"):
            yield path.name, rule


# --- Wazuh rules -----------------------------------------------------------------------

@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_rule_file_is_well_formed(path):
    ET.fromstring("<root>" + path.read_text(encoding="utf-8") + "</root>")


def test_rule_ids_are_unique_and_in_the_custom_range():
    ids = [int(rule.get("id")) for _, rule in rules()]
    assert len(ids) == len(set(ids))
    assert all(100000 <= i <= 120000 for i in ids)


def test_every_rule_has_a_description_and_a_level():
    for name, rule in rules():
        assert rule.findtext("description"), (name, rule.get("id"))
        assert 0 <= int(rule.get("level")) <= 15


def test_alerting_rules_carry_a_mitre_technique():
    for name, rule in rules():
        if int(rule.get("level")) >= 8:
            ids = [i.text for i in rule.iter("id")]
            assert ids and all(re.fullmatch(r"T\d{4}(\.\d{3})?", i) for i in ids), (name, rule.get("id"))


def test_frequency_rules_group_on_a_source():
    """A rule that counts events must say what it counts them per (the defect 100102 had)."""
    for name, rule in rules():
        if rule.get("frequency"):
            grouped = rule.find("same_field") is not None or rule.find("same_source_ip") is not None
            assert grouped, (name, rule.get("id"))


# --- Firewall policy -------------------------------------------------------------------

@pytest.fixture(scope="module")
def policy():
    return json.loads((ROOT / "firewall" / "segmentation-policy.json").read_text(encoding="utf-8"))


def test_every_zone_ends_with_a_logged_default_deny(policy):
    for zone in ("opt1", "opt2", "opt3", "opt4", "opt5"):
        zone_rules = sorted((r for r in policy["rules"] if r["if"] == zone), key=lambda r: r["seq"])
        last = zone_rules[-1]
        assert (last["action"], last["dst"], last["log"]) == ("block", "any", 1), zone


def test_containment_block_comes_first_in_every_zone(policy):
    for zone in ("opt1", "opt2", "opt3", "opt4", "opt5"):
        first = min((r for r in policy["rules"] if r["if"] == zone), key=lambda r: r["seq"])
        assert first["action"] == "block" and first.get("src") == "BLOCKED_ATTACKERS", zone


def test_rule_sequences_and_descriptions_are_unique(policy):
    seqs = [r["seq"] for r in policy["rules"]]
    descs = [r["desc"] for r in policy["rules"]]
    assert len(seqs) == len(set(seqs)) and len(descs) == len(set(descs))


def test_aliases_used_by_rules_exist(policy):
    names = {a["name"] for a in policy["aliases"]}
    for r in policy["rules"]:
        for value in (r.get("port"), r.get("src")):
            if value and re.fullmatch(r"[A-Z_]+", value):
                assert value in names, r["desc"]


def test_opnsense_form_flattening(monkeypatch):
    monkeypatch.setenv("OPN_KEY", "k")
    monkeypatch.setenv("OPN_SECRET", "s")
    import opnsense_client
    assert opnsense_client.form({"rule": {"a": "1", "b": {"c": "2"}}, "x": "3"}) == {
        "rule[a]": "1", "rule[b][c]": "2", "x": "3"}


# --- Velociraptor ----------------------------------------------------------------------

@pytest.mark.parametrize("path", ARTIFACTS, ids=lambda p: p.name)
def test_artifact_loads_and_is_named_after_its_file(path):
    artifact = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert artifact["name"] == path.stem
    assert artifact.get("type", "CLIENT") in {"CLIENT", "SERVER", "SERVER_EVENT"}
    assert artifact["sources"] and all(s.get("query") for s in artifact["sources"])


def test_vql_quoting_cannot_be_broken_out_of():
    import velociraptor_client
    assert velociraptor_client.quote("C.123") == "'C.123'"
    assert velociraptor_client.quote("a'b\\c") == "'a\\'b\\\\c'"


# --- SOAR nodes ------------------------------------------------------------------------

@pytest.fixture(scope="module")
def workflow():
    import create_wazuh_webhook_workflow
    return create_wazuh_webhook_workflow


def test_every_node_compiles_with_no_placeholder_left(workflow):
    for label, _, fn, params, _, _ in workflow.CHAIN + workflow.HOUSEKEEPING:
        if fn == "execute_python":
            compile(params["code"], label, "exec")
            assert not re.search(r"__[A-Z_]{3,}__", params["code"]), label


def test_chains_are_linear(workflow):
    for chain in (workflow.CHAIN, workflow.HOUSEKEEPING):
        labels = [c[0] for c in chain]
        assert [c[5] for c in chain] == [None] + labels[:-1]


def test_ensure_chain_leaves_one_branch_per_node(workflow):
    wf = {"actions": [], "branches": []}
    workflow.ensure_chain(wf, hook_id="hook")
    workflow.ensure_chain(wf, hook_id="hook")
    destinations = [b["destination_id"] for b in wf["branches"]]
    assert len(destinations) == len(set(destinations)) == len(workflow.CHAIN)


def test_never_block_list_covers_the_soc_and_the_domain_controller(workflow):
    nets = [ipaddress.ip_network(n) for n in workflow.NEVER_BLOCK.split(",")]
    for protected in ("10.10.10.10", "10.10.10.20", "10.10.20.10", "10.10.30.1"):
        assert any(ipaddress.ip_address(protected) in n for n in nets), protected
    assert not any(ipaddress.ip_address("10.10.50.10") in n for n in nets)


def build_alert(workflow, capsys, wazuh_alert):
    """Run Build_TheHive_Alert the way Shuffle does: the webhook body replaces $exec."""
    body = json.dumps({"all_fields": wazuh_alert})
    exec(workflow.BUILD_ALERT.replace("$exec", body), {})
    return json.loads(capsys.readouterr().out)


def test_build_alert_on_an_admin_share_escalation(workflow, capsys):
    alert = build_alert(workflow, capsys, {
        "id": "1791367342.4269077", "timestamp": "2026-10-07T10:02:22.000+0000",
        "rule": {"id": "100141", "level": 12, "description": "Repeated admin-share access",
                 "mitre": {"id": ["T1021.002"]}},
        "agent": {"name": "WIN01"},
        "data": {"win": {"system": {"computer": "DESKTOP-75LAKDV.socforge.lab"},
                         "eventdata": {"ipAddress": "10.10.50.10", "subjectUserName": "labuser"}}}})
    assert alert["severity"] == 3
    assert alert["sourceRef"] == "1791367342.4269077"
    assert {"wazuh", "rule-100141", "T1021.002"} <= set(alert["tags"])
    observables = {(o["dataType"], o["data"]) for o in alert["observables"]}
    assert {("ip", "10.10.50.10"), ("hostname", "WIN01"),
            ("hostname", "DESKTOP-75LAKDV.socforge.lab")} <= observables


def test_build_alert_below_the_containment_threshold(workflow, capsys):
    alert = build_alert(workflow, capsys, {
        "id": "1", "rule": {"id": "100210", "level": 10, "description": "Cron job file modified"},
        "agent": {"name": "linux01"},
        "syscheck": {"path": "/etc/cron.d/backup", "event": "added", "sha256_after": "ab" * 32}})
    assert alert["severity"] == 2
    observables = {(o["dataType"], o["data"]) for o in alert["observables"]}
    assert ("filename", "/etc/cron.d/backup") in observables and ("hash", "ab" * 32) in observables
    assert not any(t == "ip" for t, _ in observables)


def test_build_alert_keeps_hostile_text_as_data(workflow, capsys):
    """Quotes, backslashes and newlines in an event field stay inside the JSON string."""
    hostile = 'x" + __import__("os").system("id") + "\\\n\'\'\''
    alert = build_alert(workflow, capsys, {
        "id": "2", "rule": {"id": "100121", "level": 12, "description": hostile},
        "agent": {"name": "WIN01"},
        "data": {"win": {"eventdata": {"commandLine": hostile}}}})
    assert alert["title"] == hostile
    assert ("other", hostile.strip()) in {(o["dataType"], o["data"]) for o in alert["observables"]}


# --- Documentation ---------------------------------------------------------------------

@pytest.mark.parametrize("path", MARKDOWN, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(path):
    text = path.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text) + re.findall(r'src="([^"]+)"', text):
        if re.match(r"[a-z]+://|mailto:", target):
            continue
        assert (path.parent / target).exists(), f"{path.name}: {target}"


def test_no_screenshot_is_orphaned():
    referenced = "\n".join(p.read_text(encoding="utf-8") for p in MARKDOWN)
    for image in (ROOT / "docs" / "screenshots").glob("*.png"):
        assert image.name in referenced, image.name
