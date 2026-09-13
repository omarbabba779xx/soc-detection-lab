# Sample Data — Threat Hunting Notebook

These JSON files back up the notebook when the SIEM (VM02-WAZUH) is not running.
`query_os()` tries the live OpenSearch instance first (5s timeout) and falls
back to the matching file here on failure — the notebook prints `[LIVE]` or
`[OFFLINE]` on every query so it's always clear which mode produced the output.

## Provenance

Each file mirrors the rule IDs, agent names, and hit counts already
documented and screenshotted elsewhere in the repo — not invented data:

| File | Mirrors |
|------|---------|
| `hunt1_powershell.json` | SC-01/SC-07 detections, rules 100120/100121/100131 |
| `hunt2_bruteforce.json` | [scenario2_wazuh_rule60122_list_15hits.png](../../../docs/screenshots/scenario2_wazuh_rule60122_list_15hits.png) — 15 hits |
| `hunt3_admin_shares.json` | [scenario4_wazuh_rule100140_3hits_overview.png](../../../docs/screenshots/scenario4_wazuh_rule100140_3hits_overview.png) — 3 hits |
| `hunt4_persistence.json` | SC-10/SC-11/SC-12 detections (rules 60642, 92004, 92302, 100153) |
| `hunt5_lsass.json` | SC-05 detection, rule 100103 |

## Restoring live mode

With VM02-WAZUH running:

```bash
export OS_PASS='<wazuh admin password>'
```

Then re-run the notebook — `query_os()` will use the live index and the
sample files are never touched.
