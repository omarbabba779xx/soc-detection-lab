<p align="center"><img src="docs/banner.png" alt="SocForge, end-to-end SOC lab"></p>

# SocForge

A complete SOC lab on a single PC, built with VirtualBox: twelve virtual machines, from detection through to
response. Every detection was triggered by a real, benign offensive action, launched from a Kali machine or, for
local techniques, on the targeted host, then observed in the SIEM and documented with its logs, UTC timestamps
and screenshots.

The project follows an incident all the way through: one attack is tracked across the whole chain (detection,
orchestration, enrichment, network blocking, host isolation, hunting, case closure). The details are in
scenario sheet [SC-14](purple-team/scenarios/SC-14-shuffle-soar-workflow.md).

A few numbers: 12 machines, 16 scenario sheets, 29 detection rules written for the lab, 5 filtered network
zones, a 6-node automation chain and 47 screenshots. On the tracked attack, Wazuh alerts within 1 to 7 seconds,
the alert reaches TheHive 7 seconds after its delivery, the attacker's address is blocked at 24 seconds, the host
isolation order goes out at 29 seconds and the hunt is requested at 35 seconds
([metrics](docs/metrics-mttd-mtta-mttr.md)).

This README tells the project in the order it was built, step by step, with the 47 screenshots taken on the lab.
On each screenshot, the red frames show what to look at: the query, the number of results, the line or the value
that proves the point. The scenario sheets then give the exact command, the logs and the clean-up.

| Step | Content | Screenshots |
|---|---|---|
| 1 | Collect the logs and see them in Wazuh | 1 |
| 2 | Detect techniques on Windows and Linux | 12 |
| 3 | Monitor and segment the network | 6 |
| 4 | Automate the response: Shuffle, TheHive, Cortex, MISP | 8 |
| 5 | Hunt on endpoints from threat intelligence | 12 |
| 6 | One attack followed end to end | 8 |

The dashboards display the lab's local time (UTC+1). The sheets and the logs are in UTC.

The scenario sheets and the other documents linked from this page are written in French. A French version of
this README is available in [`README.fr.md`](README.fr.md).

Three things to know when reading the screenshots:

- They come from two periods. Those of steps 1 to 5 were taken between 17 and 25 September 2026, while the lab was being built: they are separate tests, one per technique or per component. Those of step 6 all come from the attack of 7 October 2026. The only exception in steps 1 to 5: the two screenshots of the Linux hunt, at the end of step 5, also taken on 7 October.
- The addresses changed between the two. In September, Kali and the targets still had an interface on the management network: Kali appears as `10.10.10.60`, DC01 as `10.10.10.109`, WIN01 as `10.10.10.110`. Those interfaces were then removed so that the attacker and the targets can only communicate through the firewall. On 7 October, PURPLE is `10.10.50.10` and WIN01 is `10.10.30.110`.
- WIN01 has two names depending on the tool: `WIN01` is the name of its Wazuh agent, `DESKTOP-75LAKDV` is its Windows hostname, the one Velociraptor and TheHive display. It is the same machine.

## Architecture

![Lab architecture](docs/architecture.png)

| Layer | Components | Role |
|---|---|---|
| Attack | PURPLE (Kali Linux) | launches the attacks, alone in its zone |
| Network | OPNsense, NDR sensor (Suricata and Zeek) | default-deny segmentation, passive network detection |
| Administration | management network `10.10.10.0/24` | hosts the tools (Wazuh, Shuffle, TheHive…). It is not filtered: neither the attacker nor the targets have an interface on it |
| Targets | DC01, WIN01, LINUX01 | Windows domain, Windows 11 workstation with Sysmon, Ubuntu server; each has a Wazuh agent |
| Detection | Wazuh | receives the agents, the firewall syslog and the network alerts |
| Response | Shuffle, TheHive, Cortex, MISP | orchestration, incident tracking, analysis, threat intelligence |
| DFIR | Velociraptor | endpoint hunting, isolation of a compromised host |

The full inventory (addresses, versions, flows) is in [`docs/lab-registry.md`](docs/lab-registry.md). An incident
report written from a real alert is in
[`docs/incident-report-2026-09-24-cron-persistence.md`](docs/incident-report-2026-09-24-cron-persistence.md).

## Step 1: collect and see

The three targets (DC01, WIN01, LINUX01) and the network sensor each run a Wazuh agent. On Windows, the agent
sends the Security, PowerShell and Sysmon logs; on Linux, the authentication logs and real-time integrity
monitoring of `/etc/cron.d`. The firewall sends its log over syslog. Before writing a single rule, all of this had
to be confirmed as reaching the manager.

The Threat Hunting dashboard shows it after one day of tests: 3,956 alerts in 24 hours, 172 of them at level 12
or above, and a MITRE ATT&CK breakdown that matches the techniques executed (valid accounts, process injection,
PowerShell, scheduled task, LSASS memory, admin shares).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-threat-hunting-overview.png" alt="Wazuh Threat Hunting dashboard"></p>

## Step 2: detect techniques on the hosts

Every technique follows the same method: run a real, benign action, check whether the rule fires, fix the rule if
it does not, then keep the evidence. The 29 lab rules are in `wazuh/rules/`, and the defects found while testing
them are described in the [Windows detection sheet](detections/windows/detection-sheet-windows.md) and the
[Linux sheet](detections/linux/detection-sheet-linux.md).

### Scheduled task and privileged account (SC-01, SC-02)

On DC01, a scheduled task is created with `schtasks`, then the `C$` share is mounted with the administrator
account. The console shows both commands and their result.

<p align="center"><img src="docs/screenshots/rule-100153-100178-live-rebuild.png" alt="Commands run on DC01"></p>

In Wazuh, the query on the two rules returns 11 alerts: `100153` for the task creation (event 4698) and `100178`
for the network logon of the privileged account (event 4624, type 3).
Sheets: [SC-01](purple-team/scenarios/SC-01-T1053-scheduled-task.md),
[SC-02](purple-team/scenarios/SC-02-T1078-valid-account.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-dc01-events.png" alt="Alerts 100153 and 100178 on DC01"></p>

### Admin shares: separating noise from signal (SC-03)

A domain controller constantly accesses its own shares with machine accounts. Alerting on every access to `C$` or
`ADMIN$` would drown the analyst. Rule `100139` therefore classifies those routine accesses at level 3, without an
alert, and rule `100140` only keeps accesses made by a real account, at level 10. The screenshot shows both side
by side, along with rule `100186`, which flags the modification of a PowerShell profile on WIN01.
Sheet: [SC-03](purple-team/scenarios/SC-03-T1021-lateral-movement.md).

<p align="center"><img src="docs/screenshots/wazuh-rules-100139-100140-100186-live.png" alt="Rules 100139, 100140 and 100186"></p>

### Encoded PowerShell (SC-04)

On WIN01, a PowerShell command is run with `-EncodedCommand`. Two sources see it: the process creation (event
4688, rule `100121`) and the content of the script once Windows has decoded it (event 4104, rule `100131`). The
manager's alert log shows both, at level 12, ten seconds apart.

<p align="center"><img src="docs/screenshots/rule-100121-100131-powershell-live.png" alt="Alerts 100121 and 100131 in the manager log"></p>

The dashboard groups all the PowerShell activity of the day on WIN01: 26 alerts, led by the two level 12 rules,
followed by PowerShell process creation (`100120`) and Base64 patterns (`100127`).
Sheet: [SC-04](purple-team/scenarios/SC-04-T1059-powershell-encoded.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-win01-powershell-events.png" alt="PowerShell alerts on WIN01"></p>

### Port scan from Kali (SC-05)

PURPLE scans DC01 with `nmap`. Each connection to a sensitive port raises rule `100101` (level 8). When the same
source touches several ports in a short time, correlation rule `100102` goes up to level 10: it is the one that
says "scan" rather than "isolated connection". 60 alerts across the four rules of the query.
Sheet: [SC-05](purple-team/scenarios/SC-05-T1046-port-scan.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-dc01-scan-events.png" alt="Port scan detected on DC01"></p>

### SMB brute force (SC-06)

Still from PURPLE, a series of password attempts against the administrator account of DC01. Each failure gives a
level 6 alert `100110`; the repetition triggers `100111` at level 10. 13 alerts in total.
Sheet: [SC-06](purple-team/scenarios/SC-06-T1110-brute-force.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-dc01-bruteforce-events.png" alt="Brute force detected on DC01"></p>

### sudo and cron persistence on Linux (SC-07)

On LINUX01, commands run with `sudo` raise rule `100200` (level 9), and dropping a file into `/etc/cron.d` raises
rule `100210` (level 10) thanks to real-time integrity monitoring. 19 alerts.
Sheet: [SC-07](purple-team/scenarios/SC-07-T1548-T1053-linux.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-linux01-events.png" alt="sudo and cron alerts on LINUX01"></p>

### Lateral movement from WIN01 to DC01 (SC-08)

From WIN01, the admin share of DC01 is mounted with a domain account. Two rules complement each other on DC01:
`100178` sees the session of the privileged account, `100140` sees the access to the share. The test was run twice
that day, hence the 6 alerts.
Sheet: [SC-08](purple-team/scenarios/SC-08-T1021-win01-to-dc01.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-lateral-movement-win01-dc01.png" alt="Lateral movement from WIN01 to DC01"></p>

### Run key persistence (SC-09)

A value is written under the `CurrentVersion\Run` key of WIN01. Sysmon logs the write (event 13) and rule `100147`
alerts at level 9. This is the rule that took the most investigation: it did not fire while it was chained with
`if_group`, and has fired since it was chained with `if_sid`.
Sheet: [SC-09](purple-team/scenarios/SC-09-T1547-registry-run-key.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-rule-100147-live.png" alt="Rule 100147 on WIN01"></p>

### Process injection (SC-10)

A script creates a thread in a local `notepad.exe` with `CreateRemoteThread`, without writing any code into it.
Sysmon produces event 8 and rule `100155` alerts at level 13. The 17 results for a single test showed how noisy
the rule was. The noise was analysed on 7 October: 16 of the 18 alerts kept by the manager were the Ctrl+C signal
that Windows sends to console programs. Rule `100156` classifies that case at level 3, without an alert, and the
chaining of rule `100155` was corrected at the same time.
Sheet: [SC-10](purple-team/scenarios/SC-10-T1055-process-injection.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-rule-100155-live.png" alt="Rule 100155 on WIN01"></p>

### Access to LSASS memory (SC-11)

On WIN01, Windows LSA protection refuses the opening of `lsass.exe` before Sysmon even sees it: the defence works
and there is nothing to detect. On DC01, where that protection is not enabled, access is granted and rule `100103`
alerts at level 14, two seconds after the attempt. The screenshot shows the source process (`powershell.exe`) and
the access mask `0x1010`.
Sheet: [SC-11](purple-team/scenarios/SC-11-T1003-lsass-access.md).

<p align="center"><img src="docs/screenshots/wazuh-dashboard-rule-100103-live.png" alt="Rule 100103 on DC01"></p>

## Step 3: monitor and segment the network

### The network sensor (SC-12)

A dedicated machine listens to mirrored traffic with Suricata (52,795 ET Open signatures) and Zeek. Its alerts
reach Wazuh through an agent. During a scan launched from Kali, Suricata recognises the probes to database ports,
SSH and `nmap` OS detection. Rule `100400` turns them into level 10 alerts, where the raw Suricata alert (`86601`)
stays at level 3.

<p align="center"><img src="docs/screenshots/wazuh-ndr-suricata-scan.png" alt="Scan detected by Suricata and reported in Wazuh"></p>

The sensor also listens to the attacker zone. Here, interface `enp0s10` captures a ping from PURPLE
(`10.10.50.10`) to the manager: traffic from that zone is seen by the sensor.
Sheet: [SC-12](purple-team/scenarios/SC-12-ndr-purple-scan.md).

<p align="center"><img src="docs/screenshots/wazuh-ndr-purple-tap-alerts.png" alt="Attacker zone traffic captured by the sensor"></p>

### Segmentation (SC-16)

OPNsense separates five zones with a default deny. The policy fits in 17 rules, described in
`firewall/segmentation-policy.json` and applied through the API. Two groups matter here: PURPLE is only allowed to
reach the test targets, and five containment rules, one per zone, reject any address placed in the
`BLOCKED_ATTACKERS` alias. Those are the ones the automated response uses in step 6.

<p align="center"><img src="docs/screenshots/opnsense-segmentation-policy.png" alt="The 17 segmentation rules in OPNsense"></p>

The firewall log reaches Wazuh. When PURPLE scans the other zones, each rejected packet gives a `100301` alert
(level 8), and the repetition triggers `100302` at level 12: a scan across zones.

<p align="center"><img src="docs/screenshots/wazuh-opnsense-segmentation-blocks.png" alt="Firewall blocks seen in Wazuh"></p>

Same result when PURPLE tries to reach the Wazuh manager on the agent port: eight alerts, all with the `block`
action. The attacker cannot reach the SOC tools.
Sheet: [SC-16](purple-team/scenarios/SC-16-firewall-segmentation.md).

<p align="center"><img src="docs/screenshots/wazuh-purple-to-mgmt-blocked.png" alt="PURPLE attempts to the management network blocked"></p>

The containment mechanism was first tested on its own, with a documentation address: the script
`firewall/contain_attacker.py` adds it to the alias, the OPNsense interface shows it, then
`uncontain_attacker.py` removes it.

<p align="center"><img src="docs/screenshots/opnsense-blocked-attackers-alias.png" alt="Test address in the BLOCKED_ATTACKERS alias"></p>

## Step 4: automate the response

### First alert in TheHive (SC-13)

The integration started by hand: an alert created in TheHive through the API, with the service account, from
Wazuh alert `100155`. It carries the technique, the source and the rule reference. This test set the format that
Shuffle reuses.
Sheet: [SC-13](purple-team/scenarios/SC-13-thehive-cortex-100155.md).

<p align="center"><img src="docs/screenshots/thehive-alert-rule100155.png" alt="First TheHive alert created from a Wazuh alert"></p>

### From Wazuh to TheHive without intervention (SC-14)

The Wazuh manager then sends every alert of level 10 or above to Shuffle by itself. To tune the chain, the trigger
used in these trials is a test cron file dropped on the Wazuh server itself: that is why the agent is called
`wazuh` in the screenshots of this step. The rule is the same one validated on LINUX01 in step 2. The execution
below was triggered that way: source `webhook`, rule `100210`, fifteen seconds end to end, and TheHive answers
`201` to the creation of the alert.

<p align="center"><img src="docs/screenshots/shuffle-wazuh-webhook-execution.png" alt="Shuffle execution triggered by Wazuh"></p>

The alert reaches TheHive with its tags and, as its reference, the identifier of the original Wazuh alert. It is
always possible to go back from TheHive to the raw log.

<p align="center"><img src="docs/screenshots/thehive-alerts-from-wazuh-webhook.png" alt="Alert delivered to TheHive through the webhook"></p>

### Enrichment with Cortex and MISP

A second workflow reads the observables of the alert, extracts the address and submits it to the Cortex analyzer
`MISP_SocForge`, which queries MISP. The screenshot shows the address extracted during the execution and the `200`
answer from Cortex, meaning the analysis was started. The result of the analysis can be read two screenshots
further down, on the observable in TheHive.

<p align="center"><img src="docs/screenshots/shuffle-dynamic-trigger-misp-match.png" alt="Enrichment workflow in Shuffle"></p>

Alerts then carry their observables from creation. Case #9, opened from an alert created by the `SOAR Bot`
account, holds three: the hostname, the SHA-256 hash of the file and its path.

<p align="center"><img src="docs/screenshots/thehive-case9-wazuh-alert-observables.png" alt="Case 9 and its three observables"></p>

When an observable is known to MISP, the Cortex report says so on the observable itself. Here the cron file
matches a MISP event (`MISP:Search="1 event(s)"`), while the hash matches none.

<p align="center"><img src="docs/screenshots/thehive-alert-soar-chain-cortex-misp.png" alt="Cortex report with a MISP match"></p>

### The chain grows: hunt requested, case handled

A MISP match triggers the next stage: Shuffle republishes the MISP event concerned, which starts a Velociraptor
hunt (step 5). The alert receives the tags `misp:match` and `dfir:hunt-triggered`, and a dated note written by the
node itself. Everything the chain does can be read on the alert.

<p align="center"><img src="docs/screenshots/thehive-alert-dfir-hunt-triggered.png" alt="TheHive alert after the hunt was triggered"></p>

The alert is then turned into a case and handled with a five-task incident response template: triage,
containment, eradication, recovery, lessons learned. Case #10 is closed as a true positive. The corresponding
incident report is in
[`docs/incident-report-2026-09-24-cron-persistence.md`](docs/incident-report-2026-09-24-cron-persistence.md).
Sheet: [SC-14](purple-team/scenarios/SC-14-shuffle-soar-workflow.md).

<p align="center"><img src="docs/screenshots/thehive-case10-ir-playbook-closed.png" alt="Case 10 closed with its five tasks"></p>

## Step 5: hunt on endpoints from threat intelligence

The idea of this step: an indicator published in MISP should be enough to start a search on the endpoints, and
the result should come back to MISP. Sheet: [SC-15](purple-team/scenarios/SC-15-dfir-velociraptor-misp-hunt.md).

### A first hunt by hand

Velociraptor searches the PowerShell logs of WIN01 for the Base64 string used in SC-04. The collection finishes
in 8 seconds and finds 3 events.

<p align="center"><img src="docs/screenshots/velociraptor-hunt-win01-flow-completed.png" alt="First Velociraptor hunt on WIN01"></p>

The detailed results show the 4104 events with the full script block: the analyst reads the command as it was
executed, five days after the fact.

<p align="center"><img src="docs/screenshots/velociraptor-hunt-win01-4104-results.png" alt="4104 events found by the hunt"></p>

### The indicators go through MISP

The indicators of the previous scenarios are grouped in MISP event #2: the name of the scheduled task, the Kali
address, the cron file, the Run key and the Base64 string.

<p align="center"><img src="docs/screenshots/misp-event2-campaign-iocs.png" alt="MISP event 2 and its five indicators"></p>

The hunt is run again with an expression built from those indicators. This time it finds 11 events on WIN01.

<p align="center"><img src="docs/screenshots/velociraptor-hunt-misp-iocs-11-hits.png" alt="Hunt with the MISP indicators, 11 results"></p>

From those results, a notebook rebuilds the timeline of the SC-09 Run key: the `reg add` command, the write seen
by Sysmon, then the deletion. The key no longer existed on the host when the hunt ran; its traces did.

<p align="center"><img src="docs/screenshots/velociraptor-sc09-runkey-timeline.png" alt="Rebuilt timeline of the Run key"></p>

### Velociraptor reads MISP and answers it

A server artifact written for the lab (`velociraptor/`) reads the MISP event and creates the hunt itself, with
the tags `misp` and `misp-event-2` and the expression derived from the indicators.

<p align="center"><img src="docs/screenshots/velociraptor-misp-native-hunt-created.png" alt="Hunt created by the server artifact"></p>

A second artifact watches for the end of hunts and sends MISP one sighting per indicator found. MISP answers `200`
to each one.

<p align="center"><img src="docs/screenshots/velociraptor-misp-sightings-monitor.png" alt="Sightings sent to MISP"></p>

In MISP, the two indicators found on WIN01 now show their sightings. The other three, which concern other
machines, stay at zero.

<p align="center"><img src="docs/screenshots/misp-event2-sightings-from-velociraptor.png" alt="Sightings visible in MISP"></p>

### The loop runs on its own

Last step: no manual command at all. A test MISP event (#3) is published with a benign marker executed on WIN01.
Velociraptor detects it, hunts and sends back two sightings.

<p align="center"><img src="docs/screenshots/misp-event3-autohunt-sightings.png" alt="MISP event 3 and its automatic sightings"></p>

The list of hunts confirms it: those of 24 September were created by `VelociraptorServer`, the server itself,
while those of the day before had been created by the `admin` account.

<p align="center"><img src="docs/screenshots/velociraptor-autohunt-hunts.png" alt="Hunts created automatically by the server"></p>

### The same loop on Linux

On 7 October, the loop is replayed on LINUX01, which now reaches Velociraptor through the firewall. A benign
marker is written to the system log with `logger`, then MISP event #7, which contains it, is published at
14:09:00. Velociraptor creates the hunt 8 seconds later, without intervention. LINUX01 returns two rows: the one
from the system log and the one from the `sudo` command in the authentication log.

<p align="center"><img src="docs/screenshots/velociraptor-linux01-autohunt-flow.png" alt="Automatic hunt executed on LINUX01"></p>

The sighting reaches MISP at 14:09:47, 47 seconds after publication, with the hostname and the hunt identifier.

<p align="center"><img src="docs/screenshots/misp-event7-linux-sighting.png" alt="MISP event 7 and its sighting from LINUX01"></p>

## Step 6: one attack followed end to end

Everything above is put together here, on 7 October 2026, on a single attack. The eight screenshots of this step
all come from that run. The machines are started in groups, according to their role: first the attack and its
detection, then the response chain. The real alert was handed to Shuffle with Wazuh's official integration
script, and the actions below are the real actions of the chain. The hour-by-hour detail is in sheet
[SC-14](purple-team/scenarios/SC-14-shuffle-soar-workflow.md).

### 1. The attack and its detection

From PURPLE, three successive accesses to the admin share of WIN01 with a valid local account. Wazuh flags the
session coming from the untrusted zone at the first connection (`100179`, level 12, 7 seconds), then each access
to the share (`100140`), and finally the escalation `100141` at the third access, 27 seconds after the start.

<p align="center"><img src="docs/screenshots/wazuh-rule-100141-live.png" alt="Alerts 100179, 100140 and 100141 on WIN01"></p>

### 2. Shuffle processes the alert

Alert `100141` goes through the six nodes in 35 seconds. The screenshot shows the result of each: TheHive alert
created (`201`), MISP match found by Cortex, address `10.10.50.10` added to the firewall, quarantine order sent to
Velociraptor, hunt triggered.

<p align="center"><img src="docs/screenshots/shuffle-execution-chain-100141.png" alt="Shuffle execution of the six nodes"></p>

### 3. The TheHive alert tells the rest

Each node leaves a tag and a dated note on the alert: address blocked at 10:09:37, isolation requested at
10:09:42, MISP event republished at 10:09:48, hunt result at 10:34:29. The alert is attached to case #11.

<p align="center"><img src="docs/screenshots/thehive-alert-chain-100141.png" alt="TheHive alert at the end of the chain"></p>

### 4. The attacker is blocked at the firewall

PURPLE's address is in the `BLOCKED_ATTACKERS` alias, 24 seconds after the delivery of the alert.

<p align="center"><img src="docs/screenshots/opnsense-blocked-attackers-attack-ip.png" alt="Attacker address in the alias"></p>

The OPNsense live log shows the effect: every new attempt from `10.10.50.10` to port 445 of WIN01 is rejected by
the rule `purple -> blocked (SOAR containment)`.

<p align="center"><img src="docs/screenshots/opnsense-firewall-log-containment.png" alt="Attacker connections rejected"></p>

### 5. The host is isolated, then searched

On the Velociraptor side, WIN01 shows the quarantine order sent by the `soar-api` account and the hunt started by
the server, which returns 30 rows. The order applies when the host reconnects: ping then drops to 100% loss, while
the Velociraptor channel stays open for the investigation.

<p align="center"><img src="docs/screenshots/velociraptor-win01-flows-isolation.png" alt="Quarantine and hunt on WIN01"></p>

### 6. The intelligence is updated

MISP event #6, which already held the attacker's address, was republished by the chain at 10:09:51. The two
Velociraptor sightings reach it at 10:25.

<p align="center"><img src="docs/screenshots/misp-event6-sightings.png" alt="MISP event 6 and its two sightings"></p>

### 7. The case is handled and closed

The alert becomes case #11. The five tasks of the template are filled in and the case is closed as a true
positive. The timings displayed are those computed by TheHive.

<p align="center"><img src="docs/screenshots/thehive-case11-chain-100141-closed.png" alt="Case 11 closed"></p>

After the exercise, the isolation of WIN01 was lifted and the address removed from the alias.

## What the repository demonstrates

- Windows detection: 20 Wazuh rules mapped to MITRE ATT&CK, the main ones also available as Sigma rules in `detections/sigma/` (15 rules, Windows and Linux).
- Linux detection: sudo and cron persistence.
- Network: a Suricata and Zeek sensor whose alerts reach Wazuh, and logged default-deny segmentation between five zones.
- Orchestration: a Wazuh alert becomes a TheHive alert with its observables, is enriched by Cortex and MISP, then triggers the blocking of the attacker, the isolation of the host and the hunt, without intervention.
- Guardrails on the automated response: a list of addresses that are never blocked, a label that protects the domain controller, time-limited blocking, a webhook reserved for Wazuh, access to Velociraptor through an SSH key restricted to one command. They are tested in sheet [SC-14](purple-team/scenarios/SC-14-shuffle-soar-workflow.md).
- DFIR: a published MISP event starts a Velociraptor hunt on its own and the sightings come back to MISP. The full loop is proven on Windows and on Linux; isolation of a Linux host was tested separately.
- Repository quality: 54 automated tests check the rules, the firewall policy, the artifacts, the node code and the documentation links; they run on every push, along with validation of the Sigma rules.
- Encryption: the HTTPS services (MISP, OPNsense) are called with the lab's internal CA, without disabling verification. TheHive, Cortex and Shuffle are only reachable from the management network, isolated from the attacker and the targets, and are called over HTTP.

## Scenarios

Sheets SC-01 to SC-11 were written before the management interfaces of the targets were removed (7 October): the addresses `10.10.10.109`, `10.10.10.110` and `10.10.10.111` they mention are the ones DC01, WIN01 and LINUX01 had on the management network at the time. Their current addresses are `10.10.20.10`, `10.10.30.110` and `10.10.30.20` (see the [inventory](docs/lab-registry.md)).

| # | Technique | Sheet |
|---|---|---|
| SC-01 | T1053.005 Scheduled task | [SC-01-T1053-scheduled-task.md](purple-team/scenarios/SC-01-T1053-scheduled-task.md) |
| SC-02 | T1078 Valid account, network logon | [SC-02-T1078-valid-account.md](purple-team/scenarios/SC-02-T1078-valid-account.md) |
| SC-03 | T1021.002 Admin shares: noise filtering | [SC-03-T1021-lateral-movement.md](purple-team/scenarios/SC-03-T1021-lateral-movement.md) |
| SC-04 | T1059.001 Encoded PowerShell | [SC-04-T1059-powershell-encoded.md](purple-team/scenarios/SC-04-T1059-powershell-encoded.md) |
| SC-05 | T1046 Port scan from Kali | [SC-05-T1046-port-scan.md](purple-team/scenarios/SC-05-T1046-port-scan.md) |
| SC-06 | T1110 SMB brute force | [SC-06-T1110-brute-force.md](purple-team/scenarios/SC-06-T1110-brute-force.md) |
| SC-07 | T1548.003 / T1053.003 sudo and cron (Linux) | [SC-07-T1548-T1053-linux.md](purple-team/scenarios/SC-07-T1548-T1053-linux.md) |
| SC-08 | T1021.002 + T1078 Lateral movement WIN01 → DC01 | [SC-08-T1021-win01-to-dc01.md](purple-team/scenarios/SC-08-T1021-win01-to-dc01.md) |
| SC-09 | T1547.001 Run key | [SC-09-T1547-registry-run-key.md](purple-team/scenarios/SC-09-T1547-registry-run-key.md) |
| SC-10 | T1055 Process injection | [SC-10-T1055-process-injection.md](purple-team/scenarios/SC-10-T1055-process-injection.md) |
| SC-11 | T1003 LSASS access, blocked on WIN01 (LSA protection), validated live on DC01 | [SC-11-T1003-lsass-access.md](purple-team/scenarios/SC-11-T1003-lsass-access.md) |
| SC-12 | NDR: capture and detection of a scan | [SC-12-ndr-purple-scan.md](purple-team/scenarios/SC-12-ndr-purple-scan.md) |
| SC-13 | TheHive + Cortex | [SC-13-thehive-cortex-100155.md](purple-team/scenarios/SC-13-thehive-cortex-100155.md) |
| SC-14 | SOAR Wazuh → Shuffle → TheHive → Cortex → MISP | [SC-14-shuffle-soar-workflow.md](purple-team/scenarios/SC-14-shuffle-soar-workflow.md) |
| SC-15 | Velociraptor hunt driven by MISP | [SC-15-dfir-velociraptor-misp-hunt.md](purple-team/scenarios/SC-15-dfir-velociraptor-misp-hunt.md) |
| SC-16 | OPNsense segmentation | [SC-16-firewall-segmentation.md](purple-team/scenarios/SC-16-firewall-segmentation.md) |

## Hardware requirements

The twelve virtual machines add up to 32.5 GB of allocated memory (per-machine detail in
[`docs/lab-registry.md`](docs/lab-registry.md)). Running them all together takes a host with at least 48 GB.

The lab was built and operated on a 16 GB PC. The machines are therefore started in groups, according to the role
played at each stage: the attacker, the target and Wazuh for detection; Shuffle, TheHive, Cortex and MISP for the
response; Velociraptor and the host for the hunt. The firewall stays on from one group to the next. This is why
the alert of step 6 is handed to Shuffle a few minutes after it was raised: the chain and its configuration are
the same as on a larger host, only the sequence is split.

## Repository layout

| Folder | Content |
|---|---|
| `wazuh/rules/` | SocForge rules (Windows/Sigma, Linux, firewall, NDR) |
| `wazuh/agents/` | centralised agent configurations (Windows, Linux, NDR) |
| `wazuh/manager/` | Shuffle integration and syslog listener of the manager |
| `firewall/` | OPNsense segmentation policy, script that applies it through the API, containment and release of an attacker |
| `dfir/` | isolation and release of a compromised host through Velociraptor (Windows and Linux); `server/`: restricted account used by Shuffle |
| `sysmon/` | Sysmon configuration of the domain controller |
| `detections/sigma/` | Sigma rules, validated by CI |
| `tests/` | automated tests (rules, firewall policy, artifacts, SOAR nodes, links) |
| `ndr/` | sensor configuration: monitored interfaces, Suricata, Zeek cluster |
| `pki/` | internal lab CA (public certificate) and certificate issuing script |
| `soar/` | creation of the Shuffle workflows (`nodes/`: code of the containment, host isolation, DFIR hunt trigger and scheduled follow-up nodes); webhook access filter |
| `velociraptor/` | MISP ↔ Velociraptor artifacts (server) and Linux hunt (client) |
| `detections/` | Windows and Linux detection sheets |
| `purple-team/scenarios/` | one sheet per scenario (SC-01 to SC-16) |
| `docs/` | rebuild plan, inventory, metrics, incident report, architecture diagram, screenshots (`screenshots/`) |

## Timeline

First build from 2 to 15 August 2026, a pause, then rebuild and audit from 13 September to 7 October 2026
(details in [`docs/rebuild-plan.md`](docs/rebuild-plan.md)).
