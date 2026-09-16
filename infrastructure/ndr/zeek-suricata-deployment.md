# NDR Deployment — Zeek + Suricata (VM07-NDR)

## Versions installed

| Component | Version | Source |
|---|---|---|
| Suricata | 6.0.4 | Ubuntu 22.04 official repo |
| Zeek | 8.0.10 (LTS) | OpenSUSE Build Service `security:zeek` repo |

## Capture interface

> **Note**: the original plan called for a dedicated `socforge-ndr` tap network mirroring traffic from a separate mgmt zone. Deployed and validated live on 2026-09-16: `enp0s3` carries the `socforge-ndr` zone IP (10.10.40.40), routed through VM01-FW (OPT3/em4, 0% packet loss, see `docs/network/IP-plan.md`). This test also uncovered and fixed a pre-existing bug where the mgmt (10.10.10.40) and ndr (10.10.40.10) IPs were swapped between `enp0s3` and `enp0s8` — `enp0s8` now correctly carries the mgmt IP.

`enp0s9` — the passive capture NIC on `socforge-mgmt`, separate from `enp0s3` (ndr zone) and `enp0s8` (mgmt).

## Suricata setup

```bash
sudo apt-get install -y suricata
sudo sed -i 's/interface: eth0/interface: enp0s9/g' /etc/suricata/suricata.yaml
sudo systemctl enable --now suricata
```

Runs in AF_PACKET mode via systemd (`suricata.service`).

## Zeek setup

```bash
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" | \
  sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | \
  sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg
sudo apt-get update && sudo apt-get install -y zeek-lts

sudo sed -i 's/interface=eth0/interface=enp0s9/' /opt/zeek/etc/node.cfg
sudo /opt/zeek/bin/zeekctl deploy
```

Standalone Zeek node, managed via `zeekctl`. Logs land in `/opt/zeek/logs/current/` (conn.log, http.log, ssh.log, dns.log, files.log, etc.).

## Verification

```bash
sudo /opt/zeek/bin/zeekctl status
sudo systemctl status suricata
sudo tail /opt/zeek/logs/current/conn.log
```

Both services capture real traffic on the tap interface — confirmed by inspecting `ssh.log` and `conn.log` entries matching live connections during setup.

## Persistence across reboots

- `suricata.service` enabled via systemd (`systemctl enable suricata`)
- Zeek redeployed on boot via `/etc/cron.d/zeek-start` (`@reboot root /opt/zeek/bin/zeekctl deploy`) since zeekctl does not ship a systemd unit by default
