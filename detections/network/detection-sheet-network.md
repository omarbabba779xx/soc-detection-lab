# Fiche de Détection — Réseau (OPNsense + VM07-NDR)

## Sources de logs réseau

| Source              | Format               | Collecteur           | Destination          |
|---------------------|----------------------|----------------------|----------------------|
| OPNsense filterlog  | Syslog (RFC 5424)    | Wazuh agent syslog   | VM02-WAZUH           |
| Zeek (VM07)         | JSON / TSV           | Wazuh agent filebeat | VM02-WAZUH           |
| Suricata (VM07)     | EVE JSON             | Wazuh agent          | VM02-WAZUH           |

---

## Détections OPNsense

### T1046 — Network Scan (règle firewall)
- **Indicateur**: Flood de connexions bloquées SYN vers multiples ports depuis la même IP
- **Source**: filterlog action=block, de nombreux dst_port distincts en <1 minute
- **Règle OPNsense**: Règle IDS/IPS intégrée + log syslog vers Wazuh

### Exfiltration de données (T1041)
- **Indicateur**: Volume sortant anormalement élevé vers une IP externe
- **Source**: Interface WAN filterlog — connexions allow de volume > 50MB

---

## Détections Zeek

| Log Zeek           | Technique MITRE | Indicateurs                                          |
|--------------------|-----------------|------------------------------------------------------|
| conn.log           | T1046           | `resp_pkts` ≈ 0 sur multiples hosts → scan SYN       |
| dns.log            | T1071.004       | Requêtes DNS anormalement longues (DGA patterns)     |
| http.log           | T1071.001       | User-Agent vide, method=POST vers IP inconnue        |
| ssl.log            | T1573.002       | Certificat auto-signé, CN=localhost, ja3 suspect     |
| smb_files.log      | T1021.002       | Accès massif à des shares (>100 fichiers/minute)     |
| ntlm.log           | T1110           | `status=LOGON_FAILURE` répétés sur le même compte    |

---

## Détections Suricata (règles ET Open)

| Catégorie ET Open   | Technique MITRE | Description                                |
|---------------------|-----------------|--------------------------------------------|
| ET SCAN             | T1046           | Détection scans nmap, masscan              |
| ET EXPLOIT          | T1190           | Exploitation tentée sur services exposés   |
| ET MALWARE          | T1071           | Beacon C2 connus (Cobalt Strike, Metasploit) |
| ET POLICY           | T1021.001       | RDP depuis une IP non-autorisée            |
| ET TROJAN           | T1055           | Communication reverse shell                |

---

## Zones réseau surveillées

> Le plan initial prévoyait 6 zones réseau isolées. État réel : les 6 zones (`mgmt`, `srv`, `ep`, `ndr`, `purple`, `dfir`) sont déployées et leur routage inter-zone via VM01-FW a été validé en direct le 2026-09-16 (ping 0% perte sur chacune, voir `docs/network/IP-plan.md`).

| Zone          | CIDR             | Surveillance                               |
|---------------|------------------|--------------------------------------------|
| Management    | 10.10.10.0/24 | Tout le trafic lab via Zeek/Suricata + Wazuh agents |
| Serveurs (srv) | 10.10.20.0/24   | DC01 — routage inter-zone validé            |
| Endpoints (ep) | 10.10.30.0/24   | WIN01, LINUX01 — routage inter-zone validé  |
| NDR           | 10.10.40.0/24    | NDR — routage inter-zone validé             |
| Purple Team   | 10.10.50.0/24    | PURPLE — routage inter-zone validé          |
| DFIR          | 10.10.60.0/24    | Velociraptor gRPC vers endpoints            |
| Internet      | 0.0.0.0/0        | NAT via WAN OPNsense (accès lab restreint)  |
