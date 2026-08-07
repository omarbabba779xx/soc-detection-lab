# Preuves Wazuh Dashboard — Session 2026-08-06

## Authentification résolue
- **URL** : https://localhost:12443 (portforward VM02:443)
- **Credentials** : admin / S0cF0rge.Lab2024
- **Méthode reset** : /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh

## Pages documentées (vérifiées en session)

### 1. Overview Dashboard
- URL: https://localhost:12443/app/wz-home#/overview
- Contenu: Agents Summary (3 disconnected), 31 High, 1697 Medium, 3235 Low (24h)

### 2. Threat Hunting Dashboard (7 jours)
- URL: https://localhost:12443/app/threat-hunting
- Contenu: 10 190 alertes, 31 Level 12+, 80 auth failures, agents: wazuh/dc01/win01/linux01
- Pic d'activité: 2026-08-04 à 06 (scénarios Purple Team)

### 3. Malware Detection
- URL: https://localhost:12443/app/malware-detection
- Contenu: Emotet + Rootkits activity charts, Rule 510/521

### 4. MITRE ATT&CK Dashboard (24h)
- URL: https://localhost:12443/app/mitre-attack
- Contenu: Defense Evasion, Privilege Escalation, Initial Access, Persistence, Lateral Movement
- Agents: dc01 (dominant), wazuh, win01
- Techniques: SMB/Windows Admin, Valid Accounts, Pass the Hash, Remote Services

## Wazuh → Shuffle intégration
- integrations.log confirmé: POSTs vers webhook_f1ded55e-cd60-404c-bd24-93f2a3ea9aa4
- ossec.conf: 1 bloc <integration><name>shuffle</name> actif (level 3+)
- wazuh-manager: active

## Screenshots à prendre (Win+Shift+S) quand vous revenez
Pour la preuve portfolio, naviguez sur ces URLs et prenez les screenshots:
1. https://localhost:12443/app/wz-home#/overview
2. https://localhost:12443/app/threat-hunting (Last 7 days)
3. https://localhost:12443/app/mitre-attack (Framework tab)
4. http://localhost:3001/workflows/6d5df895-0e47-4341-aed9-6aa3fc4ae605 (Shuffle workflow)

## 5. MITRE ATT&CK Framework (URL directe validée)
- URL: https://localhost:12443/app/mitre-attack#/overview/?tab=mitre&tabView=inventory
- CETTE PAGE EST LA PLUS IMPORTANTE POUR LE PORTFOLIO
- Tactics avec hits réels:
  - Defense Evasion: 1894, Privilege Escalation: 1889, Persistence: 1737
  - Lateral Movement: 267, Credential Access: 21, Execution: 3, Discovery: 3
- Techniques Purple Team confirmées:
  - T1046 Network Service Discovery: 2 (Scénario 1 - nmap)
  - T1021.002 SMB/Windows Admin Shares: 138 (Scénario 4 - Lateral Movement)
  - T1059.001 PowerShell: 3 (Scénario 3 - Encoded Command)
  - T1027 Obfuscated Files: 3 (Scénario 3 - obfuscation)
  - T1078 Valid Accounts: 1717 (Scénario 2 - credential attack)

## Pour prendre les screenshots quand vous revenez (PRIORITÉ)
1. **MITRE Framework** : https://localhost:12443/app/mitre-attack -> onglet Framework
   -> Win+Shift+S sur le panneau Tactics + Techniques (pas le plein écran)
2. **Threat Hunting 7j** : https://localhost:12443/app/threat-hunting (Last 7 days)
3. **Wazuh Overview** : https://localhost:12443/app/wz-home
Credentials: admin / S0cF0rge.Lab2024
