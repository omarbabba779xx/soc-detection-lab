# SocForge — Index des Artifacts Velociraptor collectés

**Serveur Velociraptor**: 10.10.60.10:8889
**Clients**: DC01 (C.dc01.socforge.lab), WIN01 (C.win01.socforge.lab)
**Collection date**: 2026-08-07

---

## Artifacts collectés par client

### DC01 — Windows Server 2022 (10.10.10.109)

| Artifact ID       | Type          | Fichier VQL                        | Résultats             |
|-------------------|---------------|------------------------------------|-----------------------|
| ART-DC01-001      | Process List  | artifact-socforge-pslist.yaml      | 46 processus          |
| ART-DC01-002      | Network State | artifact-socforge-netstat.yaml     | 23 connexions actives |
| ART-DC01-003      | EVTX Hunt     | artifact-socforge-evtx-hunt.yaml   | 1,247 événements      |
| ART-DC01-004      | LSASS Hunt    | hunt-T1003-lsass-access.yaml       | 2 accès détectés      |

### WIN01 — Windows 11 (10.10.10.110)

| Artifact ID       | Type          | Fichier VQL                        | Résultats             |
|-------------------|---------------|------------------------------------|-----------------------|
| ART-WIN01-001     | Process List  | artifact-socforge-pslist.yaml      | 38 processus          |
| ART-WIN01-002     | Network State | artifact-socforge-netstat.yaml     | 15 connexions actives |
| ART-WIN01-003     | EVTX Hunt     | artifact-socforge-evtx-hunt.yaml   | 892 événements        |
| ART-WIN01-004     | LSASS Hunt    | hunt-T1003-lsass-access.yaml       | 1 accès (test ART)   |

---

## Résultats notables

### DC01 — LSASS Access Hunt (ART-DC01-004)

```
Timestamp: 2026-08-07T13:10:04Z
Source Process: C:\AtomicRedTeam\atomics\T1003.001\bin\Invoke-Mimikatz.ps1
Target: lsass.exe (PID 640)
Access Mask: 0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
CallChain: powershell.exe → Invoke-AtomicTest → lsass access
```

→ Corrélation: EventID 10 Sysmon détecté par Wazuh (Règle 100150, 6s MTTD)

---

### WIN01 — Process List snapshot (ART-WIN01-001)

```
Processus notables détectés:
  - powershell.exe (PID 4892) — parent: explorer.exe — SUSPECT
  - hydra.exe — NON présent sur WIN01 (seulement sur VM12-PURPLE)
  - mimikatz.exe — NON présent (test ART utilise script PS)
  - sysmon.exe (PID 1204) — service Sysmon actif ✓
  - wazuhd.exe (PID 892) — agent Wazuh actif ✓
```

---

## Exports disponibles

Les résultats bruts des hunts sont exportables depuis Velociraptor GUI:

```
Velociraptor GUI → Hunts → [Hunt ID] → Download Results → CSV/JSON
```

Les fichiers CSV des pslist sont référencés dans:
- `metrics/datasets/labeled-events-2026-08-07.csv`
- `dfir/velociraptor/investigation-report-2026-08-07.md`

---

## Chain of Custody

Voir: `dfir/velociraptor/chain-of-custody.md`

Tous les artifacts collectés portent:
- Hash SHA256 généré automatiquement par Velociraptor
- Timestamp UTC horodaté par le serveur Velociraptor (NTP sync)
- Signature numérique du serveur (clé TLS interne lab)
