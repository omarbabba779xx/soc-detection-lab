# SC-05 : T1046, scan de ports

| | |
|---|---|
| Date | 2026-09-17 (reconstruction) |
| Lancé depuis | PURPLE (Kali 2026.2, `10.10.10.60` à cette date) |
| Cible | DC01 (agent Wazuh 007, `10.10.10.109` à cette date) |
| Technique MITRE | T1046, Network Service Discovery |
| Tactique | Discovery |
| Résultat | détecté, règles 100101 (niveau 8) et 100102 (niveau 10) |

> Adresses : ce test date d'avant le 24/09/2026, quand PURPLE avait encore une carte sur le réseau de gestion
> (`10.10.10.60`). Depuis, PURPLE n'existe plus que dans sa zone filtrée (`10.10.50.10`) : voir SC-16,
> « Isolement de l'attaquant ».

## Objectif

Jusqu'à ce test, les attaques de la reconstruction étaient lancées sur la console de la machine visée, ce qui n'est
pas réaliste. C'est le premier scénario lancé depuis PURPLE, la machine prévue pour tenir le rôle de l'attaquant.

## Ce qu'il a fallu corriger avant

1. PURPLE n'était pas joignable en SSH. `sshd` tournait, mais la carte NAT `eth1` n'avait jamais reçu d'adresse
   par DHCP. Corrigé avec `nmcli device connect eth1`, conservé au redémarrage.
2. Sysmon (Sysinternals) n'était pas installé sur DC01 : seul un `sysmon.ocx` sans rapport existait. Il a été
   installé avec la configuration SwiftOnSecurity, qui exclut la plupart des connexions réseau pour réduire le
   bruit. Elle a été remplacée par une configuration minimale sans exclusion réseau, pour que les scans soient
   visibles.
3. L'agent de DC01 est resté en état `Pending` après un redémarrage du manager. Résolu par
   `Restart-Service WazuhSvc -Force` sur DC01. Les règles 100101 et 100102 n'avaient pas de défaut.

## Test

```bash
nmap -sT -p 21,22,23,25,445,1433,3306,3389,5985,5986 10.10.10.109
```

Résultat : 445/tcp et 5985/tcp ouverts, le reste filtré.

Pour atteindre le seuil de 100102 (dix connexions en cinq minutes) :

```bash
for i in 1 2 3 4 5; do
  nmap -sT -p 445,5985 --max-retries 0 --host-timeout 5s 10.10.10.109
done
```

## Détection

| Règle | Niveau | Rôle |
|---|---|---|
| 100101 | 8 | une connexion vers un port sensible |
| 100102 | 10 | dix connexions de ce type en cinq minutes : scan |

```
Rule: 100101 (level 8) -> 'Sigma T1046: Network connection to a sensitive/admin port — 10.10.10.109:445'
Rule: 100101 (level 8) -> 'Sigma T1046: Network connection to a sensitive/admin port — 10.10.10.109:5985'
...
Rule: 100102 (level 10) -> 'Sigma T1046: Multiple ports scanned from the same source — possible port scan'
```

Capture (tableau de bord Wazuh, 60 correspondances) :
[`wazuh-dashboard-dc01-scan-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-scan-events.png)

Depuis le 07/10, `100102` regroupe les connexions par adresse source (`same_field`) : voir
[`detection-sheet-windows.md`](../../detections/windows/detection-sheet-windows.md).

## Résultats

| Critère | Valeur |
|---|---|
| Détecté | oui |
| Règles | 100101, 100102 |
| Verdict | vrai positif |
| Source | PURPLE (10.10.10.60), et non la console de la machine visée |

## Lecture côté défense

Ici, le scan est vu depuis la cible : Sysmon enregistre sur DC01 chaque connexion entrante vers un port sensible,
et la règle `100102` regroupe ces connexions par adresse source. Cette vue n'existe que sur les postes équipés de
Sysmon, et pour les ports listés dans la règle.

Deux autres vues du même comportement existent dans le lab : la sonde réseau (SC-12), qui reconnaît les signatures
de scan, et le pare-feu (SC-16), qui journalise les tentatives vers les zones interdites. Les trois se recoupent
sans dépendre les unes des autres.

## Nettoyage

Rien à retirer sur DC01 : un scan n'écrit rien sur le disque. Sysmon reste installé avec la configuration qui
inclut les connexions réseau, c'est le réglage de détection voulu.
