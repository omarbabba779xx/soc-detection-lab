# SC-05 : T1046 : Network Service Discovery (scan de ports)

Session : Reconstruction, 2026-09-17
Attaquant : PURPLE (Kali 2026.2, 10.10.10.60), premier test de la reconstruction lancé
depuis la machine d'attaque dédiée plutôt que depuis la console de la victime

> Adresse de l'attaquant : ce test date d'avant le 24/09/2026, quand PURPLE avait encore une
> patte sur le réseau mgmt (`10.10.10.60`). Depuis, PURPLE n'existe plus que dans sa zone
> filtrée (`10.10.50.10`) : voir SC-16, « Isolement de l'attaquant ».

Cible : dc01 (agent Wazuh ID 007, 10.10.10.109)
MITRE : T1046, Network Service Discovery
Tactique : Discovery

---

## Objectif

Corriger une faiblesse méthodologique identifiée dans les tests précédents de cette
reconstruction : toutes les attaques avaient été lancées depuis la console de la machine
victime elle-même (DC01, WIN01), ce qui n'est pas réaliste pour un scénario
purple-team. PURPLE (Kali) existe précisément pour jouer le rôle de l'attaquant.

## Pré-requis découverts et corrigés pendant ce test

1. PURPLE n'avait pas de SSH exploitable : `sshd` tournait depuis le boot mais restait
   inaccessible depuis l'hôte. Cause racine : `eth1` (le NIC NAT) était UP mais n'avait
   jamais reçu de bail DHCP. Corrigé via `nmcli device connect eth1` (persistant après
   reboot via autoconnect).
2. Sysmon (Sysinternals) n'était pas installé sur DC01, seul un `sysmon.ocx` Windows
   sans rapport existait. Installé avec la config SwiftOnSecurity, qui s'est révélée
   trop restrictive par défaut : elle exclut la plupart des connexions réseau
   (réduction du bruit). Remplacée par une config minimale sans exclusion réseau pour que
   les scans soient visibles.
3. Bug de règle : 100101/100102 elles-mêmes n'avaient pas de bug, mais l'agent dc01
   s'est retrouvé bloqué en état `Pending` après un redémarrage du manager (poignée de
   main incomplète). Résolu par `Restart-Service WazuhSvc -Force` côté DC01.

## Commande exécutée (depuis PURPLE)

```bash
nmap -sT -p 21,22,23,25,445,1433,3306,3389,5985,5986 10.10.10.109
```

Résultat : 445/tcp (microsoft-ds) et 5985/tcp (wsman) ouverts, le reste filtré.

Pour valider l'agrégation (règle 100102, seuil ≥10 connexions/5 min) :

```bash
for i in 1 2 3 4 5; do
  nmap -sT -p 445,5985 --max-retries 0 --host-timeout 5s 10.10.10.109
done
```

## Détection Wazuh

| Règle  | Niveau | Rôle                                             |
|--------|--------|---------------------------------------------------|
| 100101 | 8      | Connexion individuelle vers un port sensible       |
| 100102 | 10     | ≥10 connexions matchées 100101 en 5 min, scan     |

Testé en direct le 2026-09-17 :

```
Rule: 100101 (level 8) -> 'Sigma T1046: Network connection to a sensitive/admin port — 10.10.10.109:445'
Rule: 100101 (level 8) -> 'Sigma T1046: Network connection to a sensitive/admin port — 10.10.10.109:5985'
...
Rule: 100102 (level 10) -> 'Sigma T1046: Multiple ports scanned from the same source — possible port scan'
```

## Résultats

| Critère    | Valeur              |
|------------|----------------------|
| Détecté    | validé OUI               |
| Règles     | 100101, 100102       |
| Verdict    | VP (vrai positif)    |
| Source     | PURPLE (10.10.10.60), attaque réaliste, pas la console de la victime |

Capture (dashboard Wazuh, 60 correspondances) :
[`docs/screenshots/wazuh-dashboard-dc01-scan-events.png`](../../docs/screenshots/wazuh-dashboard-dc01-scan-events.png)

## Nettoyage

Aucun artefact persistant côté DC01 (scan réseau, pas d'écriture disque). Sysmon reste
installé avec la config réseau-inclusive, comportement de détection voulu, pas un
artefact de test à retirer.
