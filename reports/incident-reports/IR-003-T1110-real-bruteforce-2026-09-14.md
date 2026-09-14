# Rapport d'Incident — IR-003 (Réel)

**Type**: Brute Force SMB/NTLM
**Technique MITRE**: T1110
**Sévérité**: Moyenne (niveau 5)
**Date**: 2026-09-14
**Cible**: DC01 (agent 002, 10.10.10.109)
**Source**: LINUX01 (10.10.10.111)
**Statut**: Test authentifié — exécuté et documenté en direct pendant cette session

---

## Contexte

Ce rapport documente une attaque réellement exécutée pendant une session de vérification du lab, suivant le playbook [PB-002](../../incident-response/playbooks/PB-002-bruteforce.md) étape par étape avec de vraies données — contrairement aux rapports IR précédents (IR-001, IR-002) qui contenaient des données narratives fabriquées et ont été supprimés du repo.

## Attaque exécutée

Depuis LINUX01, authentification SMB avec 6 mots de passe incorrects contre le compte `Administrator` sur DC01 :

```bash
for pw in password1 admin123 Welcome1 Qwerty123 P@ssw0rd wrongpass1; do
  smbclient -L //10.10.10.109 -U "Administrator%$pw" -m SMB3
done
```

**Résultat réel** : 6× `NT_STATUS_LOGON_FAILURE`, exécuté à `2026-09-14T12:36:21Z`.

## Détection réelle

Wazuh a détecté chaque échec via la règle **60122** (`Logon Failure - Unknown user or bad password`, niveau 5), avec les champs suivants extraits directement de `/var/ossec/logs/alerts/alerts.json` :

```json
{
  "timestamp": "2026-09-14T12:36:21.855+0000",
  "agent": {"id": "002", "name": "dc01", "ip": "10.10.10.109"},
  "rule": {"id": "60122", "level": 5, "firedtimes": 6},
  "data": {
    "win": {
      "eventdata": {
        "targetUserName": "Administrator",
        "logonType": "3",
        "authenticationPackageName": "NTLM",
        "workstationName": "LINUX01",
        "ipAddress": "10.10.10.111",
        "status": "0xc000006d",
        "subStatus": "0xc000006a"
      }
    }
  }
}
```

**MTTD réel** : timestamp de l'attaque (12:36:21.000 environ) → timestamp de l'alerte (12:36:21.855) = **< 1 seconde**. Pas un chiffre calculé ou estimé — la différence brute entre le log `smbclient` côté attaquant et le timestamp Wazuh côté détection.

## Preuve visuelle — Wazuh Threat Hunting

![Rule 60122 — 6 hits, dc01](../../docs/screenshots/sc-real-bruteforce-wazuh-rule60122-dashboard.png)

Capture du dashboard Wazuh confirmant les 6 hits sur `rule.id: 60122`, tous horodatés entre `13:36:21.702` et `13:36:21.855` (heure locale du dashboard, UTC+1) — écart de 153 ms entre la 1ère et la dernière alerte, cohérent avec le MTTD sub-seconde mesuré côté log brut.

## Application du playbook PB-002

**Phase 1 — Triage** :
- Compte ciblé : `Administrator`
- IP source : `10.10.10.111` — dans le périmètre lab (10.10.10.0/24) → test interne, pas d'escalade externe
- Type de logon : 3 (réseau/NTLM)

**Phase 2 — Investigation** :
- Recherche d'un succès (rule 60106 / EventID 4624) après les échecs sur le même compte depuis la même IP → **aucun trouvé** (mots de passe tous invalides intentionnellement)
- Volume : 6 tentatives en < 1 seconde
- Outil identifié : `smbclient` (Samba) via `workstationName: LINUX01`

**Phase 3 — Confinement** :
- Test authentifié depuis une VM du lab — aucune action de confinement nécessaire (pas d'IP externe à bloquer, pas de compte réel à désactiver)

**Phase 4 — Rapport** :
- Ce document constitue le rapport, avec MTTD réel et toutes les données extraites du log Wazuh brut

## Limite connue

La règle de corrélation "brute force" à seuil (5+ échecs en 60s, normalement rule 100111) n'a pas eu le temps de se déclencher car les 6 tentatives sont arrivées en moins d'une seconde — plus rapide que la fenêtre d'agrégation Wazuh. Seule la règle atomique 60122 (échec individuel) s'est déclenchée, 6 fois. Ceci illustre une limite réelle observée : le détecteur atomique fonctionne, la corrélation de fréquence nécessite un espacement temporel plus large entre tentatives pour être fiable à observer.
