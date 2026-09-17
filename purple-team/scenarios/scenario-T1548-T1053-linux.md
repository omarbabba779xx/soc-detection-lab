# SC-07 — T1548.003 + T1053.003 : Privilege Escalation & Persistence (Linux)

**Session** : Reconstruction — 2026-09-17
**Attaquant** : PURPLE (Kali 2026.2, 10.10.10.60) — pivot SSH vers linux01
**Cible** : linux01 (agent Wazuh ID 008, 10.10.10.111)
**MITRE** : T1548.003 (Sudo and Sudo Caching), T1053.003 (Cron)
**Tactiques** : Privilege Escalation / Persistence

---

## Objectif

Continuer la méthodologie établie sur DC01 (SC-05, SC-06) : attaquer depuis PURPLE
plutôt que depuis la console de la victime. Pour Linux, l'accès initial simulé est un
pivot SSH (identifiants déjà obtenus par l'attaquant), depuis lequel il tente une
élévation de privilèges (`sudo`) puis une persistance (cron).

## Pré-requis découverts et corrigés

L'agent LINUX01 était configuré dans le groupe Wazuh `default`, qui ne contient qu'une
configuration FIM **Windows** (chemins `%WINDIR%`, registre) — sans aucun effet sur un
hôte Linux, et sans aucune règle FIM sur les répertoires cron. Un groupe `linux` dédié a
été créé (`wazuh/agents/agent-linux.conf`) avec surveillance temps réel de `/etc/cron.d`,
`/etc/cron.{daily,hourly,weekly,monthly}` et `/var/spool/cron`.

Le NIC de management (`enp0s9`, 10.10.10.111) n'était pas non plus dans la configuration
réseau persistante (`/etc/netplan/01-socforge.yaml`) — corrigé.

## Commandes exécutées (pivot depuis PURPLE)

```python
import paramiko
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('10.10.10.111', username='socadmin', password='...')
c.exec_command('echo ... | sudo -S whoami')                       # T1548.003
c.exec_command('echo ... | sudo -S tee /etc/cron.d/socforge-test') # T1053.003
```

## Détection Wazuh

| Règle  | Niveau | Technique  | Source                              |
|--------|--------|-----------|--------------------------------------|
| 100200 | 9      | T1548.003 | journald (PAM/sudo), règle base 5402 |
| 100210 | 10     | T1053.003 | FIM temps réel sur répertoires cron  |

**Testé en direct le 2026-09-17** :

```
Rule: 100200 (level 9) -> 'Sigma T1548.003: sudo command executed — /usr/bin/whoami'
Rule: 100210 (level 10) -> 'Sigma T1053.003: Cron job file created/modified — possible persistence'
```

Capture (dashboard Wazuh, 19 correspondances) :
[`docs/screenshots/wazuh-dashboard-linux01-events.png`](../../docs/screenshots/wazuh-dashboard-linux01-events.png)

## Résultats

| Critère    | Valeur                    |
|------------|----------------------------|
| Détecté    | ✅ OUI (les deux règles)  |
| Règles     | 100200, 100210            |
| Verdict    | VP (vrai positif)         |
| Source     | PURPLE → pivot SSH → linux01 |

## Méthodologie de vérification

Comme pour les tests Windows, les alertes sont recherchées par **agent émetteur**
(`(linux01)`) plutôt que par mot-clé seul — toute commande `sudo` tapée directement sur
la console du manager (agent 000) déclenche aussi la règle 100200 et peut créer une
confusion si l'on ne filtre pas par agent.

## Nettoyage

`/etc/cron.d/socforge-test` supprimé immédiatement après validation de l'alerte.
