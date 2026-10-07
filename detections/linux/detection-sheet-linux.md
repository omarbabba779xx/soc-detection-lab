# Fiche de Détection : Linux (LINUX01)

> Reconstruit le 2026-09-17. Contrairement au socle Windows, l'agent LINUX01 tournait
> jusqu'ici dans le groupe `default`, une configuration partagée 100% Windows sans
> aucun effet réel sur un hôte Linux (aucun répertoire de surveillance FIM pertinent,
> aucune collecte de log spécifique). Un groupe `linux` dédié a été créé
> (`wazuh/agents/agent-linux.conf`) avec une configuration FIM adaptée.

## Sources de logs collectés

| Source              | Mécanisme                     | Détail                                              |
|---------------------|--------------------------------|------------------------------------------------------|
| Authentification    | journald (PAM/sudo)             | Capté nativement par `wazuh-logcollector`, sans `<localfile>` dédié |
| File Integrity Monitoring | `syscheck` (temps réel)   | `/etc/cron.d`, `/etc/cron.{daily,hourly,weekly,monthly}`, `/var/spool/cron`, `/etc` |

## Techniques détectées

### T1548.003 : Sudo and Sudo Caching Abuse
- Source: journald (PAM), règle de base Wazuh 5402
- Règle Wazuh: 100200
- Indicateurs: `100200` (niveau 5) enregistre toute commande exécutée via `sudo` ; `100201` (niveau 10) alerte quand la commande touche aux comptes, aux droits ou aux identifiants (`/etc/shadow`, `/etc/sudoers`, `useradd`, `usermod`, `passwd`, `visudo`, `authorized_keys`), ouvre un shell root ou pose un bit setuid.
- Testé en direct le 2026-09-17 : `sudo whoami` exécuté depuis PURPLE (Kali) via
  un pivot SSH vers linux01 (10.10.10.111), simulant un attaquant ayant déjà obtenu un
  accès shell bas-privilège et tentant l'élévation :
  `Rule: 100200 (level 9) -> 'Sigma T1548.003: sudo command executed — /usr/bin/whoami'`
- Faux positifs: toute commande d'administration légitime via `sudo` (bruit élevé en
  usage normal), règle utile pour la corrélation, pas pour l'alerte isolée.
- Piège méthodologique documenté : toute commande `sudo` tapée sur la console du
  manager Wazuh lui-même est captée par cette même règle (agent 000/local). Chercher
  une preuve dans `alerts.log` avec `grep` sous `sudo` génère une auto-correspondance
  (la commande de recherche apparaît dans son propre résultat). Toujours filtrer par nom
  d'agent (`(linux01)` dans le préfixe de ligne) pour éviter ce piège.
- Réglage du 2026-10-07 : au niveau 9, `100200` était la règle la plus bavarde du lab (560 alertes, presque toutes de l'administration légitime). Elle est descendue au niveau 5, et seules les commandes sensibles alertent (`100201`). Test en direct sur LINUX01 : une commande `sudo` qui lit `/etc/shadow` donne `100201` (niveau 10), les autres commandes `sudo` restent à `100200` (niveau 5).

### T1053.003 : Cron Persistence
- Source: FIM (syscheck), surveillance temps réel de `/etc/cron.d` et
  `/var/spool/cron`
- Règle Wazuh: 100210
- Indicateurs: création ou modification d'un fichier dans un répertoire cron.
- Testé en direct le 2026-09-17 : création de `/etc/cron.d/socforge-test` depuis
  PURPLE via le même pivot SSH, détecté quasi-instantanément (`realtime="yes"`) :
  `Rule: 100210 (level 10) -> 'Sigma T1053.003: Cron job file created/modified — possible persistence'`
- Nettoyage: fichier de test supprimé immédiatement après validation.

## Preuves visuelles : Wazuh Dashboard

Événements filtrés sur `rule.id:(100200 or 100210) and agent.name:linux01`, 19
correspondances :
[`wazuh-dashboard-linux01-events.png`](../../docs/screenshots/wazuh-dashboard-linux01-events.png)

## Prérequis découverts et corrigés pendant cette reconstruction

1. `enp0s9` (NIC mgmt, 10.10.10.111) jamais dans la config réseau persistante
   (`/etc/netplan/01-socforge.yaml`), l'interface existait mais restait DOWN sans IP à
   chaque boot. Ajoutée et validée par `netplan apply`.
2. Aucune règle de redirection SSH n'existait pour LINUX01 sur l'hôte, ajoutée
   (`127.0.0.1:12223` → port invité 22).
3. Agent Wazuh dans le mauvais groupe (`default`, config Windows sans effet), recréé
   dans un groupe `linux` dédié avec une vraie config FIM.
4. Auto-enrôlement en double : après le premier redémarrage du service, un nouvel
   agent `linux01` (minuscule) s'est enregistré automatiquement avec un nouvel ID, laissant
   l'ancien `LINUX01` orphelin en `Disconnected`, même schéma que WIN01/DC01 rencontré
   plus tôt dans cette session. Ancien agent supprimé, le nouveau réassigné au groupe
   `linux`.
