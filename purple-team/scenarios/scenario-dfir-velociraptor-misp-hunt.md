# SC-15 — Étape 8 : Import d'IOC dans MISP et chasse Velociraptor (DFIR-HUNT)

**Session** : Reconstruction, étape 8 — 2026-09-22
**VM actives** : VM08-DFIR-HUNT (Velociraptor 0.77.1) + VM10-WIN01 (endpoint chassé) + VM05-MISP
**Objectif** (plan de reconstruction) : importer des IOC dans MISP, puis lancer une requête
de chasse DFIR-HUNT sur un artefact laissé par les tests précédents.

---

## Pourquoi une chasse dans les journaux et pas sur le disque

Chaque scénario d'attaque précédent a été nettoyé (clé Run supprimée, tâche planifiée
supprimée, fichier cron supprimé). Il ne reste donc aucun artefact « vivant » à trouver sur
le disque. En revanche, les **journaux d'événements** gardent la trace de la création
**et** de la suppression de ces artefacts. C'est exactement ce que cherche un analyste DFIR
face à un attaquant qui a fait le ménage.

## Préparation — trois vrais problèmes corrigés sur VM08

1. **Carte réseau mgmt jamais configurée** : `enp0s8` (réseau `socforge-mgmt`, celui des
   endpoints) était `DOWN`, sans adresse. Aucun client ne pouvait donc joindre le serveur.
   Corrigé : `10.10.10.61/24`, persistant dans `/etc/netplan/99-socforge.yaml`.
2. **URL du frontend incorrecte** : le bloc `Client.server_urls` de la config serveur (celui
   que `velociraptor config client` recopie dans la config client) ne pointait pas vers une
   adresse joignable. Corrigé en `https://10.10.10.61:8889/`, puis config client régénérée.
3. **Utilisateur API** : création de `socforge-api` (rôle administrator,
   `/home/socadmin/api.config.yaml`) pour piloter les collectes via l'API gRPC (port 8001)
   du serveur en marche. La commande `query` hors-ligne ne voit pas l'index des clients.

## Déploiement de l'agent sur WIN01

- **Intégration souris VirtualBox** : WIN01 n'a pas les Guest Additions et utilisait une
  souris PS/2 (relative). Passage en `--mouse usbtablet` avec un contrôleur `--usbxhci on`
  (pointage absolu, pilote HID natif de Windows 11). Le pilotage GUI est désormais fiable.
- Binaire et config servis depuis l'hôte (`python -m http.server`, joignable depuis la VM
  via la passerelle NAT `10.0.3.2`), puis téléchargés dans une console admin
  (`C:\V\v.exe`, `C:\V\c.yaml`).
- **Le service Windows ne se connectait pas** : `service install` a réutilisé le service
  existant d'une installation d'août. Le processus tournait (`Running`) mais n'ouvrait
  aucune connexion, alors que le même binaire lancé au premier plan fonctionnait. Cause
  exacte non déterminée. Contournement : service désactivé, remplacé par une tâche planifiée
  `VelociraptorAgent` (déclencheur au démarrage, compte SYSTEM, `C:\V\v.exe --config C:\V\c.yaml client`).
- **Persistance vérifiée** : WIN01 redémarré sans ouverture de session. Le client s'est
  reconnecté seul (reset à 18:48 UTC, `last_seen` 18:52:10 UTC).

Client : `C.07dab9364f98e1aa` — `DESKTOP-75LAKDV.socforge.lab` — `10.10.10.110`.

## Chasse 1 — trace du test T1059 (SC-04)

Collecte `Windows.EventLogs.EvtxHunter` (flow `F.DAPCIL0FN91P4`) sur
`C:/Windows/System32/winevt/Logs/*PowerShell*.evtx`, `IocRegex=U29jRm9yZ2VSdWxlVGVzdA`,
`IdRegex=^4104$`.

**Résultat : 3 événements 4104** (17/09 17:48, 17:57, 18:05 UTC, `labuser`), chacun
contenant le ScriptBlock décodé
`FromBase64String('U29jRm9yZ2VSdWxlVGVzdA==')`. Ils ont été trouvés directement dans le
`.evtx` de WIN01, indépendamment de Wazuh.

## Import des IOC de la campagne dans MISP

Événement **#2** « SocForge purple-team campaign - IOCs from rebuild scenarios », publié,
5 attributs tirés des fiches de scénario :

| Type | Valeur | IDS | Scénario |
|---|---|---|---|
| ip-src | `10.10.10.60` (PURPLE) | ✅ | SC-05 (scan), SC-06 (brute force) |
| text | `U29jRm9yZ2VSdWxlVGVzdA==` | — | SC-04 (T1059.001, WIN01) |
| regkey\|value | `HKLM\...\Run\SocForgeTest12\|%WINDIR%\System32\calc.exe` | ✅ | SC-09 (T1547.001, WIN01) |
| text | `SocForgeRebuildTest` | — | SC-01 (T1053.005, DC01) |
| filename | `/etc/cron.d/socforge-test` | ✅ | SC-07 (T1053.003, LINUX01) |

Le type `windows-scheduled-task` n'existe pas dans cette version de MISP (2.4.177). La
tâche planifiée a donc été saisie en `text`.

## Chasse 2 — pilotée par les IOC de MISP

Les attributs `text` et `regkey|value` de l'événement #2 sont lus **via l'API MISP**
(`/attributes/restSearch`). Pour la clé de registre, seul le nom de la valeur est gardé.
L'expression obtenue est passée telle quelle à Velociraptor :
`IocRegex = U29jRm9yZ2VSdWxlVGVzdA|SocForgeTest12|SocForgeRebuildTest`, sur **tous** les
journaux de WIN01 (flow `F.DAPD1G4KA3HL4`, 296 s).

**Résultat : 11 événements**
- les 3 ScriptBlocks 4104 de SC-04 ;
- **la chronologie complète de la persistance SC-09, alors que la clé n'existe plus** :
  - 18/09 08:56:49 — `reg add ...\Run /v SocForgeTest12 /d C:\Windows\System32\calc.exe`
    (Sysmon 1 + Security 4688), valeur écrite (Sysmon 13 `SetValue`)
  - 08:57:09 — Windows crée `RunNotification\StartupTNotiSocForgeTest12` (Sysmon 13)
  - 08:58:12 — `reg delete ...` (le nettoyage du test) : Sysmon 1 + 4688 + Sysmon 12 `DeleteValue`
  - 09:03:21 — suppression de `StartupTNotiSocForgeTest12` (Sysmon 12)
- `SocForgeRebuildTest` : **0 résultat, ce qui est attendu**. SC-01 a été exécuté sur DC01,
  pas sur WIN01.

## Incident en cours de route

À 19:02 UTC, WIN01 a figé : le journal VirtualBox montre `AHCI#0: Port 0 reset`, ce qui
indique une réinitialisation du disque virtuel, probablement sous pression mémoire de l'hôte
(3 VM + hôte). L'horloge de l'écran de verrouillage était bloquée et la VM ne répondait plus
au ping. Après un reset, l'agent s'est reconnecté seul et a exécuté la collecte restée en
file d'attente.

## Captures

- [`docs/screenshots/velociraptor-hunt-win01-flow-completed.png`](../../docs/screenshots/velociraptor-hunt-win01-flow-completed.png) — chasse 1 terminée, client `Connected`
- [`docs/screenshots/velociraptor-hunt-win01-4104-results.png`](../../docs/screenshots/velociraptor-hunt-win01-4104-results.png) — les 4104 avec le ScriptBlock décodé
- [`docs/screenshots/misp-event2-campaign-iocs.png`](../../docs/screenshots/misp-event2-campaign-iocs.png) — événement MISP #2 publié, 5 IOC
- [`docs/screenshots/velociraptor-hunt-misp-iocs-11-hits.png`](../../docs/screenshots/velociraptor-hunt-misp-iocs-11-hits.png) — chasse 2 : `IocRegex` issu de MISP, 11 événements

## Limites

- L'orchestration MISP → Velociraptor est un script lancé depuis l'hôte (lecture de l'API
  MISP, puis appel de l'API Velociraptor). Aucune intégration native n'est configurée entre
  les deux outils.
- Le service Windows Velociraptor d'origine reste désactivé. L'agent tourne via une tâche
  planifiée SYSTEM.
- L'IOC réseau `10.10.10.60` n'est pas chassé côté endpoint. Il relève de NDR et de Wazuh.

## Résultats

| Critère | Valeur |
|---|---|
| Serveur Velociraptor joignable par les endpoints | ✅ (`10.10.10.61:8889`) |
| Agent WIN01 connecté et persistant après redémarrage | ✅ |
| Artefact laissé par un test précédent retrouvé | ✅ (4104 de SC-04) |
| IOC de campagne importés et publiés dans MISP | ✅ (événement #2, 5 IOC) |
| Chasse pilotée par les IOC MISP | ✅ (11 événements, chronologie SC-09 reconstituée) |

## Nettoyage

Aucun. L'agent reste installé sur WIN01 pour les prochaines chasses. Les événements MISP #1
et #2 restent comme référence.
