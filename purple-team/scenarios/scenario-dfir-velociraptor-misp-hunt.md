# SC-15 — Étape 8 : IOC MISP et chasse Velociraptor (DFIR-HUNT)

**Sessions** : reconstruction, étape 8 — 2026-09-22 (déploiement, chasses 1 et 2) et
2026-09-23 (intégration native MISP ↔ Velociraptor)
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

## Préparation de VM08 — deux défauts corrigés et un ajout

Défauts :

1. **Carte réseau mgmt jamais configurée** : `enp0s8` (réseau `socforge-mgmt`, celui des
   endpoints) était `DOWN`, sans adresse. Aucun client ne pouvait donc joindre le serveur.
   Corrigé : `10.10.10.61/24`, persistant dans `/etc/netplan/99-socforge.yaml`.
2. **URL du frontend incorrecte** : le bloc `Client.server_urls` de la config serveur (celui
   que `velociraptor config client` recopie dans la config client) ne pointait pas vers une
   adresse joignable. Corrigé en `https://10.10.10.61:8889/`, puis config client régénérée.

Ajout :

3. **Utilisateur API** `socforge-api` (rôle administrator, `/home/socadmin/api.config.yaml`)
   pour interroger le serveur en marche via gRPC (port 8001). La commande `query` hors-ligne
   ne voit pas l'index des clients.

## Déploiement de l'agent sur WIN01

- **Intégration souris VirtualBox** : WIN01 n'a pas les Guest Additions et utilisait une
  souris PS/2 (relative). Passage en `--mouse usbtablet` avec un contrôleur `--usbxhci on`
  (pointage absolu, pilote HID natif de Windows 11). Le pilotage GUI est désormais fiable.
- Binaire et config servis depuis l'hôte (`python -m http.server`, joignable depuis la VM
  via la passerelle NAT `10.0.3.2`), puis téléchargés dans une console admin
  (`C:\V\v.exe`, `C:\V\c.yaml`).
- **Persistance** : tâche planifiée `VelociraptorAgent` (déclencheur au démarrage, compte
  SYSTEM, `C:\V\v.exe --config C:\V\c.yaml client`). Vérifiée par redémarrage sans
  ouverture de session : le client se reconnecte seul.

Client : `C.07dab9364f98e1aa` — `DESKTOP-75LAKDV.socforge.lab` — `10.10.10.110`.

### Pourquoi une tâche planifiée et pas le service Windows

`service install` a réutilisé le service `Velociraptor` créé lors de la première
réalisation du projet (04/08, voir la chronologie dans `docs/rebuild-plan.md`). Ce
service démarre mais ne se connecte jamais. Le 23/09, le problème a été reproduit en test
contrôlé, sans ouvrir de session sur WIN01, par des collectes Velociraptor :

- binaire et config du service **identiques** à ceux de l'agent qui fonctionne : même
  taille (70 375 416 et 2 661 octets), même `server_urls` (`https://10.10.10.61:8889/`),
  même fichier writeback ;
- agent de la tâche planifiée arrêté, service passé en démarrage manuel puis lancé :
  `STATE: RUNNING`, PID 4228, événement Application 1 « Starting service Velociraptor » ;
- **aucune connexion au serveur en 4 minutes**, alors que le même binaire avec la même
  config, lancé par la tâche planifiée, se connecte en quelques secondes.

La config n'est donc pas en cause. Le défaut se trouve dans le mode `service run` de cette
installation. Seule différence visible : le `ImagePath` (`Velociraptor.exe service run`)
ne passe pas de `--config`. La cause exacte à l'intérieur du mode service n'est pas
démontrée. Après le test, le service a été remis en `DISABLED`, la tâche de test et ses
fichiers ont été supprimés, et l'agent planifié est revenu après redémarrage.

## Chasse 1 — trace du test T1059 (SC-04)

Collecte `Windows.EventLogs.EvtxHunter` (flow `F.DAPCIL0FN91P4`) sur
`C:/Windows/System32/winevt/Logs/*PowerShell*.evtx`, `IocRegex=U29jRm9yZ2VSdWxlVGVzdA`,
`IdRegex=^4104$`.

**Résultat : 3 événements 4104** (17/09 17:48:09, 17:57:17, 18:05:53 UTC, `labuser`),
chacun contenant le ScriptBlock décodé `FromBase64String('U29jRm9yZ2VSdWxlVGVzdA==')`. Ils
ont été lus directement dans le `.evtx` de WIN01, indépendamment de Wazuh.

**Pourquoi trois et pas un** : la charge SC-04 a été exécutée trois fois ce jour-là. Le
premier passage (17:48) n'a pas déclenché la règle 100131, à cause du bug `if_group`
décrit dans SC-04. Il y a eu ensuite un passage pendant le diagnostic (17:57), puis le
passage final après correction (18:05:53). Pour ce dernier, `alerts.log` montre la 100131
à **18:06:08**. Les 15 s d'écart séparent la création de l'événement sur WIN01 de l'alerte
côté manager (lecture du canal par l'agent, envoi, analyse). Ce ne sont pas deux
événements différents.

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

## Chasse 2 (22/09) — pilotée par les IOC de MISP, via un script

Les attributs `text` et `regkey|value` de l'événement #2 sont lus via l'API MISP
(`/attributes/restSearch`) par un script lancé depuis l'hôte. Pour la clé de registre,
seul le nom de la valeur est gardé. Le script lance ensuite la collecte via l'API
Velociraptor (créateur `socforge-api`) avec
`IocRegex = U29jRm9yZ2VSdWxlVGVzdA|SocForgeTest12|SocForgeRebuildTest`, sur **tous** les
journaux de WIN01 (flow `F.DAPD1G4KA3HL4`, 296 s).

**Résultat : 11 événements**
- les 3 ScriptBlocks 4104 de SC-04 ;
- **la chronologie complète de la persistance SC-09, alors que la clé n'existe plus**
  (8 lignes, voir la capture de la chronologie) :
  - 18/09 08:56:49 — `reg add ...\Run /v SocForgeTest12 /d C:\Windows\System32\calc.exe`
    (Sysmon 1 + Security 4688), valeur écrite (Sysmon 13 `SetValue`)
  - 08:57:09 — Windows crée `RunNotification\StartupTNotiSocForgeTest12` (Sysmon 13)
  - 08:58:12 — `reg delete ...` (le nettoyage du test) : Sysmon 1 + 4688 + Sysmon 12 `DeleteValue`
  - 09:03:21 — suppression de `StartupTNotiSocForgeTest12` (Sysmon 12)
- `SocForgeRebuildTest` : **0 résultat, ce qui est attendu**. SC-01 a été exécuté sur DC01,
  pas sur WIN01.

Limite de cette version : l'orchestration vivait **hors** des deux outils. Elle est
remplacée par l'intégration native ci-dessous.

## Intégration native MISP ↔ Velociraptor (23/09)

Tout tourne désormais **dans le serveur Velociraptor**. Aucun script sur l'hôte, et la clé
MISP n'apparaît dans aucun artefact. Les définitions sont versionnées dans
[`velociraptor/artifacts/`](../../velociraptor/artifacts/).

| Élément | Rôle |
|---|---|
| Secret serveur `misp_api` (type *HTTP Secrets*) | URL autorisée `^https://10[.]10[.]10[.]22/`, en-tête `Authorization` MISP. Partagé avec `admin`, `socforge-api` et `VelociraptorServer`. |
| `Custom.Server.MISP.Iocs` (SERVER) | `http_client(secret='misp_api')` → `/attributes/restSearch`. Rend un motif par IOC (nom de valeur pour `regkey\|value`, caractères spéciaux échappés). |
| `Custom.Server.MISP.IOCHunt` (SERVER) | Construit l'`IocRegex` et crée une **vraie chasse** `hunt()` EvtxHunter sur les clients Windows, taguée `misp` et `misp-event-<id>`. |
| `Custom.Server.MISP.Sightings` (SERVER_EVENT, monitoring serveur) | Toutes les 60 s, pour chaque flow terminé d'une chasse `misp` pas encore traité : rapproche les lignes des IOC et ajoute **un sighting MISP par IOC vu**, avec la source `Velociraptor <hôte> (<client>) <chasse>`. |

### Déroulé réel

1. L'analyste lance `Custom.Server.MISP.IOCHunt` depuis **Server Artifacts** dans le GUI
   (compte `admin`, flow serveur `F.DAPS4N2K94VBQ`).
2. L'artefact lit les 3 IOC chassables de l'événement #2 et crée la chasse
   **`H.DAPS4NATSTMN0`** (créateur `admin`, tags `misp`/`misp-event-2`, OS Windows).
3. WIN01 exécute la chasse : **9 lignes** (voir plus bas pourquoi 9 et pas 11).
4. `Custom.Server.MISP.Sightings` voit les flows terminés et poste les sightings (HTTP 200).
5. Dans MISP, l'événement #2 affiche **4 sightings**. Les attributs `U29jRm9yZ2VSdWxlVGVzdA==`
   et `...\Run\SocForgeTest12` sont à **(2/0/0)** : un sighting par chasse sur WIN01
   (`H.DAPRHG8LC6RFA` à 11:32 et `H.DAPS4NATSTMN0` à 12:13). Les trois autres attributs
   restent à (0/0/0), ce qui est correct : ils ne concernent pas WIN01.

Plusieurs passages de 60 s ont eu lieu après les 4 sightings sans en créer d'autres : le
dédoublonnage fonctionne.

### Défauts rencontrés en construisant l'intégration

- **`System.Flow.Completion` ne voit pas les flows clients** sur ce serveur : seuls les
  flows serveur y apparaissent. Un premier monitoring fondé sur ce flux ne s'est jamais
  déclenché. Il a été remplacé par une interrogation périodique des chasses `misp`.
- **Un flow de chasse porte comme créateur le compte qui a lancé la chasse** (`admin`) et un ID de
  forme `F.<chasse>.H`, pas l'ID de la chasse.
- **`source()` lit `HuntId`/`FlowId` dans la portée de la ligne** quand on ne les passe
  pas. La relecture des résultats déjà envoyés partait donc sur `hunt_results()` (log :
  « artifact … not available in hunt »). Corrigé en nommant autrement les colonnes internes.
- **Le monitoring serveur tourne sous le principal `VelociraptorServer`** : « Permission
  Denied accessing secret misp_api » tant que le secret ne lui était pas partagé.
- Les sous-requêtes à plusieurs instructions (`{ LET …; SELECT … }`) ne renvoient rien, sans
  message d'erreur. La requête a été restructurée sans elles.

### Pourquoi 9 lignes au lieu de 11 : le journal Security a tourné

Les deux chasses MISP du 23/09 ont 40 minutes d'écart. Les 9 premières lignes sont
identiques, et seules les deux **Security 4688** de SC-09 manquent dans la seconde.
L'artefact `Custom.Windows.EventLogs.Retention` (plus ancien événement de chaque journal,
calculé comme minimum sur tous les enregistrements, car un `.evtx` est circulaire) le
confirme :

| Journal | Taille | Plus ancien événement |
|---|---|---|
| Security | 20 975 616 o (maximum par défaut, plein) | 22/09 19:10 UTC* |
| Microsoft-Windows-Sysmon/Operational | 49 Mo | 13/08 |
| Microsoft-Windows-PowerShell/Operational | 15 Mo | 13/08 |
| System | 4 Mo | 03/08 (première réalisation du projet) |

\* Horodatage écrit pendant la dérive d'horloge de WIN01 (voir Incidents). En réalité,
l'événement date du 23/09.

Les redémarrages du 23/09 ont rempli le journal Security, qui a écrasé les 4688 du 18/09.
La chronologie SC-09 reste complète grâce à Sysmon (1, 12, 13), dont le journal est plus
grand. C'est une vraie leçon DFIR : **dimensionner le journal Security**, et ne jamais
conclure « l'événement n'a pas eu lieu » sans vérifier la rétention.

## Incidents

- **22/09 19:02 UTC** — WIN01 figé, `AHCI#0: Port 0 reset` dans le journal VirtualBox,
  sous pression mémoire de l'hôte (3 VM). Corrigé ensuite par `storagectl --hostiocache on`
  sur les contrôleurs SATA de WIN01 et de MISP (MISP avait aussi figé pendant un démarrage).
- **23/09, reprise après la pause de la nuit** — les VM étaient restées allumées pendant
  la veille de l'hôte. Les horloges de VM08 et WIN01 avaient donc environ 14 h de retard
  (celle de MISP, synchronisée par NTP, était juste). Ce n'est pas un défaut du lab, mais
  une conséquence du travail en plusieurs sessions (voir la chronologie dans
  `docs/rebuild-plan.md`). VM08 a été recalée sur l'heure UTC de
  l'hôte. Pour WIN01, sans Guest Additions, un `reset` ne suffit pas : l'horloge RTC émulée
  suit le temps virtuel de la VM. Seul un arrêt complet suivi d'un démarrage l'a recalée.
- **23/09** — en 0.77.1, `Windows.System.PowerShell` et `Windows.System.CmdShell` ouvrent
  une session shell interactive. Utilisés comme « exécute cette commande », leurs flows ne
  se terminent jamais et occupent l'agent. Les diagnostics ont été faits avec de petits
  artefacts VQL (`execve`, `parse_evtx`, `glob` sur le registre) puis supprimés du serveur.

## Captures

- [`docs/screenshots/velociraptor-hunt-win01-flow-completed.png`](../../docs/screenshots/velociraptor-hunt-win01-flow-completed.png) — chasse 1 terminée, client `Connected`
- [`docs/screenshots/velociraptor-hunt-win01-4104-results.png`](../../docs/screenshots/velociraptor-hunt-win01-4104-results.png) — les 4104 avec le ScriptBlock décodé
- [`docs/screenshots/misp-event2-campaign-iocs.png`](../../docs/screenshots/misp-event2-campaign-iocs.png) — événement MISP #2 publié, 5 IOC
- [`docs/screenshots/velociraptor-hunt-misp-iocs-11-hits.png`](../../docs/screenshots/velociraptor-hunt-misp-iocs-11-hits.png) — chasse 2 : `IocRegex` issu de MISP, 11 événements
- [`docs/screenshots/velociraptor-sc09-runkey-timeline.png`](../../docs/screenshots/velociraptor-sc09-runkey-timeline.png) — chronologie SC-09 (8 lignes : `reg add` → `SetValue` → `reg delete` → `DeleteValue`), clé déjà supprimée
- [`docs/screenshots/velociraptor-misp-native-hunt-created.png`](../../docs/screenshots/velociraptor-misp-native-hunt-created.png) — chasse `H.DAPS4NATSTMN0` créée par l'artefact serveur (créateur `admin`, tags `misp`, `IocRegex` venu de MISP)
- [`docs/screenshots/velociraptor-misp-sightings-monitor.png`](../../docs/screenshots/velociraptor-misp-sightings-monitor.png) — monitoring serveur `Custom.Server.MISP.Sightings` : 4 envois, `MispStatus 200`
- [`docs/screenshots/misp-event2-sightings-from-velociraptor.png`](../../docs/screenshots/misp-event2-sightings-from-velociraptor.png) — côté MISP : sightings (2/0/0) sur les deux IOC trouvés sur WIN01

## Limites

- La remontée des sightings se fait par interrogation toutes les 60 s, pas sur événement
  (voir plus haut).
- Seuls les types `text` et `regkey|value` sont chassés sur l'endpoint. L'IOC réseau
  `10.10.10.60` relève de NDR et de Wazuh.
- Le secret `misp_api` a `skip_verify` : le certificat MISP est auto-signé.
- La chasse est lancée à la main depuis le GUI. Il n'y a pas de déclenchement automatique
  à la publication d'un événement MISP.
- Le service Windows Velociraptor d'origine reste désactivé (cause circonscrite au mode
  service, voir plus haut). L'agent tourne via une tâche planifiée SYSTEM.

## Résultats

| Critère | Valeur |
|---|---|
| Serveur Velociraptor joignable par les endpoints | ✅ (`10.10.10.61:8889`) |
| Agent WIN01 connecté et persistant après redémarrage | ✅ |
| Artefact laissé par un test précédent retrouvé | ✅ (4104 de SC-04, chronologie SC-09) |
| IOC de campagne importés et publiés dans MISP | ✅ (événement #2, 5 IOC) |
| Chasse pilotée par les IOC MISP, depuis Velociraptor | ✅ (`Custom.Server.MISP.IOCHunt`, secret serveur) |
| Retour Velociraptor → MISP | ✅ (4 sightings, sans doublon) |

## Nettoyage

Aucun pour l'intégration : les artefacts `Custom.Server.MISP.*` restent installés et le
monitoring `Custom.Server.MISP.Sightings` reste actif. Les artefacts de diagnostic
`Custom.Diag.*` ont été supprimés du serveur. Sur WIN01, le service de test a été remis
en `DISABLED`, la tâche `SvcTest` et ses fichiers ont été supprimés. Les événements MISP
#1 et #2 restent comme référence.
