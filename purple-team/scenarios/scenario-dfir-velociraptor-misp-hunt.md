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
- **Persistance** : service Windows `Velociraptor` (démarrage automatique, compte SYSTEM,
  redémarrage automatique en cas d'échec). Vérifiée par redémarrage sans ouverture de
  session (voir ci-dessous).

Client : `C.07dab9364f98e1aa` — `DESKTOP-75LAKDV.socforge.lab` — `10.10.10.110`.

### Le service qui ne se connectait jamais : cause et correction

`service install` avait réutilisé le service `Velociraptor` créé lors de la première
réalisation du projet (04/08, voir la chronologie dans `docs/rebuild-plan.md`). Ce
service démarrait mais ne se connectait jamais. En attendant la cause, l'agent a d'abord
tourné via une tâche planifiée SYSTEM (`C:\V\v.exe --config C:\V\c.yaml client`).

Un premier test contrôlé, dans l'après-midi du 23/09, avait écarté le fichier de config :
binaire et config de même taille que ceux de l'agent qui fonctionnait (70 375 416 et
2 661 octets ; empreinte SHA-256 des deux configs identique, vérifiée le soir), service `RUNNING`, mais
aucune connexion en 4 minutes. Seule différence : le `ImagePath` du
service (`Velociraptor.exe service run`) ne passe pas de `--config`.

**Cause démontrée le soir du 23/09**, par une comparaison A/B sur le même binaire :

| Lancement | Config chargée | `server_urls` |
|---|---|---|
| sans `--config` (comme le service) | config **par défaut** du binaire | `https://localhost:8000/` |
| avec `--config ...\Velociraptor.config.yaml` | config du lab | `https://10.10.10.61:8889/` |

Sans `--config`, le service ne lit jamais le fichier posé à côté de lui : il utilise la
config par défaut et contacte `localhost:8000`, c'est-à-dire WIN01 elle-même. Il tourne
donc normalement, mais ne peut jamais atteindre le serveur.

**Correction** : `ImagePath` =
`"C:\Program Files\Velociraptor\Velociraptor.exe" --config "C:\Program Files\Velociraptor\Velociraptor.config.yaml" service run`,
démarrage `Automatic`, redémarrage automatique sur échec (`sc failure`, 3 × 60 s). Au
lancement, connexion TCP établie vers `10.10.10.61:8889` et même client
(`C.07dab9364f98e1aa`, même fichier writeback) vu par le serveur à 22:22:55.

**Preuve de persistance** (tâche planifiée désactivée, redémarrage ordonné à 22:23:33),
collectée par le service lui-même :

| Point vérifié | Valeur |
|---|---|
| Démarrage de WIN01 | 22:25:13 UTC |
| Session interactive | aucune (`No User exists`) |
| Service | `Running` / `Auto`, PID 3724, lancé à 22:27:38 |
| Tâche planifiée | `Disabled` |
| Connexion au serveur | port local 49673 → `10.10.10.61`, ouverte par le PID 3724 ; le serveur voit le client depuis `10.10.10.110:49673` à 22:28:18 |

La tâche planifiée et son dossier `C:\V` ont ensuite été supprimés : il ne reste aucune
trace du contournement.

Une première tentative de correction par `sc.exe config ... binPath=` lancée à distance
n'avait rien modifié. Le redémarrage qui la suivait avait coupé la sortie de la commande,
et WIN01 s'était retrouvée sans agent. La correction a été refaite par
`Set-ItemProperty` sur `ImagePath` et `Set-Service`, avec vérification de l'état **avant**
de redémarrer.

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
| `Custom.Server.MISP.Sightings` (SERVER_EVENT, monitoring serveur) | Réagit à chaque fin de flow d'une chasse `misp` (`System.Flow.Completion`) : rapproche les lignes des IOC et ajoute **un sighting MISP par IOC vu**, avec la source `Velociraptor <hôte> (<client>) <chasse>`. Au démarrage, rattrape les flows terminés pendant une coupure. (Version du 23/09 : interrogation toutes les 60 s.) |
| `Custom.Server.MISP.AutoHunt` (SERVER_EVENT, monitoring serveur, 24/09) | Détecte chaque publication d'événement MISP et lance `IOCHunt` sans analyste. Une publication = une clé (id, `publish_timestamp`) : pas de doublon, et une republication relance la chasse. |

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

- **Un premier monitoring fondé sur `System.Flow.Completion` ne s'est jamais déclenché.**
  Conclusion tirée le 23/09 : ce flux ne verrait pas les flows clients. Elle était
  **fausse**, et a été corrigée le 24/09 par un observateur branché sur ce flux : une
  collecte directe (`F.DAQFSBIPA9DCM`) et un flow de chasse (`F.DAQFTI2NLAAMC.H`) y
  apparaissent, 2 s après leur fin. En revanche, dans ces événements, `Flow.request` est
  **vide** : un filtre sur les artefacts demandés ne correspond donc jamais. C'est
  exactement le défaut retrouvé le 24/09 dans la nouvelle version, et très probablement
  celui du 23/09. Le filtre utilise désormais `Flow.artifacts_with_results`.
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

**Appliqué le 24/09**, sur WIN01 et sur DC01 (voir plus bas).

## Incidents

- **22/09 19:02 UTC** — WIN01 figé, `AHCI#0: Port 0 reset` dans le journal VirtualBox,
  sous pression mémoire de l'hôte (3 VM). Corrigé ensuite par `storagectl --hostiocache on`
  sur les contrôleurs SATA de WIN01 et de MISP (MISP avait aussi figé pendant un démarrage).
  Cause de fond trouvée le 24/09 : VirtualBox tournait par-dessus l'hyperviseur Windows
  (mode de repli NEM, faiblesse 26 du plan de reconstruction), corrigée depuis.
- **23/09 23:54 UTC** — l'agent de WIN01 a disparu pendant une collecte. Ce n'était pas
  l'agent, mais un écran bleu de WIN01 (0xA, même cause de fond). Le même artefact rejoué
  deux fois le 24/09 n'a rien provoqué.
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
- [`docs/screenshots/velociraptor-autohunt-hunts.png`](../../docs/screenshots/velociraptor-autohunt-hunts.png) — chasses du 24/09 créées par `VelociraptorServer` (automatiques), à côté de celles du 23/09 créées par `admin`
- [`docs/screenshots/misp-event3-autohunt-sightings.png`](../../docs/screenshots/misp-event3-autohunt-sightings.png) — événement MISP #3 publié, 2 sightings renvoyés par les chasses automatiques

## Chasse et sightings automatiques (24/09)

Les deux limites du 23/09 sont levées : la chasse était lancée à la main, et les sightings
remontaient par interrogation toutes les 60 s.

Test de bout en bout, sans aucune action manuelle dans la chaîne. Trace bénigne et unique
générée sur WIN01 : `cmd.exe /c echo SocForge-AutoHunt-241046-9CF558`, enregistrée en
Security 4688 à 10:46:42. Puis événement MISP #3 avec ce marqueur comme IOC `text`.

| Heure (UTC) | Maillon |
|---|---|
| 10:47:35 | MISP : événement #3 publié |
| 10:48:15 | `AutoHunt` crée la chasse **`H.DAQFVRQUQLMJ2`**, créateur **`VelociraptorServer`**, tags `misp`, `misp-event-3` |
| 10:48:26 → 10:50:25 | WIN01 exécute la chasse : 3 lignes |
| 11:04:08 | sighting MISP (au redémarrage corrigé de `Sightings`, par le rattrapage) |
| 11:05:06 | événement #3 republié → nouvelle chasse **`H.DAQG7PIM1PVAQ`** 4 s plus tard |
| 11:07:14 | fin du flow de chasse **et** sighting MISP dans la même seconde (déclenchement par événement) |

Deux publications, exactement deux chasses, alors qu'`AutoHunt` a interrogé MISP chaque
minute : pas de doublon, y compris après un redémarrage d'`AutoHunt`. Le rattrapage a
aussi été vérifié : la version d'abord déployée de `Sightings` filtrait sur
`Flow.request` (vide) et n'a rien envoyé pour la première chasse ; au redémarrage de la
version corrigée, elle a été reprise et signalée.

**DC01 de retour dans Velociraptor.** Son agent était hors ligne depuis le 10/08 : sa
config visait l'ancienne adresse du serveur (`10.10.10.60`). Config du serveur déployée
(même SHA-256 que WIN01), `--config` ajouté au service ; client `C.c6b3dab429088216`
reconnecté à 11:50:15 et collectes acceptées. Les chasses MISP couvrent désormais les deux
postes Windows, dont DC01, où a été exécuté SC-01.

**Journaux dimensionnés** (mesurés par `Custom.Windows.EventLogs.Retention`, qui affiche
désormais la taille maximale) :

| Journal | WIN01 avant → après | DC01 avant → après |
|---|---|---|
| Security | 20 Mo, plein, moins de 30 h d'historique → **512 Mo** | 128 Mo, plein → **1 Go** |
| Sysmon/Operational | taille d'origine non relevée → **256 Mo** | 64 Mo → **256 Mo** |
| PowerShell/Operational | fichier de 15 Mo (plein) → **256 Mo** | 15 Mo, plein, **quelques minutes** d'historique → **256 Mo** |
| System | taille d'origine non relevée → **128 Mo** | 20 Mo → **128 Mo** |

Sur WIN01, le nombre d'événements Security est passé de 22 961 à 23 634 alors que le plus
ancien est resté le même : le journal ne s'écrase plus.

**Délai de récupération des tâches** : le 23/09, juste après le démarrage de WIN01,
l'agent (alors lancé par la tâche planifiée) a mis environ 10 min à prendre ses premières
collectes. Non reproduit avec le service : collecte prise en 1 à 2 s, que ce soit juste
après le démarrage ou 10 min plus tard. La configuration concernée n'existe plus.

## Périmètre

- Seuls les types `text` et `regkey|value` sont chassés sur l'endpoint. L'IOC réseau
  `10.10.10.60` relève de NDR et de Wazuh.
- `AutoHunt` apprend les publications en interrogeant MISP toutes les 60 s : MISP ne
  peut pas appeler Velociraptor. Aucune action humaine n'est nécessaire.

## Résultats

| Critère | Valeur |
|---|---|
| Serveur Velociraptor joignable par les endpoints | ✅ (`10.10.10.61:8889`) |
| Agent WIN01 connecté et persistant après redémarrage | ✅ (service Windows, sans session ouverte) |
| Artefact laissé par un test précédent retrouvé | ✅ (4104 de SC-04, chronologie SC-09) |
| IOC de campagne importés et publiés dans MISP | ✅ (événement #2, 5 IOC) |
| Chasse pilotée par les IOC MISP, depuis Velociraptor | ✅ (`Custom.Server.MISP.IOCHunt`, secret serveur) |
| Retour Velociraptor → MISP | ✅ (4 sightings, sans doublon) |
| Chasse lancée automatiquement à la publication MISP | ✅ (créateur `VelociraptorServer`, sans doublon) |
| Sightings déclenchés par la fin de la chasse | ✅ (même seconde que la fin du flow) |
| Agent DC01 connecté | ✅ (hors ligne depuis le 10/08, corrigé) |
| Journaux Windows dimensionnés pour la DFIR | ✅ (WIN01 et DC01) |

## TLS vérifié entre Velociraptor et MISP (24/09)

Le secret `misp_api` avait `skip_verify` : MISP présentait un certificat auto-signé
(émetteur = sujet = `10.10.10.22`). Une CA interne a été créée (`pki/make_certs.py`,
certificat public `pki/socforge-lab-ca.crt`, clés privées hors dépôt). MISP présente
désormais `CN=misp.socforge.lab`, SAN `DNS:misp.socforge.lab, IP:10.10.10.22`, signé par
`SocForge Lab CA`. Le certificat est installé dans le conteneur par
`/home/socadmin/misp/ssl/install-cert.sh` (à rejouer si le conteneur est recréé), et
l'ancien est gardé en `.selfsigned-20260807`.

Le secret a été recréé avec `root_ca` (la CA du lab) et `skip_verify: FALSE`. Vérifié
depuis VM08 :

| Test | Résultat |
|---|---|
| `curl --cacert socforge-lab-ca.crt https://10.10.10.22/` | `HTTP 200`, `ssl_verify_result=0` |
| `curl` sans la CA | refus : `self-signed certificate in certificate chain` |
| `http_client(secret='misp_api')` | `200` ; `Custom.Server.MISP.Iocs` lit les 3 IOC de l'événement #2 |
| même appel avec un secret de test **sans** `root_ca` | `500` : `x509: certificate signed by unknown authority` (secret supprimé ensuite) |

## Nettoyage

Aucun pour l'intégration : les artefacts `Custom.Server.MISP.*` restent installés et le
monitoring `Custom.Server.MISP.Sightings` reste actif. Les artefacts de diagnostic
`Custom.Diag.*` ont été supprimés du serveur. Sur WIN01, la tâche de test `SvcTest`, puis
la tâche `VelociraptorAgent` et son dossier `C:\V`, ont été supprimées ; seul le service
reste. Les événements MISP #1 et #2 restent comme référence.
