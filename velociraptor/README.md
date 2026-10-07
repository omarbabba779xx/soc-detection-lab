# Velociraptor : artefacts SocForge

Serveur : VM08-DFIR-HUNT, Velociraptor 0.77.1. Détail et preuves : SC-15
(`purple-team/scenarios/SC-15-dfir-velociraptor-misp-hunt.md`).

| Artefact | Type | Rôle |
|---|---|---|
| `Custom.Server.MISP.Iocs` | SERVER | Lit les IOC chassables d'un événement MISP (API REST, secret serveur) |
| `Custom.Server.MISP.IOCHunt` | SERVER | Crée une chasse EvtxHunter à partir de ces IOC, taguée `misp` / `misp-event-<id>` |
| `Custom.Server.MISP.Sightings` | SERVER_EVENT | À la fin de chaque flow d'une chasse `misp`, renvoie à MISP un sighting par IOC vu sur l'endpoint |
| `Custom.Server.MISP.AutoHunt` | SERVER_EVENT | Lance `IOCHunt` tout seul à chaque publication d'un événement MISP |
| `Custom.Windows.EventLogs.Retention` | CLIENT | Taille maximale, taille actuelle et plus ancien événement de chaque journal Windows |

## Installation

1. Créer le secret dans le GUI : *Server Secrets* → *HTTP Secrets* → nom `misp_api`,
   avec les champs suivants :

   | Champ | Valeur |
   |---|---|
   | `url_regex` | `^https://10[.]10[.]10[.]22/` |
   | `root_ca` | contenu de [`pki/socforge-lab-ca.crt`](../pki/socforge-lab-ca.crt) |
   | `skip_verify` | `FALSE` (MISP présente un certificat signé par la CA du lab) |
   | `extra_headers` (YAML) | `Authorization: <clé API MISP>`<br>`Accept: application/json`<br>`Content-Type: application/json` |

2. Le partager avec les comptes qui lancent les artefacts et avec le principal du
   serveur, sous lequel tourne le monitoring :

   ```sql
   SELECT secret_modify(name='misp_api', type='HTTP Secrets',
                        add_users=['admin', 'VelociraptorServer']) FROM scope()
   ```

3. Charger les artefacts (GUI : *View Artifacts* → *Upload*, ou `artifact_set()`), puis
   activer le monitoring :

   ```sql
   SELECT add_server_monitoring(artifact='Custom.Server.MISP.Sightings'),
          add_server_monitoring(artifact='Custom.Server.MISP.AutoHunt') FROM scope()
   ```

   Après une mise à jour d'un de ces artefacts, le retirer (`rm_server_monitoring`) puis le
   rajouter : le monitoring garde sinon l'ancienne définition.

## Utilisation

Publier un événement dans MISP suffit : `AutoHunt` crée la chasse (créateur
`VelociraptorServer`, tags `misp` / `misp-event-<id>`) à sa vérification suivante, et
`Sightings` envoie les sightings à la fin du flow de chaque client. La chasse peut
toujours être lancée à la main : *Server Artifacts* → *New Collection* →
`Custom.Server.MISP.IOCHunt` (paramètre `EventId`).
