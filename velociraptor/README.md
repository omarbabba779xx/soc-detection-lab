# Velociraptor — artefacts SocForge

Serveur : VM08-DFIR-HUNT, Velociraptor 0.77.1. Détail et preuves : SC-15
(`purple-team/scenarios/scenario-dfir-velociraptor-misp-hunt.md`).

| Artefact | Type | Rôle |
|---|---|---|
| `Custom.Server.MISP.Iocs` | SERVER | Lit les IOC chassables d'un événement MISP (API REST, secret serveur) |
| `Custom.Server.MISP.IOCHunt` | SERVER | Crée une chasse EvtxHunter à partir de ces IOC, taguée `misp` / `misp-event-<id>` |
| `Custom.Server.MISP.Sightings` | SERVER_EVENT | Renvoie à MISP un sighting par IOC vu sur un endpoint |
| `Custom.Windows.EventLogs.Retention` | CLIENT | Taille et plus ancien événement de chaque journal Windows |

## Installation

1. Créer le secret dans le GUI : *Server Secrets* → *HTTP Secrets* → nom `misp_api`,
   avec les champs suivants :

   | Champ | Valeur |
   |---|---|
   | `url_regex` | `^https://10[.]10[.]10[.]22/` |
   | `skip_verify` | `TRUE` (certificat MISP auto-signé) |
   | `extra_headers` (YAML) | `Authorization: <clé API MISP>`<br>`Accept: application/json`<br>`Content-Type: application/json` |

2. Le partager avec les comptes qui lancent les artefacts **et** avec le principal du
   serveur, sous lequel tourne le monitoring :

   ```sql
   SELECT secret_modify(name='misp_api', type='HTTP Secrets',
                        add_users=['admin', 'VelociraptorServer']) FROM scope()
   ```

3. Charger les artefacts (GUI : *View Artifacts* → *Upload*, ou `artifact_set()`), puis
   activer le monitoring :

   ```sql
   SELECT add_server_monitoring(artifact='Custom.Server.MISP.Sightings') FROM scope()
   ```

## Utilisation

*Server Artifacts* → *New Collection* → `Custom.Server.MISP.IOCHunt` (paramètre
`EventId`). Les sightings arrivent dans MISP moins d'une minute après la fin du flow de
chaque client.
