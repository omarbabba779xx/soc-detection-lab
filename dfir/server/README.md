# Accès du SOAR à Velociraptor

Shuffle et les scripts de `dfir/` interrogent Velociraptor par SSH, avec un compte qui ne
peut rien faire d'autre qu'envoyer une requête VQL.

| Élément | Réglage sur VM08-DFIR-HUNT |
|---|---|
| Compte système | `soar`, mot de passe verrouillé (`passwd -l`), connexion par clé uniquement |
| Clé SSH | ed25519, dédiée ; la clé privée reste hors du dépôt |
| Commande imposée | `command="/usr/local/bin/soar-vql",restrict` dans `authorized_keys` : quelle que soit la commande demandée, seul [`soar-vql.sh`](soar-vql.sh) s'exécute, sans terminal ni redirection de port |
| Utilisateur d'API | `soar-api`, rôles `investigator` et `api`, plus les permissions `execve` et `network` exigées par les artefacts de quarantaine |
| Fichier d'API | `/etc/velociraptor/soar.api.config.yaml`, lisible par `soar` seul |
| Empreinte du serveur | vérifiée par le client (`known_hosts`) ; une clé inconnue interrompt la connexion |

## Mise en place

```sh
useradd -m -s /bin/sh soar && passwd -l soar
install -m 755 soar-vql.sh /usr/local/bin/soar-vql
install -d -m 700 -o soar -g soar /home/soar/.ssh
echo 'command="/usr/local/bin/soar-vql",restrict ssh-ed25519 AAAA... soar@shuffle' \
    > /home/soar/.ssh/authorized_keys

velociraptor --config server.config.yaml config api_client \
    --name soar-api --role investigator,api /etc/velociraptor/soar.api.config.yaml
chown soar:soar /etc/velociraptor/soar.api.config.yaml && chmod 600 /etc/velociraptor/soar.api.config.yaml
```

Puis, depuis un compte administrateur de Velociraptor :

```sql
SELECT user_grant(user='soar-api', roles=['investigator', 'api'],
                  policy=dict(roles=['investigator', 'api'], execve=TRUE, network=TRUE))
FROM scope()
```

## Actifs protégés

Un client qui porte le label `no-auto-quarantine` n'est jamais isolé par la chaîne SOAR
(`soar/nodes/quarantine_host.py`) : l'alerte reçoit le tag `quarantine:approval-required`
et la décision revient à un analyste. Le contrôleur de domaine porte ce label :

```sql
SELECT label(client_id='C.c6b3dab429088216', labels=['no-auto-quarantine'], op='set')
FROM scope()
```

## Vérification (06/10)

- `ssh soar@<serveur> 'id; cat /etc/shadow'` n'exécute ni `id` ni `cat` : la commande
  imposée lit l'entrée standard et rend le résultat d'une requête VQL, rien d'autre.
- Sans les permissions `execve` et `network`, `collect_client` sur un artefact de
  quarantaine est refusé (`PermissionDenied`) : elles sont accordées à `soar-api` seul.
