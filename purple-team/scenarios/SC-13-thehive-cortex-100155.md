# SC-13 : TheHive et Cortex depuis une alerte Wazuh

| | |
|---|---|
| Date | 2026-09-18 (reconstruction, étape 6) |
| Objectif du plan | créer un cas depuis une alerte Wazuh et lancer un analyseur Cortex |
| Résultat | alerte créée dans TheHive, analyseur Cortex exécuté ; création de cas débloquée le 24/09 |

Cette fiche décrit le premier raccordement, fait à la main. Depuis le 23/09, les alertes Wazuh de niveau 10 ou
plus arrivent seules dans TheHive : voir SC-14.

## Deux obstacles levés en chemin

### VM03-THEHIVE ne démarrait pas

Même symptôme que la sonde NDR (SC-12) : arrêt du noyau en boucle sur `raid6: avx2x4`, causé par la combinaison
`CPUProfile: host` et `Effective Paravirt. Prov.: KVM`. Corrigé par :

```
VBoxManage modifyvm SF-VM03-THEHIVE --paravirtprovider legacy
```

Le démarrage se termine ensuite normalement. Le conteneur `thehive-thehive-1` (TheHive 5.4.7-1, stockage embarqué
BerkeleyDB et Lucene) répond sur le port 9000.

### Une licence invalide bloquait la gestion de cas

Le bandeau `Your license is invalid` de l'interface n'était pas décoratif : toute écriture sur un cas ou un
observable était refusée, quel que soit le compte.

| Compte | Profil | Permissions | `POST /case` |
|---|---|---|---|
| `admin@socforge.local` | admin (plateforme) | `manageUser`, `managePlatform`, etc. | 403 (attendu : profil de plateforme, sans droit sur les cas) |
| `soar-bot@socforge.local` | analyst (compte de service) | `manageAlert/create`, `manageKnowledgeBase` | 403 |
| `soc@socforge.local` | analyst (25 permissions, dont `manageCase/create`) | 25 permissions | 403 aussi |

La création d'un utilisateur `org-admin` supplémentaire échouait avec `LicenseLimitExceeded`
(`Capability(users.normal) (2/0)`). Un essai de `POST /case/{id}/observable` sur un cas de démonstration existant
donnait le même 403 : le blocage ne tenait pas à la création de cas, mais à toutes les écritures de gestion de
cas.

Ce qui fonctionnait malgré tout : la création d'alertes (`POST /api/v1/alert`), utilisée par le raccordement au
SIEM. Testée avec succès (`201 Created`).

La cause a été établie le 23/09 : `GET /api/v1/license/current` renvoyait
`"id": "no-license", "plan": "No", "capabilities": []`. La licence d'essai installée en août avait expiré. Depuis
TheHive 5.3, même l'édition Community demande une clé, obtenue sur le portail StrangeBee. Une licence a été
activée le 24/09, et le passage d'une alerte à un cas est validé (cas #8 et #9, voir SC-14).

## Alerte créée depuis Wazuh (règle 100155)

Test manuel, qui vérifie le format de l'alerte :

```
POST /api/v1/alert (auth: soar-bot@socforge.local bearer key)
{
  "type": "wazuh", "source": "wazuh-manager", "sourceRef": "rule-100155",
  "title": "T1055 Process Injection - WIN01",
  "description": "Wazuh rule 100155 (level 13): CreateRemoteThread powershell.exe -> Notepad.exe",
  "severity": 3, "tlp": 2, "pap": 2, "tags": ["T1055","wazuh","win01"]
}
-> 201 Created, _id: ~122884296
```

Capture (liste des alertes TheHive, l'alerte en tête) :
[`thehive-alert-rule100155.png`](../../docs/screenshots/thehive-alert-rule100155.png)

## Analyseur Cortex

Un seul analyseur est configuré : `MISP_SocForge`, qui interroge le serveur MISP (`10.10.10.22`). Lancé sur
l'adresse de WIN01 :

```
POST /api/analyzer/421b31691f33f5ce93618c5bbec4bf51/run
{"data": "10.10.10.110", "dataType": "ip", "tlp": 2, "message": "WIN01 - source injection T1055 (rule 100155)"}
-> 200, job_id: ZR1XtqABzK3jl9cg45ui, status: Waiting -> InProgress
```

Rapport final : `status: Failure`, erreur `No route to host` vers `10.10.10.22:443`. C'est attendu à cette étape :
la VM MISP n'était pas démarrée, elle n'entre dans le plan qu'à l'étape 8. Le circuit Cortex lui-même fonctionne :
la tâche est soumise, le script de l'analyseur s'exécute, le résultat remonte. L'analyse réussit avec une vraie
correspondance MISP à l'étape suivante (SC-14).

## Résultats

| Critère | Valeur |
|---|---|
| VM03-THEHIVE démarre | oui, après le changement de fournisseur de paravirtualisation |
| Alerte créée depuis Wazuh | oui (201, par le compte de service) |
| Cas créé depuis l'alerte | oui le 24/09, après activation de la licence : cas #8 et #9 (voir SC-14) |
| Analyseur Cortex exécuté | oui (tâche soumise et traitée) |
| Résultat de l'analyseur | échec attendu ici (MISP éteint) ; succès avec correspondance MISP dans SC-14 |

## Nettoyage

Rien à retirer : l'alerte et la tâche de test restent comme preuve.
