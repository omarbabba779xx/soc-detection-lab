# SC-13 : Étape 6 : TheHive + Cortex depuis l'alerte Wazuh 100155

Session : Reconstruction, étape 6, 2026-09-18
Objectif : Créer un cas depuis une alerte Wazuh, lancer un analyseur Cortex
(conformément au plan de reconstruction).

---

## Bug n°1 : VM03-THEHIVE ne démarrait pas (même crash noyau que VM07-NDR)

Même symptôme que NDR : crash noyau complet en boucle sur `raid6: avx2x4`, causé par
`CPUProfile: host` + `Effective Paravirt. Prov.: KVM`. Corrigé par :
```
VBoxManage modifyvm SF-VM03-THEHIVE --paravirtprovider legacy
```
Après ce correctif, le démarrage se termine normalement et le conteneur Docker
`thehive-thehive-1` (TheHive 5.4.7-1, stockage embarqué BerkeleyDB + Lucene, sans
Cassandra/Elasticsearch séparés) répond en HTTP 200 sur le port 9000.

## Bug n°2 (réel, mais logiciel : pas une erreur de configuration) : Licence TheHive invalide bloque la gestion de cas

Le bandeau `Your license is invalid` visible dans l'interface n'est pas cosmétique :
toute opération d'écriture liée aux cas et observables est bloquée par la licence,
quel que soit le compte utilisé :

| Compte                     | Profil     | Permissions listées                  | Résultat `POST /case` |
|-----------------------------|------------|----------------------------------------|--------------------------|
| `admin@socforge.local`      | admin (plateforme) | `manageUser`, `managePlatform`, etc. | 403 (normal, profil plateforme, pas cas) |
| `soar-bot@socforge.local`   | analyst (Service) | `manageAlert/create`, `manageKnowledgeBase` seulement | 403 |
| `soc@socforge.local`        | analyst (Normal, toutes permissions listées incl. `manageCase/create`) | 25 permissions | 403 quand même |

Tentative de créer un utilisateur supplémentaire avec profil `org-admin` : bloquée par
`LicenseLimitExceeded` (`Capability(users.normal) (2/0)`, quota de comptes "normal"
déjà dépassé). Confirmé par un test direct sur `POST /case/{id}/observable` sur un cas
existant (parmi les 7 cas de démo "Phishing" préchargés) : même 403, prouvant que
ce n'est pas spécifique à la création de cas mais un blocage général de licence sur
toutes les opérations d'écriture de gestion de cas.

Ce qui fonctionne malgré la licence invalide : la création d'alertes (`POST
/api/v1/alert`), utilisée par l'intégration SIEM externe (Wazuh → TheHive), n'est PAS
soumise à cette restriction, testé avec succès (`201 Created`).

Cause exacte, établie le 2026-09-23 : `GET /api/v1/license/current` renvoie
`"id": "no-license", "plan": "No", "capabilities": []`. La licence d'essai installée en
août (phase 1 du projet) a expiré, et l'instance n'a plus aucune capacité de gestion de
cas. Depuis TheHive 5.3, même l'édition Community gratuite demande une clé, obtenue en
s'inscrivant sur le portail StrangeBee. Licence obtenue et activée le 24/09 : la
promotion alerte → cas est validée (cas #8 et #9, voir SC-14).

## Alerte créée depuis Wazuh (rule 100155)

> Test manuel du 18/09, qui vérifie le format de l'alerte. Depuis le 23/09, les alertes
> Wazuh de niveau ≥ 10 arrivent automatiquement dans TheHive (intégration native
> Wazuh → webhook Shuffle → `POST /api/v1/alert`), voir SC-14.

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

Capture (liste des alertes TheHive, notre alerte en tête) :
[`docs/screenshots/thehive-alert-rule100155.png`](../../docs/screenshots/thehive-alert-rule100155.png)

## Cortex : analyseur exécuté avec succès

Un seul analyseur est configuré (`MISP_SocForge`, interroge un serveur MISP à
`10.10.10.22`). Exécuté sur l'IP de WIN01 :

```
POST /api/analyzer/421b31691f33f5ce93618c5bbec4bf51/run
{"data": "10.10.10.110", "dataType": "ip", "tlp": 2, "message": "WIN01 - source injection T1055 (rule 100155)"}
-> 200, job_id: ZR1XtqABzK3jl9cg45ui, status: Waiting -> InProgress
```

Rapport final : `status: Failure`, erreur `No route to host` vers `10.10.10.22:443`.
Ce n'est pas un bug : VM05-MISP n'est pas démarrée à ce stade du plan (elle est
prévue à l'étape 8, avec DFIR-HUNT). Le pipeline Cortex lui-même (soumission de job,
exécution du script Python de l'analyseur, remontée du résultat) fonctionne de bout en
bout, la panne est une dépendance externe attendue, pas un défaut de Cortex.

## Résultats

| Critère                          | Valeur                                       |
|------------------------------------|-------------------------------------------------|
| VM03-THEHIVE démarre                | validé OUI (après fix paravirt provider)            |
| Alerte créée depuis Wazuh           | validé OUI (201, via API bot SOAR)                  |
| Cas créé depuis l'alerte            | validé OUI le 24/09, après activation d'une licence StrangeBee : cas #8 et #9 depuis des alertes Wazuh automatiques (voir SC-14) |
| Analyseur Cortex exécuté            | validé OUI (job soumis et traité)                    |
| Résultat de l'analyseur             | Échec attendu ici (MISP hors ligne) ; succès avec corrélation MISP réelle à l'étape 7 (SC-14) |

## Nettoyage

Aucun artefact de test à nettoyer (alerte et job de test peuvent rester comme preuve).
