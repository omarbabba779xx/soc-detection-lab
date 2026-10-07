# SC-09 : T1547.001, persistance par clé Run

| | |
|---|---|
| Date | 2026-09-18 (reconstruction, étape 4) |
| Lancé depuis | console locale de WIN01, compte `labuser`, invite élevée |
| Cible | WIN01 (agent Wazuh 005) |
| Technique MITRE | T1547.001, Boot or Logon Autostart Execution: Registry Run Keys |
| Tactique | Persistence |
| Résultat | détecté, règle 100147 (niveau 9), après trois corrections |

## Objectif

Vérifier la détection d'une persistance par clé de registre `Run`, l'une des façons les plus courantes de survivre
à un redémarrage.

## Test

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v SocForgeTest12 /t REG_SZ /d C:\Windows\System32\calc.exe /f
```

Réponse de Windows : `The operation completed successfully.`

## Détection

| Règle | Niveau | Source | Rôle |
|---|---|---|---|
| 100147 | 9 | Sysmon 13 | écriture d'une valeur sous une clé `Run` |

```
Rule: 100147 (level 9) -> 'Sigma T1547.001: Registry autostart persistence — HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SocForgeTest12'
```

Capture (tableau de bord Wazuh, 2 correspondances) :
[`wazuh-dashboard-rule-100147-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100147-live.png)

## Historique : trois causes, dans l'ordre où elles ont été trouvées

C'est la règle qui a demandé le plus de recherche pendant la reconstruction.

1. Un nom de groupe faux. La règle citait `sysmon_event13,sysmon_event14` : sans tiret bas, et avec une
   virgule comme séparateur. Ce groupe n'existe pas. Corrigé en `sysmon_event_13|sysmon_event_14`.
2. Une fausse piste, mais un vrai défaut. Le scan d'intégrité de WIN01 restait bloqué (`wazuh-agent.exe` à
   0 % de processeur). Des fichiers `.gz` orphelins dans `queue\diff\file\`, laissés par des redémarrages forcés
   du service, bloquaient tout renommage (`ERROR (1124): Could not rename ... File exists`). Ils ont été
   supprimés. Cela n'a rien changé pour 100147 : cette règle dépend de Sysmon, pas du scan d'intégrité. Le défaut
   était réel, mais ce n'était pas la cause cherchée.
3. La cause. `<if_group>sysmon_event_13</if_group>` ne déclenchait pas cette règle, alors que le groupe était
   correct : la règle officielle 92300, qui en dépend, sonnait sur le même événement. Une comparaison l'a
   confirmé : une règle d'essai rattachée par `<if_sid>92300</if_sid>` sonnait aussitôt, la même avec `<if_group>`
   jamais. La règle 100147 est maintenant rattachée directement à `<if_sid>92300</if_sid>`.

En cours de route, `wazuh-db` (un service interne du manager) s'est arrêté
(`Unable to connect to socket 'queue/db/wdb'`), probablement à cause du manque de mémoire sur l'hôte. Un
redémarrage complet du manager l'a rétabli.

## Résultats

| Critère | Valeur |
|---|---|
| Détecté | oui |
| Règle | 100147 |
| Verdict | vrai positif |
| Source | WIN01, console locale |

## Lecture côté défense

La règle `100147` hérite son périmètre de la règle officielle `92300` : les clés `CurrentVersion\Run` et leurs
variantes 32 bits. Les autres emplacements de démarrage automatique relèvent d'autres règles.

L'intérêt de Sysmon se voit dans SC-15 : la chronologie complète (écriture puis suppression de la valeur) a été
retrouvée dans son journal alors que la clé n'existait plus et que le journal Security avait déjà tourné.

Le test est lancé sur la console de WIN01.

## Nettoyage

Douze valeurs de test (`SocForgeTest1` à `SocForgeTest12`, créées au fil des essais) supprimées par une boucle.
