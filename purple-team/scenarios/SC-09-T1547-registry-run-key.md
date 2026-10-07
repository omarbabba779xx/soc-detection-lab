# SC-09 : T1547.001, persistance par clé Run

Session : Reconstruction, étape 4, 2026-09-18
Attaquant : WIN01, console locale (`labuser`, cmd élevé)
Cible : WIN01 (agent Wazuh ID 005)
MITRE : T1547.001, Boot or Logon Autostart Execution: Registry Run Keys
Tactique : Persistence

---

## Objectif

Valider la détection d'une persistance classique par clé de registre `Run`, technique
la plus courante après un accès initial pour survivre à un redémarrage.

## Commande exécutée

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v SocForgeTest12 /t REG_SZ /d C:\Windows\System32\calc.exe /f
```

Résultat : `The operation completed successfully.`

## Détection Wazuh

| Règle  | Niveau | Source              | Rôle                                    |
|--------|--------|----------------------|-------------------------------------------|
| 100147 | 9      | Sysmon EventID 13     | Écriture d'une clé Run/Winlogon\Shell     |

Testé en direct le 2026-09-18 :

```
Rule: 100147 (level 9) -> 'Sigma T1547.001: Registry autostart persistence — HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SocForgeTest12'
```

Capture (dashboard Wazuh, 2 correspondances) :
[`docs/screenshots/wazuh-dashboard-rule-100147-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100147-live.png)

## Historique de l'investigation (trois bugs distincts trouvés et corrigés)

Cette règle a nécessité l'investigation la plus longue de toute la reconstruction, avec
trois causes distinctes découvertes et corrigées dans l'ordre :

1. Groupe mal nommé : `sysmon_event13,sysmon_event14` (sans underscore, virgule comme
   séparateur), n'existait pas. Corrigé en `sysmon_event_13|sysmon_event_14`.
2. Faux départ, un vrai bug d'infrastructure, mais pas la cause du problème : le
   scan FIM sur WIN01 restait bloqué "in progress" indéfiniment (`wazuh-agent.exe` à 0%
   CPU en continu). Root cause : des fichiers `.gz` orphelins dans `queue\diff\file\`,
   laissés par des redémarrages forcés antérieurs du service pendant qu'un scan tournait,
   bloquant tout renommage FIM (`ERROR (1124): Could not rename ... File exists`).
   Nettoyé. Cette piste s'est révélée être une fausse route : 100147 dépend en fait de
   Sysmon (EventID 13), pas du module FIM/syscheck, le scan FIM n'a jamais été le
   problème réel, seulement un incident parallèle et bien réel.
3. Root cause véritable : `<if_group>sysmon_event_13</if_group>` ne déclenchait pas
   cette règle custom précise, alors que le groupe était correctement tagué (la règle
   officielle 92300, qui en dépend, matchait sur le même événement). Confirmé par test
   A/B avec une règle de debug : chaînée sur `<if_sid>92300</if_sid>`, elle matchait
   immédiatement ; la même règle avec `<if_group>` ne matchait jamais. Corrigé en
   chaînant 100147 directement sur `<if_sid>92300</if_sid>`.

Un incident annexe découvert en cours de route : `wazuh-db` (socket interne du manager)
s'était planté (`Unable to connect to socket 'queue/db/wdb'`), probablement lié à la
pression RAM hôte. Corrigé par un redémarrage complet du manager.

## Résultats

| Critère    | Valeur              |
|------------|----------------------|
| Détecté    | oui               |
| Règle      | 100147               |
| Verdict    | VP (vrai positif)    |
| Source     | WIN01 (console locale) |

## Lecture côté défense

La règle `100147` hérite son périmètre de la règle officielle `92300` : les clés `CurrentVersion\Run` et leurs
variantes 32 bits. Les autres emplacements de démarrage automatique relèvent d'autres règles. L'intérêt de Sysmon
ici se voit dans SC-15 : la chronologie complète (écriture puis suppression de la valeur) a été retrouvée dans son
journal alors que la clé n'existait plus et que le journal Security avait déjà tourné. Le test est lancé sur la
console de WIN01.

## Nettoyage

Douze clés de test (`SocForgeTest1` à `SocForgeTest12`, créées au fil des itérations de
debug) supprimées via une boucle `for` en une commande.
