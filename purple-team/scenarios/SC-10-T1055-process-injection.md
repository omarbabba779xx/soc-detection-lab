# SC-10 : T1055, injection de processus (CreateRemoteThread)

| | |
|---|---|
| Date | 2026-09-18 (reconstruction, étape 4) |
| Lancé depuis | console locale de WIN01, compte `labuser`, invite élevée |
| Cible | WIN01 (agent Wazuh 005), processus `notepad.exe` local |
| Technique MITRE | T1055, Process Injection |
| Tactiques | Defense Evasion, Privilege Escalation |
| Résultat | détecté, règle 100155 (niveau 13) ; bruit traité et rattachement corrigé le 07/10 |

## Objectif

Vérifier la détection de la création d'un thread dans un autre processus (Sysmon 8), une fois corrigé le défaut
de rattachement de la règle 100155, le même que pour 100147 et 100103.

## Test (bénin)

Un script PowerShell, passé en `-EncodedCommand` :

1. lance `notepad.exe` comme processus cible ;
2. ouvre ce processus (`OpenProcess`) ;
3. y crée un thread (`CreateRemoteThread`) qui appelle `kernel32!Sleep` avec un paramètre de 500 ms.

Aucun code n'est écrit dans la mémoire de la cible : le thread exécute une fonction Windows déjà présente dans le
processus. C'est une méthode de test courante, qui produit la télémétrie Sysmon sans risque.

Sortie de la console :

```
Target handle: True
Remote thread handle: True
Done
```

## Détection

| Règle | Niveau | Source | Rôle |
|---|---|---|---|
| 100155 | 13 | Sysmon 8 | thread créé dans un autre processus |

```
Rule: 100155 (level 13) -> 'Sigma T1055: CreateRemoteThread into another process — possible process injection — C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -> C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_...\Notepad\Notepad.exe'
StartFunction: Sleep
```

Capture (tableau de bord Wazuh, 17 correspondances sur `rule.id:100155`) :
[`wazuh-dashboard-rule-100155-live.png`](../../docs/screenshots/wazuh-dashboard-rule-100155-live.png)

## Défaut corrigé

Même famille que pour 100147 et 100103 : `<if_group>sysmon_event8</if_group>` ne déclenchait jamais cette règle sur
ce manager. Pour 100103, une règle officielle équivalente existait (92900). Ici, aucune règle officielle ne couvre
l'événement 8 en général : les règles 92400 à 92403 visent chacune un processus cible précis. La règle 100155 est
donc rattachée à `<if_sid>185006</if_sid>`, la règle de base de niveau 0 qui marque tout événement 8.

## Résultats

| Critère | Valeur |
|---|---|
| Détecté | oui |
| Règle | 100155 |
| Verdict | vrai positif |
| Source | WIN01, console locale |

## Lecture côté défense

Le 18/09, la règle `100155` alertait sur tout événement Sysmon 8, sans filtre : elle voyait aussi des créations de
thread légitimes (17 correspondances dans la capture, pour un seul test). Depuis le 07/10, le signal de console de
Windows est écarté par la règle `100156` ; les autres cas continuent d'alerter.

Sysmon 8 ne décrit qu'une famille de techniques, celle qui crée un thread dans un autre processus. Le test est
lancé sur la console de WIN01 et n'écrit aucun code dans le processus cible.

## Mise à jour du 07/10

Le bruit de la règle a été analysé et son rattachement corrigé. Le détail est dans la
[fiche de détection Windows](../../detections/windows/detection-sheet-windows.md), section T1055.

## Nettoyage

Le processus `notepad.exe` cible a été fermé après le test. Aucune persistance créée.
