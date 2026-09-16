# Scénario Purple Team — T1053.003 Scheduled Task/Job: Cron

**ID Scénario**: SC-010
**Technique MITRE**: T1053.003
**Outil**: `crontab -e`
**Date test**: 2026-08-07 (Session 2 — Linux, 14h00–17h30 UTC)
**VM Attaquant**: VM12-PURPLE (10.10.10.60)
**VM Cible**: VM11-LINUX01

---

## Objectif

Valider que Wazuh détecte la création d'une tâche cron persistante — mécanisme de persistence Linux post-compromission.

---

## Étapes d'exécution (Red Team)

```bash
# Sur LINUX01
crontab -e
# Ajout d'une ligne de persistance :
# * * * * * /tmp/socforge_test.sh
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `rule.id: "100210"` → doit montrer le hit
2. Vérifier syslog/auditd pour la modification de la crontab utilisateur
3. TheHive → Alertes → `[Wazuh] Cron persistence`

---

## Résultats

| Test   | Détecté | Règle  | MTTD  | Hits |
|--------|---------|--------|-------|------|
| Test 1 | ✅      | 100210 | 14s   | 1    |

**Résultat global**: PASS — 0 FP — TheHive alerte créée automatiquement par Shuffle (pipeline 7s)

---

## Nettoyage

```bash
crontab -e
# Suppression de la ligne de test ajoutée
```
