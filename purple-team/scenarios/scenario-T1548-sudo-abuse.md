# Scénario Purple Team — T1548.003 Sudo and Sudo Caching

**ID Scénario**: SC-009
**Technique MITRE**: T1548.003
**Outil**: SSH + `sudo`
**Date test**: 2026-08-07 (Session 2 — Linux, 14h00–17h30 UTC)
**VM Attaquant**: VM12-PURPLE (10.10.10.60)
**VM Cible**: VM11-LINUX01

---

## Objectif

Valider que Wazuh détecte une escalade de privilèges via abus de `sudo` (exécution de commande en tant que root en dehors du contexte administratif normal) sur un hôte Linux.

---

## Étapes d'exécution (Red Team)

```bash
# Depuis VM12-PURPLE ou en local sur LINUX01, en tant qu'utilisateur avec droits sudo mal restreints
sudo -l
sudo /bin/bash
```

---

## Vérification Blue Team

1. Wazuh Dashboard → `rule.id: "100200"` → doit montrer le hit
2. Vérifier les logs auditd/syslog pour la commande sudo exécutée
3. TheHive → Alertes → `[Wazuh] Sudo privilege escalation`

---

## Résultats

| Test   | Détecté | Règle  | MTTD  | Hits |
|--------|---------|--------|-------|------|
| Test 1 | ✅      | 100200 | 11s   | 4    |

**Résultat global**: PASS — 0 FP — TheHive alerte créée automatiquement par Shuffle (pipeline 7s)

---

## Nettoyage

Aucun nettoyage requis (commande sudo, pas de persistance créée).
