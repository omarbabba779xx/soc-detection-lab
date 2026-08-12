# Résumé des cas TheHive — Exercice Purple Team — 2026-08-07

**VM03-THEHIVE**: 10.10.10.20:9000
**Période**: 2026-08-07T14:00:00 → 17:30:00

---

## Alertes créées par Shuffle

| # | Titre (généré par Shuffle)                                        | Sévérité | Statut   | Observable principal    |
|---|-------------------------------------------------------------------|----------|----------|-------------------------|
| 1 | [Wazuh] Sigma T1059.001: PowerShell encoded command — Level 12   | Medium   | Fermé    | ip: 10.10.10.110        |
| 2 | [Wazuh] Sigma T1059.001: Malicious script block — Level 12       | Medium   | Fermé    | ip: 10.10.10.110        |
| 3 | [Wazuh] Brute force — 5+ failures in 60s — Level 10             | Medium   | Fermé    | ip: 10.10.10.60         |
| 4 | [Wazuh] Admin share access — possible lateral movement — Level 10 | Medium  | Fermé    | ip: 10.10.10.60         |
| … | … (350+ alertes au total sur la période)                         | …        | …        | …                       |

---

## Cas d'investigation créés (promotions d'alertes)

| Cas # | Titre                                      | Template utilisé                 | Résolution |
|-------|--------------------------------------------|----------------------------------|------------|
| C-001 | Purple Team T1059.001 — 2026-08-07        | case-template-powershell.json    | Vrai Positif — Exercice lab |
| C-002 | Purple Team T1110 Brute Force — 2026-08-07 | case-template-bruteforce.json   | Vrai Positif — Exercice lab |
| C-003 | Purple Team T1021.002 — 2026-08-07        | case-template-lateral-movement.json | Vrai Positif — Exercice lab |

---

## Observables enrichis (Cortex + MISP)

| Observable       | Type     | Cortex (MaxMind)        | MISP          |
|------------------|----------|-------------------------|---------------|
| 10.10.10.60      | ip-src   | Privé (RFC1918) — lab   | Found: socforge:purple-team |
| 10.10.10.109     | hostname | Privé (RFC1918) — lab   | Found: socforge:lab |
| 10.10.10.110     | hostname | Privé (RFC1918) — lab   | Found: socforge:lab |

---

## Procédure d'export TheHive

```bash
# Export via API TheHive v5
curl -u admin:<THEHIVE_PASSWORD> \
  http://10.10.10.20:9000/api/v1/alert?range=all \
  -H "Accept: application/json" > thehive-alerts-2026-08-07.json
```
