# Fiche de chaîne de conservation — SocForge

## Identification de l'artefact

| Champ | Valeur |
|---|---|
| ID artefact | COC-YYYY-MM-DD-NNN |
| Incident associé | INC-YYYY-MM-DD-NNN |
| Nom du fichier | [nom-exact-du-fichier.ext] |
| Type d'artefact | [Prefetch / EventLog / PCAP / MFT / Autre] |
| Machine source | [HOSTNAME] |
| IP source | [10.10.x.x] |
| Date et heure de collecte | YYYY-MM-DD HH:MM:SS UTC+1 |
| Analyste collecteur | [Prénom] |
| Outil de collecte | [Velociraptor / tcpdump / autre] |

## Intégrité

| Champ | Valeur |
|---|---|
| Hash SHA-256 original | `[hash complet]` |
| Hash SHA-256 copie de travail | `[hash complet]` |
| Correspondance | ☐ Oui ☐ Non |

Commande de vérification :
```bash
sha256sum [nom-du-fichier]
# ou sous Windows :
Get-FileHash [nom-du-fichier] -Algorithm SHA256
```

## Stockage

| Champ | Valeur |
|---|---|
| Chemin original | `dfir/artifacts/INC-YYYY-MM-DD-NNN/original/[fichier]` |
| Chemin copie de travail | `dfir/artifacts/INC-YYYY-MM-DD-NNN/working/[fichier]` |
| Stockage hors Git | ☐ Oui ☐ Non |

## Traçabilité des accès

| Date | Analyste | Action | Notes |
|---|---|---|---|
| YYYY-MM-DD HH:MM | [Prénom] | Collecte initiale | Via Velociraptor |
| YYYY-MM-DD HH:MM | [Prénom] | Analyse | Copie de travail uniquement |

## Notes

[Observations lors de la collecte, anomalies constatées, conditions particulières.]
