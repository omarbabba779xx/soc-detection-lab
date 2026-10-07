# Règles Sigma

Forme Sigma des détections Windows et Linux du lab. Chaque fichier porte, dans
`custom.wazuh_rule`, l'identifiant de la règle Wazuh correspondante
([`wazuh/rules/`](../../wazuh/rules/)).

La traduction vers Wazuh est faite à la main : il n'existe pas de convertisseur Sigma
officiel pour le format XML de Wazuh. Quand la règle Wazuh s'appuie sur une règle du jeu
officiel (par exemple `92900` pour LSASS), la règle Sigma reprend les mêmes filtres.

Les seuils (analyse de ports, force brute, partages d'administration) sont écrits en
règles de corrélation Sigma, dans le même fichier que la règle de base.

Les fichiers sont validés par `sigma check detections/sigma` dans la CI. Les règles
pare-feu et NDR ne sont pas concernées : elles dépendent des journaux `filterlog`
d'OPNsense et des signatures Suricata, sans équivalent Sigma utile.
