# Installation Ubuntu Server 22.04 — Guide base SocForge

Ce guide s'applique à : VM02-WAZUH, VM03-THEHIVE, VM04-CORTEX, VM05-MISP,
VM06-SHUFFLE, VM07-NDR, VM08-DFIR-HUNT, VM11-LINUX01

## Avant de démarrer

1. Attacher l'ISO à la VM (voir `01-os-downloads.md`)
2. Prendre un snapshot "vide" si souhaité
3. Démarrer la VM depuis VirtualBox

## Paramètres d'installation Ubuntu Server

### Langue et clavier
- Language : **English**
- Keyboard layout : **French** (ou votre préférence)

### Réseau
- Lors de l'install, Ubuntu détecte les interfaces.
- La NIC NAT (ajoutée temporairement) obtiendra une IP automatiquement → accès Internet pour les mises à jour.
- La NIC interne (`socforge-*`) restera sans IP pour l'instant (configurée manuellement après).

### Stockage
- Choisir : **Use entire disk**
- Activer **LVM group** : Oui
- Confirmer la destruction du disque virtuel

### Profil utilisateur (IDENTIQUE sur toutes les VM Ubuntu)

| Champ | Valeur |
|---|---|
| Votre nom | SOC Admin |
| Nom du serveur | voir tableau ci-dessous |
| Nom d'utilisateur | `socadmin` |
| Mot de passe | [choisir un mot de passe fort, noter dans secrets/lab-registry.md] |

### Nom d'hôte par VM

| VM VirtualBox | Hostname Ubuntu |
|---|---|
| SF-VM02-WAZUH | `wazuh` |
| SF-VM03-THEHIVE | `thehive` |
| SF-VM04-CORTEX | `cortex` |
| SF-VM05-MISP | `misp` |
| SF-VM06-SHUFFLE | `shuffle` |
| SF-VM07-NDR | `ndr` |
| SF-VM08-DFIR-HUNT | `dfir-hunt` |
| SF-VM11-LINUX01 | `linux01` |

### SSH
- **Install OpenSSH server** : ✅ Coché (obligatoire)
- Import SSH identity : Non (pour l'instant)

### Snaps supplémentaires
- Rien à cocher — garder minimal

## Après redémarrage : configuration post-install

Se connecter avec `socadmin` puis exécuter :

```bash
# 1. Mises à jour complètes
sudo apt update && sudo apt upgrade -y

# 2. Outils essentiels
sudo apt install -y curl wget git vim net-tools htop unzip \
  gnupg ca-certificates apt-transport-https software-properties-common

# 3. Fuseau horaire
sudo timedatectl set-timezone Europe/Paris
sudo timedatectl set-ntp true
timedatectl status

# 4. Vérifier la synchronisation NTP
date

# 5. Configurer l'IP statique sur l'interface interne (adapter le nom d'interface)
# D'abord identifier les interfaces
ip link show
# La NIC interne sera quelque chose comme enp0s3 ou enp0s8
# Éditer la config netplan
sudo nano /etc/netplan/00-installer-config.yaml
```

### Exemple de config netplan (adapter l'IP selon la VM)

```yaml
network:
  version: 2
  ethernets:
    enp0s3:                      # Interface interne (socforge-*)
      dhcp4: false
      addresses:
        - 10.10.10.10/24         # Changer selon la VM
      nameservers:
        addresses: [10.10.20.10, 8.8.8.8]
      routes:
        - to: default
          via: 10.10.10.1        # Passerelle FW
    enp0s8:                      # Interface NAT temporaire
      dhcp4: true                # Garder pendant l'install, supprimer après
```

```bash
# Appliquer la config
sudo netplan apply

# Vérifier
ip addr show
ping -c 2 10.10.10.1
```

## Snapshot post-install

Après configuration réseau et NTP validés :
- Éteindre la VM : `sudo poweroff`
- Dans VirtualBox : clic droit → Prendre un instantané
- Nom : `SNAPSHOT-00-BASE-INSTALL-[HOSTNAME]-[DATE]`

## Désactiver la NIC NAT après installation

Une fois l'OS installé et les outils téléchargés, désactiver la NIC NAT :

```powershell
# Sur l'hôte Windows (PowerShell)
$vbm = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vbm modifyvm "SF-VM02-WAZUH" --nic2 none
# Répéter pour chaque VM
```
