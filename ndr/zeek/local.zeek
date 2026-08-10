# SocForge — Zeek Local Configuration
# VM07-NDR: /opt/zeek/share/zeek/site/local.zeek
# Chargement: zeekctl deploy

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/smtp
@load base/protocols/ftp
@load base/protocols/ssh
@load base/protocols/smb
@load base/protocols/rdp
@load base/protocols/ntlm
@load base/protocols/krb

# Détection de scans et anomalies
@load policy/misc/scan
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostnames

# Chargement des scripts SocForge custom
@load ./socforge-notices.zeek
@load ./socforge-smb-monitor.zeek

# Activer JSON pour export vers Wazuh
redef LogAscii::use_json = T;

# Interface de capture — adaptée à VirtualBox
redef NetworkInterfaces = {"eth0"};

# Répertoire de logs
redef Log::default_rotation_dir = "/var/log/zeek/current";
redef Log::default_rotation_interval = 1 hr;

# Désactiver les checksums (VirtualBox offload)
redef ignore_checksums = T;

# Seuils pour la détection de scan
redef Scan::addr_scan_threshold = 10.0;
redef Scan::port_scan_threshold = 15.0;

# Réseau interne SocForge
redef Site::local_nets = {
    10.10.10.0/24,
    10.10.20.0/24,
    10.10.30.0/24,
    10.10.50.0/24,
    10.10.60.0/24
};
