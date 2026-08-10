# SocForge — Zeek SMB/NTLM Monitoring
# Surveillance des connexions SMB pour détecter T1021.002 et T1110
# VM07-NDR: /opt/zeek/share/zeek/site/socforge-smb-monitor.zeek

module SocForge;

# Compteur de connexions SMB par source
global smb_conn_count: table[addr] of count &default=0 &create_expire=5min;

# ============================================================
# Détection: Volume élevé de connexions SMB (T1021.002)
# ============================================================
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
{
    if (c$id$resp_p == 445/tcp)
    {
        smb_conn_count[c$id$orig_h] += 1;

        if (smb_conn_count[c$id$orig_h] > 100)
        {
            NOTICE([$note=SMB_Mass_Connection,
                    $conn=c,
                    $msg=fmt("High SMB traffic from %s: %d connections in 5min",
                             c$id$orig_h, smb_conn_count[c$id$orig_h]),
                    $identifier=cat(c$id$orig_h),
                    $suppress_for=5min]);
        }
    }
}

# ============================================================
# Log NTLM — Exporté vers Wazuh via JSON
# ============================================================
event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{
    if (request?$domain_name && request?$user_name)
    {
        Log::write(NTLM::LOG, [$ts=network_time(),
                               $id=c$id,
                               $username=request$user_name,
                               $domain=request$domain_name]);
    }
}
