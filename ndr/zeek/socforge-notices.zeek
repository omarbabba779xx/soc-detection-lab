# SocForge — Custom Zeek Notices
# Détection d'activités suspectes spécifiques au lab SocForge
# VM07-NDR: /opt/zeek/share/zeek/site/socforge-notices.zeek

module SocForge;

export {
    redef enum Notice::Type += {
        ## Connexion depuis la zone Purple Team vers une cible non autorisée
        PurpleTeam_Unauthorized_Target,
        ## Volume de connexions SMB anormalement élevé (T1021.002)
        SMB_Mass_Connection,
        ## DNS query anormalement long (possible tunneling T1048.003)
        DNS_Long_Query,
        ## Connexion RDP depuis une IP non-management
        RDP_Unexpected_Source,
        ## HTTP sans User-Agent (possible C2 T1071.001)
        HTTP_Empty_UserAgent,
        ## Scan de ports détecté (T1046)
        Port_Scan_Detected
    };
}

# ============================================================
# Détection: Purple Team vers cibles non autorisées
# VM12-PURPLE (10.10.10.60) ne doit cibler que 10.10.10.109 et 10.10.10.110
# ============================================================
event connection_established(c: connection)
{
    local purple_ip = 10.10.10.60;
    local authorized_targets: set[addr] = {10.10.10.109, 10.10.10.110};

    if (c$id$orig_h == purple_ip && c$id$resp_h !in authorized_targets)
    {
        NOTICE([$note=PurpleTeam_Unauthorized_Target,
                $conn=c,
                $msg=fmt("VM12-PURPLE connecting to unauthorized target: %s", c$id$resp_h),
                $identifier=cat(c$id$orig_h, c$id$resp_h),
                $suppress_for=5min]);
    }
}

# ============================================================
# Détection: DNS query long (> 50 chars = possible tunneling)
# ============================================================
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (|query| > 50)
    {
        NOTICE([$note=DNS_Long_Query,
                $conn=c,
                $msg=fmt("Long DNS query (%d chars): %s", |query|, query),
                $identifier=query,
                $suppress_for=10min]);
    }
}

# ============================================================
# Détection: HTTP sans User-Agent
# ============================================================
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if (is_orig && name == "User-Agent" && value == "")
    {
        NOTICE([$note=HTTP_Empty_UserAgent,
                $conn=c,
                $msg=fmt("HTTP request with empty User-Agent to %s", c$id$resp_h),
                $identifier=cat(c$id$orig_h, c$id$resp_h),
                $suppress_for=5min]);
    }
}

# ============================================================
# Détection: RDP depuis IP hors zone management
# ============================================================
event connection_established(c: connection)
{
    local mgmt_net: subnet = 10.10.10.0/24;

    if (c$id$resp_p == 3389/tcp && c$id$orig_h !in mgmt_net)
    {
        NOTICE([$note=RDP_Unexpected_Source,
                $conn=c,
                $msg=fmt("RDP connection from unexpected source: %s", c$id$orig_h),
                $identifier=cat(c$id$orig_h, c$id$resp_h),
                $suppress_for=15min]);
    }
}
