#!/bin/sh
# Restricts who can reach Shuffle on the SOC network (VM06-SHUFFLE).
#
# The webhook of the alert chain has no authentication of its own: Wazuh's native
# integration (/var/ossec/integrations/shuffle.py) sends no credential, and the webhook id
# in the URL is the only secret. This filter makes the Wazuh manager the only machine of
# the SOC network allowed to open a connection to Shuffle (webhook and web interface, ports
# 3001 and 3443). Administration goes through the VirtualBox NAT interface, which is not
# affected.
#
# Docker publishes the ports with its own NAT rules, which bypass the INPUT chain (and so
# ufw): the filter goes in DOCKER-USER and matches the port the client asked for.
# Installed as /usr/local/sbin/shuffle-webhook-acl and run at boot by
# shuffle-webhook-acl.service, after docker.service.
SOC_IF="${SOC_IF:-enp0s3}"
WAZUH="${WAZUH:-10.10.10.10}"

for port in 3001 3443; do
    rule="-i $SOC_IF -p tcp -m conntrack --ctorigdstport $port ! -s $WAZUH -j DROP"
    iptables -C DOCKER-USER $rule 2>/dev/null || iptables -I DOCKER-USER $rule
done
