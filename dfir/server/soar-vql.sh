#!/bin/sh
# Forced command of the SSH key of the account "soar" on VM08-DFIR-HUNT
# (/usr/local/bin/soar-vql, see README.md in this folder). Whatever the client asks to
# run, this is what runs: one VQL query read on standard input, executed through the
# Velociraptor API as the API user "soar-api".
exec /usr/local/bin/velociraptor --api_config /etc/velociraptor/soar.api.config.yaml \
     query --format json "$(cat)"
