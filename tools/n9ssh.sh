#!/bin/sh
# SSH to the N9/N950. Their OpenSSH 5.1p1 knows neither ed25519 nor SHA-2
# signatures, so it needs ssh-rsa for both host and user key, and the
# dedicated key.
#
#   N9_HOST=192.168.1.8 tools/n9ssh.sh 'command'
exec ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa \
    -i "$HOME/.ssh/id_rsa_n9" -oConnectTimeout=10 \
    "${N9_USER:-user}@${N9_HOST:-192.168.1.15}" "$@"
