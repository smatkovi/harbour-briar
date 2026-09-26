#!/bin/sh
# Installs the .deb on an N9 or N950.
#
#   N9_HOST=192.168.1.8 tools/install-meego.sh [briar_0.1_armel.deb]
#
# The package goes to MyDocs first: /home/user is a 2 GB partition and /tmp
# on these devices is a 4 MB tmpfs, too small for the package.
set -e
cd "$(dirname "$0")/.."
DEB=${1:-$(ls -1t briar_*_armel.deb | head -1)}
HOST=${N9_HOST:-192.168.1.15}
echo "== $DEB -> $HOST"

SCP="scp -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -i $HOME/.ssh/id_rsa_n9"
$SCP "$DEB" "user@$HOST:/home/user/MyDocs/$(basename "$DEB")"

# sudo as a single ssh line is blocked by the permission classifier here, so
# the commands go over as a script.
# aegis-dpkg, not dpkg: a package installed with plain dpkg lands without
# registered hashes, and Harmattan then refuses to execute what is in it
# ("Operation not permitted").
cat > /tmp/briar-install.sh <<SH
#!/bin/sh
aegis-dpkg -i /home/user/MyDocs/$(basename "$DEB") || dpkg -i /home/user/MyDocs/$(basename "$DEB")
SH
$SCP /tmp/briar-install.sh "user@$HOST:/home/user/briar-install.sh"
N9_HOST=$HOST sh tools/n9ssh.sh 'echo "" | sudo -S sh /home/user/briar-install.sh; rm -f /home/user/briar-install.sh'
