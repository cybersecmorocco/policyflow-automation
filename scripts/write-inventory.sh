#!/bin/sh
# Write inventories/vagrant.ini from `vagrant ssh-config linux`.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"

config=$(vagrant ssh-config linux)
host=$(printf '%s\n' "$config" | awk '/HostName / { print $2; exit }')
user=$(printf '%s\n' "$config" | awk '/User / { print $2; exit }')
port=$(printf '%s\n' "$config" | awk '/Port / { print $2; exit }')
keys=$(printf '%s\n' "$config" | awk '/IdentityFile / { print $2 }')
key=$(printf '%s\n' "$keys" | awk 'NR == 1 { print; exit }')

if [ -z "$host" ] || [ -z "$user" ] || [ -z "$port" ] || [ -z "$key" ]; then
  echo "vagrant ssh-config linux did not include HostName, User, Port, and IdentityFile" >&2
  exit 1
fi

ssh_args="-o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa"
for identity in $keys; do
  ssh_args="$ssh_args -o IdentityFile=${identity}"
done

mkdir -p "$root/inventories"
cat > "$root/inventories/vagrant.ini" <<EOF
[linux]
policyflow-linux ansible_host=${host} ansible_user=${user} ansible_port=${port} ansible_ssh_private_key_file=${key} ansible_ssh_common_args='${ssh_args}'
EOF

echo "Wrote $root/inventories/vagrant.ini"
