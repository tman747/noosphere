#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^(4|8)$ ]]; then
  echo "usage: $0 <4|8 GiB>" >&2
  exit 1
fi
[[ "$(id -u)" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

SIZE_GIB="$1"
if [[ ! -f /swapfile ]]; then
  fallocate -l "${SIZE_GIB}G" /swapfile
  chmod 0600 /swapfile
  mkswap /swapfile >/dev/null
fi
if [[ "$(cat /proc/swaps)" != *"/swapfile"* ]]; then
  swapon /swapfile
fi
if [[ "$(cat /etc/fstab)" != *"/swapfile none swap sw 0 0"* ]]; then
  printf '/swapfile none swap sw 0 0\n' >> /etc/fstab
fi
printf 'vm.swappiness=10\nvm.vfs_cache_pressure=50\n' > /etc/sysctl.d/90-mindchain-memory.conf
sysctl --system >/dev/null
swapon --show
