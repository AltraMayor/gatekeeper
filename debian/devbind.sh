#!/bin/sh

if [ "$#" -eq "0" ]; then
  echo "devbind.sh <interface> [<interface> ...]"
fi

for iface in $@; do
  /usr/share/gatekeeper/dpdk-devbind.py --bind=vfio-pci $iface
done
