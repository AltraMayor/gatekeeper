#!/bin/sh

if [ "$#" -eq "0" ]; then
  echo "devbind.sh <interface> [<interface> ...]"
fi

for iface in $@; do
  /usr/bin/dpdk-devbind.py --bind=uio_pci_generic $iface
done
