#!/bin/sh

if [ "$#" -eq "0" ]; then
  echo "devbind.sh <interface> [<interface> ...]"
fi

for iface in $@; do
  /sbin/dpdk-devbind --bind=uio_pci_generic $iface
done
