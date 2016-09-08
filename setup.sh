# Gatekeeper - DoS protection system.
# Copyright (C) 2016 Digirati LTDA.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

cd dpdk

# Path to the build directory.
export RTE_SDK=`pwd`

# Target of build process.
export RTE_TARGET=x86_64-native-linuxapp-gcc

# Configure and build.
make config T=${RTE_TARGET}
make

# Install kernel modules.
sudo modprobe uio
sudo modprobe uio_pci_generic
sudo insmod ${RTE_SDK}/build/kmod/igb_uio.ko

# Make modules persist across reboots. Since multiple
# users can run this script, don't re-add these modules
# if someone else already made them persistent.
sudo ln -s ${RTE_SDK}/build/kmod/igb_uio.ko /lib/modules/`uname -r`
sudo depmod -a
if ! grep -q "uio" /etc/modules; then
  sudo echo "uio" | sudo tee -a /etc/modules
fi
if ! grep -q "uio_pci_generic" /etc/modules; then
  sudo echo "uio_pci_generic" | sudo tee -a /etc/modules
fi
if ! grep -q "igb_uio" /etc/modules; then
  sudo echo "igb_uio" | sudo tee -a /etc/modules
fi

ln -s ${RTE_SDK}/build ${RTE_SDK}/${RTE_TARGET}

cd ..

echo "Environmental variables RTE_SDK and RTE_TARGET have been set, but not saved for future logins. You should save them to your shell's preferences file or set them after every login."
