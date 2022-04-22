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

# All the dependency projects are maintained in this directory.
cd dependencies

# Setup DPDK.
cd dpdk

meson build
cd build
ninja
sudo ninja install

# Gatekeeper is being staticly linked with DPDK, so
# ldconfig(8) is not needed to make DPDK's libraries available system wide.
# sudo ldconfig

# Install kernel modules.
sudo modprobe uio
sudo modprobe uio_pci_generic

# Make modules persist across reboots. Since multiple
# users can run this script, don't re-add these modules
# if someone else already made them persistent.
sudo depmod -a
if ! grep -q "uio" /etc/modules; then
  sudo echo "uio" | sudo tee -a /etc/modules
fi
if ! grep -q "uio_pci_generic" /etc/modules; then
  sudo echo "uio_pci_generic" | sudo tee -a /etc/modules
fi

# Setup LuaJIT.
cd ../../luajit-2.0

# Build and install.
make
sudo make install

# Setup BIRD.
cd ../bird

# Build and install.
autoreconf
./configure
make
sudo make install

cd ../../

# Build interface name -> PCI address map.
gcc generate_if_map.c -o generate_if_map -Wall
./generate_if_map lua/if_map.lua

# Build client.
cd gkctl
gcc main.c -o gkctl -Wall -Wextra -pedantic
cd ..

# Build BPF programs.
cd bpf
make
make copy
cd ..

sudo mkdir -p /var/run/gatekeeper/
sudo chown -R $USER:$GROUPS /var/run/gatekeeper/
sudo chmod -R 700 /var/run/gatekeeper/
