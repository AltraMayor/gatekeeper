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

# Make modules persist across reboots.
sudo ln -s ${RTE_SDK}/build/kmod/igb_uio.ko /lib/modules/`uname -r`
sudo depmod -a
sudo echo "uio" | sudo tee -a /etc/modules
sudo echo "uio_pci_generic" | sudo tee -a /etc/modules
sudo echo "igb_uio" | sudo tee -a /etc/modules

ln -s ${RTE_SDK}/build ${RTE_SDK}/${RTE_TARGET}
