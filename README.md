# Gatekeeper

## How to Set Up

### Install and Configure Dependencies

Install the following software dependencies:

    $ sudo apt-get update
    $ sudo apt-get -y -q install git clang doxygen hugepages build-essential linux-headers-`uname -r` libmnl0 libmnl-dev libkmod2 libkmod-dev libnuma-dev autoconf flex bison libncurses5-dev libreadline-dev

Note: Both `libmnl0` and `libmnl-dev` are needed to compile and run `gatekeeper`, but only `libmnl0` is needed for simply running `gatekeeper`.
Both `libkmod2` and `libkmod-dev` are needed to compile and run `gatekeeper`, but only `libkmod2` is needed for simply running `gatekeeper`.
`libnuma-dev` is needed to compile the latest DPDK and/or support the NUMA system. The `autoconf`, `flex`, `bison`, `libncurses5-dev` and `libreadline-dev` packages are for BIRD.

To use DPDK, make sure you have all of the environmental requirements: <http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html#running-dpdk-applications>.

Note that DPDK requires the use of hugepages; instructions for mounting hugepages are available in the link above.

Once the software dependencies have been installed and the hugepages have been configured, you are ready to build `gatekeeper`.

### Obtain Source

Upon cloning the `gatekeeper` repository, you need to obtain the sources of
the dependencies:

    $ git submodule init
    $ git submodule update

(Note: these initialization steps are not needed if you clone the `gatekeeper` repository using `git clone --recursive ...`.)

### Compile

While in the `gatekeeper` directory, run the setup script:

    $ . setup.sh

This script compiles DPDK and LuaJIT, and loads the needed kernel modules.
Additionally, it saves the interface names and their respective PCI addresses
in the file `lua/if_map.lua`, so that interface names can be used in
the Gatekeeper configuration files.

It also sets two environmental variables: `RTE_SDK` and `RTE_TARGET`.
They must be set before `gatekeeper` will compile.

After running the setup script, you may want to save
the environmental variables in your shell's preferences file.
For example, in Bash, you can do:

    $ echo "export RTE_SDK=${RTE_SDK}" >> ${HOME}/.profile
    $ echo "export RTE_TARGET=${RTE_TARGET}" >> ${HOME}/.profile

Otherwise, each time you login you will need to set these environmental variables again.

Once DPDK is compiled and the variables are set, `gatekeeper` can be compiled:

    $ make

### Configure Network Adapters

Before `gatekeeper` can be used, the network adapters must be bound to DPDK. For this, you can use the script `dependencies/dpdk/usertools/dpdk-devbind.py`. For example:

    $ sudo dependencies/dpdk/usertools/dpdk-devbind.py --bind=uio_pci_generic enp131s0f0

This command binds the interface `enp131s0f0` to the `uio_pci_generic` driver so that frames can be passed directly to DPDK instead of the kernel.

## How to Run

Once `gatekeeper` is compiled and the environment is configured correctly, run:

    $ sudo build/gatekeeper [EAL OPTIONS] -- [GATEKEEPER OPTIONS]

Where `[EAL OPTIONS]` are specified before a double dash and represent the
parameters for DPDK's [Environmental Abstraction Layer](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html)
and `[GATEKEEPER OPTIONS]` are specified after the double dash and
represent [Gatekeeper-specific options](https://github.com/AltraMayor/gatekeeper/wiki/Configuration#application-configuration).

The early configuration of the system, including device and memory
configuration in DPDK, will be logged to stdout. Once Gatekeeper is booted,
all information is output to the Gatekeeper log.
