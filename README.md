# Gatekeeper

## What is Gatekeeper?

Gatekeeper is the first open source DoS protection system. It is designed to
scale to any peak bandwidth, so it can withstand DoS attacks both of today
and of tomorrow. In spite of the geographically distributed architecture of
Gatekeeper, the network policy that describes all decisions that have to be
enforced on the incoming traffic is centralized. This centralized policy
enables network operators to leverage distributed algorithms that would not
be viable under very high latency (e.g. distributed databases) and to fight
multiple multi-vector DoS attacks at once.

The intended users of Gatekeeper are network operators of institutions,
service and content providers, enterprise networks, etc. It is not intended
to be used by individual Internet users.

For more information, see the [Gatekeeper wiki](https://github.com/AltraMayor/gatekeeper/wiki).

## How to Set Up

### Configure Hugepages

DPDK requires the use of hugepages; instructions for mounting hugepages are
available in the [requirements documentation](http://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#use-of-hugepages-in-the-linux-environment).
On many systems, the following hugepages setup is sufficient:

    $ echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

### Option 1: Obtain Packages

Debian packages for Gatekeeper aren't yet available, but will be soon.

### Option 2: Build from Source

#### Install Dependencies

Install the following software dependencies:

    $ sudo apt-get update
    $ sudo apt-get -y -q install git clang doxygen hugepages build-essential linux-headers-`uname -r` libmnl0 libmnl-dev libkmod2 libkmod-dev libnuma-dev autoconf flex bison libncurses5-dev libreadline-dev

Note: Both `libmnl0` and `libmnl-dev` are needed to compile and run
`gatekeeper`, but only `libmnl0` is needed for simply running `gatekeeper`.
Both `libkmod2` and `libkmod-dev` are needed to compile and run `gatekeeper`,
but only `libkmod2` is needed for simply running `gatekeeper`.
`libnuma-dev` is needed to compile the latest DPDK and/or support the NUMA
system. The `autoconf`, `flex`, `bison`, `libncurses5-dev`, and
`libreadline-dev` packages are for BIRD.

To use DPDK, make sure you have all of the [environmental requirements](http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html#running-dpdk-application).

#### Clone Repository

Clone the Gatekeeper repository, including the submodules that
contain Gatekeeper dependencies:

    $ gatekeeper clone --recursive http://github.com/AltraMayor/gatekeeper.git

If you do not use the `--recursive` clone option, you need to obtain the
submodules that contain the dependences from within the `gatekeeper`
directory:

    $ git submodule init
    $ git submodule update

#### Compile

While in the `gatekeeper` directory, run the setup script:

    $ . setup.sh

This script compiles DPDK, LuaJIT, and BIRD, and loads the needed
kernel modules. Additionally, it saves the interface names and their
respective PCI addresses in the file `lua/if_map.lua` so that interface
names can be used in the Gatekeeper configuration files.

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

#### Configure Network Adapters

Before `gatekeeper` can be used, the network adapters must be bound to DPDK.
For this, you can use the script `dependencies/dpdk/usertools/dpdk-devbind.py`.
For example:

    $ sudo dependencies/dpdk/usertools/dpdk-devbind.py --bind=uio_pci_generic enp131s0f0

This command binds the interface `enp131s0f0` to the `uio_pci_generic` driver
so that frames can be passed directly to DPDK instead of the kernel. Note
that this binding must take place after Gatekeeper is setup in the steps
above so that the bound interface appears in the list of interfaces in
`lua/if_map.lua`.

#### How to Run

Once `gatekeeper` is compiled and the environment is configured correctly, run:

    $ sudo build/gatekeeper [EAL OPTIONS] -- [GATEKEEPER OPTIONS]

Where `[EAL OPTIONS]` are specified before a double dash and represent the
parameters for DPDK's [Environmental Abstraction Layer](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html)
and `[GATEKEEPER OPTIONS]` are specified after the double dash and
represent [Gatekeeper-specific options](https://github.com/AltraMayor/gatekeeper/wiki/Configuration#application-configuration).

The early configuration of the system, including device and memory
configuration in DPDK, will be logged to stdout. Once Gatekeeper is booted,
all information is output to the Gatekeeper log.
