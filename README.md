# Gatekeeper

<a href="https://github.com/AltraMayor/gatekeeper/actions?query=workflow%3compile">
  <img alt="Gatekeeper compilation status"
       src="https://github.com/AltraMayor/gatekeeper/workflows/compile/badge.svg">
</a>

## What is Gatekeeper?

Gatekeeper is the first open source DDoS protection system. It is designed to
scale to any peak bandwidth, so it can withstand DDoS attacks both of today
and of tomorrow. In spite of the geographically distributed architecture of
Gatekeeper, the network policy that describes all decisions that have to be
enforced on the incoming traffic is centralized. This centralized policy
enables network operators to leverage distributed algorithms that would not
be viable under very high latency (e.g. distributed databases) and to fight
multiple multi-vector DDoS attacks at once.

The intended users of Gatekeeper are network operators of institutions,
service and content providers, enterprise networks, etc. It is not intended
to be used by individual Internet users.

For more information, see the [Gatekeeper wiki](https://github.com/AltraMayor/gatekeeper/wiki).

## How to Set Up

### Configure Hugepages

DPDK requires the use of hugepages; instructions for mounting hugepages are
available in the [requirements documentation](http://doc.dpdk.org/guides/linux_gsg/sys_reqs.html#use-of-hugepages-in-the-linux-environment).
On many systems, the following hugepages setup is sufficient:

```console
$ echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### Enable the kernel module `vfio-pci`

Starting with Gatekeeper v1.1, the Linux kernel module `vfio-pci` is
the prefered way to bind NICs to DPDK/Gatekeeper.
In case you cannot get the kernel module `vfio-pci` running on your machine,
you may tray an alternative to `vfio-pci` as documented on [this page](https://github.com/AltraMayor/gatekeeper/wiki/Alternatives-to-kernel-module-vfio%E2%80%90pci).

In order for `vfio-pci` to work, both the BIOS and the kernel must support it.
BIOSes must have VT-d enabled.
BIOSes may identify VT-d as "Intel (R) VT for Directed I/O",
"Intel (R) VT-d Feature", "Intel VT-d", "VT-d", or similar variations;
for more examples, search "BIOS VT-d" on
[Google Images](https://images.google.com/).
Some BIOS may require that an option called
"Intel (R) Virtualization Technology" (or variations of this string) to be
enabled before VT-d can be enabled.

To check that VT-d is enabled at the BIOS, run the following command after
Linux boots up:

```console
$ dmesg | grep -e DMAR
```

If the command above returns some lines, VT-d should be enabled.
Otherwise, one has to go back to the BIOS to enable it.
More information on how to check that VT-d is enabled at the BIOS is
available on [this page](https://stackoverflow.com/questions/51261999/check-if-vt-d-iommu-has-been-enabled-in-the-bios-uefi).

Once VT-d is enabled at the BIOS, one must ensure that the kernel supports
IOMMU.
Notice that one needs a kernel version greater than 3.6 to support IOMMU.
One can verify if the running kernel has IOMMU enabled by default with
the following command:

```console
$ grep CONFIG_INTEL_IOMMU_DEFAULT_ON /boot/config-`uname -r`
```

Most likely, the command above will output
`# CONFIG_INTEL_IOMMU_DEFAULT_ON is not set`, that is,
the running kernel does not have IOMMU enabled by default.
Alternatives ways to check for kernel build options
(i.e. `CONFIG_INTEL_IOMMU_DEFAULT_ON`) is available on
[this page](https://unix.stackexchange.com/questions/83319/where-are-the-current-kernel-build-options-stored).

If the kernel does not have IOMMU enabled by default,
one has to pass the kernel boot parameter `intel_iommu=on` via GRUB.
For information on the why the boot parameter `intel_iommu=on` is needed,
see [this page](https://unix.stackexchange.com/questions/595353/vt-d-support-enabled-but-iommu-groups-are-missing).
One can check if the running kernel received this parameter with
the command below:

```console
$ cat /proc/cmdline | grep intel_iommu=on
```

If the running kernel has not received the parameter `intel_iommu=on`,
add it to GRUB, and reboot the machine.
Information on how to add a boot parameter to GRUB is found
[here](https://askubuntu.com/questions/19486/how-do-i-add-a-kernel-boot-parameter).

Once VT-d is enabled at the BIOS and the kernel supports IOMMU,
one can verify that everything is all set with one of the following commands:

```console
$ ls /sys/kernel/iommu_groups
```

OR

```console
$ dmesg | grep -ie 'IOMMU\s\+enabled'
```

Everything is all set if the outputs of the commands above are not empty.

### Option 1: Obtain Packages

Gatekeeper Debian packages are available for Ubuntu 20.04 LTS at the project's
[Releases](https://github.com/AltraMayor/gatekeeper/releases)
page.

#### Install

Once the packages are downloaded, they can be installed with the commands below:

```console
$ tar -zxvf gatekeeper-ubuntu-20.04-packages.tar.gz
$ cd gatekeeper-ubuntu-20.04-packages
$ sudo dpkg -i dpdk-rte-kni-dkms_*_amd64.deb gatekeeper-bird_*_amd64.deb gatekeeper_*_amd64.deb
```

The `dpdk-rte-kni-dkms` package is a DKMS (Dynamic Kernel Modules Support)
package, which builds the `rte_kni` kernel module during installation and kernel
upgrades.

#### Configure Gatekeeper

When installed via Debian packages, Gatekeeper configuration files are located
in `/etc/gatekeeper`. You should edit at least the `net.lua` file, and set the
`front_ports`, `front_ips`, `back_ports` and `back_ips` variables according to
your environment.

The other Lua files configure different Gatekeeper functional blocks. Please
refer to the project's [wiki](https://github.com/AltraMayor/gatekeeper/wiki)
for further information on whether these need to be changed in your setup.

You also need to edit the `/etc/gatekeeper/envvars` file and set the
`GATEKEEPER_INTERFACES` variable to the PCI addresses of the network adapters
to be bound to DPDK. These can found using the `lshw` command. For example:

```console
# lshw -c network -businfo
Bus info          Device     Class          Description
=======================================================
pci@0000:08:00.0  eth0       network        I350 Gigabit Network Connection
pci@0000:08:00.1  eth1       network        I350 Gigabit Network Connection
...
```

Given this output, set `GATEKEEPER_INTERFACES` as below:

```sh
GATEKEEPER_INTERFACES="08:00.0 08:00.1"
```

In the same file, you can optionally specify
[Environmental Abstraction Layer options](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html)
in the `DPDK_ARGS` variable and
[Gatekeeper-specific options](https://github.com/AltraMayor/gatekeeper/wiki/Configuration#application-configuration)
in `GATEKEEPER_ARGS`.

#### How to run

Run the commands below to start Gatekeeper and to ensure it is started
automatically on reboots.

```console
$ sudo systemctl start gatekeeper
$ sudo systemctl enable gatekeeper
```

### Option 2: Build from Source

#### Install Dependencies

Install the following software dependencies:

```console
$ sudo apt-get update
$ sudo apt-get -y -q install git clang devscripts doxygen libhugetlbfs-bin \
    build-essential gcc-multilib linux-headers-`uname -r` libmnl0 libmnl-dev \
    libkmod2 libkmod-dev libnuma-dev libelf1 libelf-dev libc6-dev-i386 \
    autoconf flex bison libncurses5-dev libreadline-dev python \
    libcap-dev libcap2 meson ninja-build pkg-config
```

Note: Both `libmnl0` and `libmnl-dev` are needed to compile and run
`gatekeeper`, but only `libmnl0` is needed for simply running `gatekeeper`.
Both `libkmod2` and `libkmod-dev` are needed to compile and run `gatekeeper`,
but only `libkmod2` is needed for simply running `gatekeeper`.
`libnuma-dev` is needed to compile the latest DPDK and to support NUMA systems.
The package `libelf-dev` is needed to compile DPDK with support to reading
BPF programs from ELF files, but only `libelf1` is needed to run it.
The package `libc6-dev-i386` is needed to compile the BPF programs in
the folder `bpf/`.
The `autoconf`, `flex`, `bison`, `libncurses5-dev`, and
`libreadline-dev` packages are for BIRD. The `devscripts` package is used to
build Gatekeeper Debian packages.
`python` is needed to be able to run the `dpdk-devbind.py` script.
`libcap-dev` is needed to compile Gatekeeper, but only `libcap2` is needed
to run Gatekeeper.
`meson` and `ninja-build` are needed for building DPDK.
`pkg-config` is needed to compile Gatekeeper.

To use DPDK, make sure you have all of the [environmental requirements](http://dpdk.org/doc/guides/linux_gsg/sys_reqs.html#running-dpdk-application).

#### Clone Repository

Clone the Gatekeeper repository, including the submodules that
contain Gatekeeper dependencies:

```console
$ git clone --recursive http://github.com/AltraMayor/gatekeeper.git
```

If you do not use the `--recursive` clone option, you need to obtain the
submodules that contain the dependences from within the `gatekeeper`
directory:

```console
$ git submodule init
$ git submodule update
```

#### Compile

This section explains how to build Gatekeeper manually. If you want to build
Debian packages, refer to the section
[How to build packages](#how-to-build-packages).

While in the `gatekeeper` directory, run the setup script:

```console
$ . setup.sh
```

This script compiles DPDK, LuaJIT, and BIRD, and loads the needed
kernel modules. Additionally, it saves the interface names and their
respective PCI addresses in the file `lua/if_map.lua` so that interface
names can be used in the Gatekeeper configuration files.

Once DPDK and LuaJIT are compiled, `gatekeeper` can be compiled:

```console
$ make
```

#### Configure Network Adapters

Before `gatekeeper` can be used, the network adapters must be bound to DPDK.
For this, you can use the script `dependencies/dpdk/usertools/dpdk-devbind.py`.
For example:

```console
$ sudo dependencies/dpdk/usertools/dpdk-devbind.py --bind=vfio-pci enp131s0f0
```

This command binds the interface `enp131s0f0` to the `vfio-pci` driver
so that frames can be passed directly to DPDK instead of the kernel. Note
that this binding must take place after Gatekeeper is setup in the steps
above so that the bound interface appears in the list of interfaces in
`lua/if_map.lua`.

#### How to Run

Once `gatekeeper` is compiled and the environment is configured correctly, run:

```console
$ sudo build/gatekeeper [EAL OPTIONS] -- [GATEKEEPER OPTIONS]
```

Where `[EAL OPTIONS]` are specified before a double dash and represent the
parameters for DPDK's [Environmental Abstraction Layer](https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html)
and `[GATEKEEPER OPTIONS]` are specified after the double dash and
represent [Gatekeeper-specific options](https://github.com/AltraMayor/gatekeeper/wiki/Configuration#application-configuration).

The early configuration of the system, including device and memory
configuration in DPDK, will be logged to stdout. Once Gatekeeper is booted,
all information is output to the Gatekeeper log.

#### How to build packages

Gatekeeper Debian packages can be built with the commands below. They are meant
to be run from the repository root and assume the git submodules have been
pulled, and that the build dependencies have been installed, as instructed
above. Gatekeeper and the submodules will be automatically compiled during the
package build process.

```console
$ tar --exclude-vcs -Jcvf ../gatekeeper_1.1.0.orig.tar.xz -C .. gatekeeper
$ debuild -uc -us
```

The Gatekeeper package will be available in the parent directory.
