/*
 * Gatekeeper - DDoS protection system.
 * Copyright (C) 2016 Digirati LTDA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>

#include "gatekeeper_main.h"
#include "kni.h"

/*
 * XXX #677 Adopt RTE_ETHER_ADDR_PRT_FMT and RTE_ETHER_ADDR_BYTES
 * once DPDK is updated.
 */
/**
 * Macro to print six-bytes of MAC address in hex format
 */
#define RTE_ETHER_ADDR_PRT_FMT     "%02X:%02X:%02X:%02X:%02X:%02X"
/**
 * Macro to extract the MAC address bytes from rte_ether_addr struct
 */
#define RTE_ETHER_ADDR_BYTES(mac_addrs) ((mac_addrs)->addr_bytes[0]), \
					 ((mac_addrs)->addr_bytes[1]), \
					 ((mac_addrs)->addr_bytes[2]), \
					 ((mac_addrs)->addr_bytes[3]), \
					 ((mac_addrs)->addr_bytes[4]), \
					 ((mac_addrs)->addr_bytes[5])

#define KNI_BUS_NAME "vdev"

void
kni_free(struct cps_kni *kni)
{
	int ret;

	if (unlikely(kni->cps_name[0] == '\0'))
		return;

	ret = rte_eal_hotplug_remove(KNI_BUS_NAME, kni->cps_name);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to remove virtio_user port (errno=%i): %s\n",
			__func__, kni->cps_name, -ret, rte_strerror(-ret));
	}
	kni->cps_name[0] = '\0';
}

static int
setup_dpdk_interface(struct cps_kni *kni, const struct gatekeeper_if *iface,
	struct rte_mempool *mp, uint16_t queue_size)
{
	struct rte_eth_conf port_conf = {};

	int ret = rte_eth_dev_get_port_by_name(kni->cps_name, &kni->cps_portid);
	if (unlikely(ret < 0)) {
		G_LOG(ERR,
			"%s(%s): cannot get port ID of \"%s\" (errno=%i): %s\n",
			__func__, iface->name, kni->cps_name,
			-ret, rte_strerror(-ret));
		return ret;
	}

	ret = rte_eth_dev_set_mtu(kni->cps_portid, iface->mtu);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): cannot set the MTU=%u (errno=%i): %s\n",
			__func__, iface->name, iface->mtu,
			-ret, rte_strerror(-ret));
		return ret;
	}

	ret = rte_eth_dev_configure(kni->cps_portid, 1, 1, &port_conf);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to configure port (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}

	ret = rte_eth_rx_queue_setup(kni->cps_portid, 0, queue_size,
		mp->socket_id, NULL, mp);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to set up rx queue (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}

	ret = rte_eth_tx_queue_setup(kni->cps_portid, 0, queue_size,
		mp->socket_id, NULL);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to set up tx queue (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}

	ret = rte_eth_dev_start(kni->cps_portid);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to start port (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		return ret;
	}

	return 0;
}

static int
modify_ipaddr(struct mnl_socket *nl, unsigned int cmd, int flags, int family,
	const void *ipaddr, uint8_t prefixlen, const char *kni_name,
	unsigned int kni_index)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	unsigned int seq;
	unsigned int portid = mnl_socket_get_portid(nl);
	int ret;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = cmd;
	nlh->nlmsg_flags = flags|NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
	ifa->ifa_family = family;
	ifa->ifa_prefixlen = prefixlen;
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	ifa->ifa_index = kni_index;

	if (ifa->ifa_family == AF_INET)
		mnl_attr_put_u32(nlh, IFA_LOCAL, *(const uint32_t *)ipaddr);
	else if (likely(ifa->ifa_family == AF_INET6))
		mnl_attr_put(nlh, IFA_LOCAL, 16, ipaddr);
	else {
		G_LOG(CRIT, "%s(): bug: address family (%i) not recognized\n",
			__func__, family);
		return -EINVAL;
	}

	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (unlikely(ret < 0)) {
		ret = -errno;
		G_LOG(ERR, "%s(%s): mnl_socket_sendto() failed, cannot update IP address (family=%i, operation=%u, errno=%i): %s\n",
			__func__, kni_name, family, cmd,
			errno, strerror(errno));
		return ret;
	}

	/*
	 * We specified NLM_F_ACK to get an acknowledgement, so receive the
	 * ACK and verify that the interface configuration message was valid
	 * using the default libmnl callback for doing message verification.
	 */

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (unlikely(ret == -1)) {
		ret = -errno;
		G_LOG(ERR, "%s(%s): mnl_socket_recvfrom() failed, cannot update IP address (family=%i, operation=%u, errno=%i): %s\n",
			__func__, kni_name, family, cmd,
		       errno, strerror(errno));
		return ret;
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (unlikely(ret == MNL_CB_ERROR)) {
		ret = -errno;
		G_LOG(ERR, "%s(%s): mnl_cb_run() failed, cannot update IP address (family=%i, operation=%u, errno=%i): %s\n",
			__func__, kni_name, family, cmd,
			errno, strerror(errno));
		return ret;
	}

	return ret;
}

static inline int
add_ipaddr(struct mnl_socket *nl, int family, const void *ipaddr,
	uint8_t prefixlen, const char *kni_name, unsigned int kni_index)
{
	return modify_ipaddr(nl, RTM_NEWADDR,
		NLM_F_CREATE|NLM_F_REQUEST|NLM_F_EXCL, family,
		ipaddr, prefixlen, kni_name, kni_index);
}

/* Add global and link-local IPv4 and IPv6 addresses. */
static int
config_ip_addrs(struct mnl_socket *nl, const char *kni_name,
	unsigned int kni_index, const struct gatekeeper_if *iface)
{
	int ret;

	if (ipv4_if_configured(iface)) {
		ret = add_ipaddr(nl, AF_INET, &iface->ip4_addr,
			iface->ip4_addr_plen, kni_name, kni_index);
		if (unlikely(ret < 0))
			return ret;
	}

	if (ipv6_if_configured(iface)) {
		ret = add_ipaddr(nl, AF_INET6, &iface->ip6_addr,
			iface->ip6_addr_plen, kni_name, kni_index);
		if (unlikely(ret < 0))
			return ret;
	}

	return 0;
}

static int
modify_link(struct mnl_socket *nl, const char *kni_name,
	unsigned int kni_index,	uint32_t mtu, int if_up)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	unsigned int seq, flags = 0;
	unsigned int portid = mnl_socket_get_portid(nl);
	int ret;

	if (if_up)
		flags |= IFF_UP;
	else
		flags &= ~IFF_UP;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
	nlh->nlmsg_seq = seq = time(NULL);

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
	ifm->ifi_family = AF_UNSPEC;
	ifm->ifi_index = kni_index;
	ifm->ifi_flags = flags;
	ifm->ifi_change = IFF_UP;

	mnl_attr_put_u32(nlh, IFLA_MTU, mtu);

	ret = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
	if (unlikely(ret < 0)) {
		ret = -errno;
		G_LOG(ERR, "%s(%s): mnl_socket_sendto() failed, cannot bring KNI %s (errno=%i): %s\n",
			__func__, kni_name, if_up ? "up" : "down",
			errno, strerror(errno));
		return ret;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (unlikely(ret == -1)) {
		ret = -errno;
		G_LOG(ERR, "%s(%s): mnl_socket_recvfrom() failed, cannot bring KNI %s (errno=%i): %s\n",
			__func__, kni_name, if_up ? "up" : "down",
			errno, strerror(errno));
		return ret;
	}

	ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
	if (unlikely(ret == MNL_CB_ERROR)) {
		ret = -errno;
		G_LOG(ERR, "%s(%s): mnl_cb_run() failed, cannot bring KNI %s (errno=%i): %s\n",
			__func__, kni_name, if_up ? "up" : "down",
			errno, strerror(errno));
		return ret;
	}

	return 0;
}

static int
setup_kernel_interface(const struct cps_kni *kni,
	const struct gatekeeper_if *iface)
{
	struct mnl_socket *nl;
	int ret;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (unlikely(nl == NULL)) {
		ret = -errno;
		G_LOG(ERR, "%s(%s): mnl_socket_open() failed (errno=%i): %s\n",
			__func__, kni->krn_name, errno, strerror(errno));
		return ret;
	}

	ret = mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): mnl_socket_bind() failed (errno=%i): %s\n",
			__func__, kni->krn_name, errno, strerror(errno));
		goto close;
	}

	ret = config_ip_addrs(nl, kni->krn_name, kni->krn_ifindex, iface);
	if (unlikely(ret < 0))
		goto close;

	/* Set MTU and bring interface up. */
	ret = modify_link(nl, kni->krn_name, kni->krn_ifindex,
		iface->mtu, true);

close:
	mnl_socket_close(nl);
	return ret;
}

static int
cps_port_name(char *port_name, uint8_t port_id)
{
	 int ret = snprintf(port_name, IF_NAMESIZE, "virtio_user%u", port_id);
	 if (unlikely(ret < 0)) {
		 G_LOG(ERR,
			"%s(port_id=%u): snprintf() failed (errno=%i): %s\n",
			__func__, port_id, -ret, strerror(-ret));
		 return ret;
	 }
	 if (unlikely(ret >= IF_NAMESIZE)) {
		 G_LOG(ERR, "%s(port_id=%u): port name is too long (len=%i)\n",
			__func__, port_id, ret);
		 return -ENOSPC;
	 }
	 return 0;
}

static int
kernel_port_name(char *port_name, const char *origin_port_name)
{
	 int ret = snprintf(port_name, IF_NAMESIZE, "kni_%s", origin_port_name);
	 if (unlikely(ret < 0)) {
		 G_LOG(ERR, "%s(%s): snprintf() failed (errno=%i): %s\n",
			__func__, origin_port_name, -ret, strerror(-ret));
		 return ret;
	 }
	 if (unlikely(ret >= IF_NAMESIZE)) {
		 G_LOG(ERR, "%s(%s): port name is too long (len=%i)\n",
			__func__, origin_port_name, ret);
		 return -ENOSPC;
	 }
	 return 0;
}

int
kni_create(struct cps_kni *kni, const struct gatekeeper_if *iface,
	struct rte_mempool *mp, uint16_t queue_size)
{
	char cps_name[IF_NAMESIZE], port_args[256];

	int ret = cps_port_name(cps_name, iface->id);
	if (unlikely(ret < 0)) {
		G_LOG(ERR,
			"%s(%s): cannot name virtio_user port (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		goto out;
	}

	ret = kernel_port_name(kni->krn_name, iface->name);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): cannot name kernel port (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		goto out;
	}

	/* Get @port_args. */
	ret = snprintf(port_args, sizeof(port_args),
		"path=/dev/vhost-net,queues=%u,queue_size=%u,iface=%s,mac="
			RTE_ETHER_ADDR_PRT_FMT,
		1, queue_size, kni->krn_name,
		RTE_ETHER_ADDR_BYTES(&iface->eth_addr));
	if (unlikely(ret < 0)) {
		G_LOG(CRIT, "%s(%s): bug: snprintf() failed (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		goto out;
	 }
	 if (unlikely(ret >= (int)sizeof(port_args))) {
		G_LOG(CRIT, "%s(%s): bug: port argument is too long (len=%i)\n",
			__func__, iface->name, ret);
		ret = -ENOSPC;
		goto out;
	 }

	ret = rte_eal_hotplug_add(KNI_BUS_NAME, cps_name, port_args);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to initialize virtio-user port (errno=%i): %s\n",
			__func__, iface->name, -ret, rte_strerror(-ret));
		goto out;
	}
	RTE_BUILD_BUG_ON(sizeof(kni->cps_name) != sizeof(cps_name));
	strcpy(kni->cps_name, cps_name);

	/*
	 * DPDK does not return the index of the kernel interface, and
	 * the kernel allows other applications to rename any interface.
	 * Therefore, there is potentially a race condition here.
	 * To minimize the chance of being affected by this race condition,
	 * obtain the index of the kernel interface as soon as possible.
	 */
	kni->krn_ifindex = if_nametoindex(kni->krn_name);
	if (unlikely(kni->krn_ifindex == 0)) {
		ret = -errno;
		G_LOG(ERR, "%s(%s): cannot get index for interface \"%s\" (errno=%i): %s\n",
			__func__, iface->name, kni->krn_name,
			errno, strerror(errno));
		goto free_kni;
	}

	ret = setup_dpdk_interface(kni, iface, mp, queue_size);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to set up DPDK interface (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		goto free_kni;
	}

	ret = setup_kernel_interface(kni, iface);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to set up kernel interface (errno=%i): %s\n",
			__func__, iface->name, -ret, strerror(-ret));
		goto free_kni;
	}

	return 0;

free_kni:
	kni_free(kni);
out:
	return ret;
}
