/*
 * Gatekeeper - DoS protection system.
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

#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/random.h>
#include <sys/syscall.h>
#include <pwd.h>
#include <grp.h>

#include <rte_mbuf.h>
#include <rte_thash.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>
#include <rte_malloc.h>

#include "gatekeeper_acl.h"
#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"

static struct net_config config;
/*
 * The secret key of the RSS hash (RSK) must be random in order
 * to prevent hackers from knowing it.
 */
uint8_t default_rss_key[GATEKEEPER_RSS_KEY_LEN];

static int
randomize_rss_key(int guarantee_random_entropy)
{
	uint16_t final_set_count;
	unsigned int flags = guarantee_random_entropy == 0 ? 0 : GRND_RANDOM;

	/*
	 * To validate if the key generated is reasonable, the
	 * number of bits set to 1 in the key must be greater than 
	 * 10% and less than 90% of the total bits in the key.
	 * min_num_set_bits and max_num_set_bits represent the lower 
	 * and upper bound for the key.
	 */
	const uint16_t min_num_set_bits = sizeof(default_rss_key) * 8 * 0.1;
	const uint16_t max_num_set_bits = sizeof(default_rss_key) * 8 * 0.9;

	do {	
		int number_of_bytes = 0;
		uint8_t i;

		/* 
		 * When the last parameter of the system call  getrandom()
		 * (i.e flags) is zero, getrandom() uses the /dev/urandom pool.
		 */	
		do {
			int ret = syscall(SYS_getrandom,
				default_rss_key + number_of_bytes,
				sizeof(default_rss_key) - number_of_bytes,
				flags);
			if (ret < 0)
				return -1;
			number_of_bytes += ret;	
		} while (number_of_bytes < (int)sizeof(default_rss_key));

		final_set_count = 0;
		for (i = 0; i < RTE_DIM(default_rss_key); i++) {
			final_set_count +=
				__builtin_popcount(default_rss_key[i]);
		}
	} while (final_set_count < min_num_set_bits ||
			final_set_count > max_num_set_bits);
	return 0;
}

/* To support the optimized implementation of generic RSS hash function. */
uint8_t rss_key_be[RTE_DIM(default_rss_key)];

/*
 * @ether_type should be passed in host ordering, but is converted
 * to little endian ordering before being added as a filter. The
 * EType register's value should be in little endian, according to
 * the 82599 datasheet.
 *
 * Does the endianness change with other NICs?
 * 	We have checked the source code of three DPDK networking drivers:
 *	i40e, ixgbe, e1000. And all of them use little endian order.
 *	However, we didn't find the parts for other drivers. We tried to
 *	ask help from the DPDK mailinglist, but didn't get reply.
 */
int
ethertype_filter_add(struct gatekeeper_if *iface, uint16_t ether_type,
	uint16_t queue_id)
{
	struct rte_eth_ethertype_filter filter = {
		.ether_type = rte_cpu_to_le_16(ether_type),
		.flags = 0,
		.queue = queue_id,
	};
	unsigned int i;
	int ret;

	RTE_VERIFY(iface->hw_filter_eth);

	for (i = 0; i < iface->num_ports; i++) {
		uint16_t port_id = iface->ports[i];
		ret = rte_eth_dev_filter_ctrl(port_id,
			RTE_ETH_FILTER_ETHERTYPE,
			RTE_ETH_FILTER_ADD,
			&filter);
		if (ret == -ENOTSUP) {
			G_LOG(NOTICE,
				"net: hardware doesn't support adding an EtherType filter for 0x%02hx on port %hhu\n",
				ether_type, port_id);
			ret = -1;
			goto out;
		} else if (ret == -ENODEV) {
			G_LOG(NOTICE,
				"net: port %hhu is invalid for adding an EtherType filter for 0x%02hx\n",
				port_id, ether_type);
			ret = -1;
			goto out;
		} else if (ret != 0) {
			G_LOG(NOTICE,
				"net: other errors that depend on the specific operations implementation on port %hhu for adding an EtherType filter for 0x%02hx\n",
				port_id, ether_type);
			ret = -1;
			goto out;
		}
	}

	ret = 0;

out:
	return ret;
}

/*
 * @dst_ip, @src_port, @src_port_mask, @dst_port, and @dst_port_mask
 * must be in big endian.
 *
 * By specifying the tuple (proto, src_port, dst_port) (and masks),
 * it can filter both IPv4 and IPv6 addresses.
 */
int
ntuple_filter_add(struct gatekeeper_if *iface, uint32_t dst_ip,
	uint16_t src_port, uint16_t src_port_mask,
	uint16_t dst_port, uint16_t dst_port_mask,
	uint8_t proto, uint16_t queue_id,
	int ipv4_configured, int ipv6_configured)
{
	int ret = 0;
	unsigned int i;
	struct rte_eth_ntuple_filter filter_v4 = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = dst_ip,
		.dst_ip_mask = UINT32_MAX,
		.src_ip = 0,
		.src_ip_mask = 0,
		.dst_port = dst_port,
		.dst_port_mask = dst_port_mask,
		.src_port = src_port,
		.src_port_mask = src_port_mask,
		.proto = proto,
		.proto_mask = UINT8_MAX,
		.tcp_flags = 0,
		.priority = 1,
		.queue = queue_id,
	};

	struct rte_eth_ntuple_filter filter_v6 = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = 0,
		.dst_ip_mask = 0,
		.src_ip = 0,
		.src_ip_mask = 0,
		.dst_port = dst_port,
		.dst_port_mask = dst_port_mask,
		.src_port = src_port,
		.src_port_mask = src_port_mask,
		.proto = proto,
		.proto_mask = UINT8_MAX,
		.tcp_flags = 0,
		.priority = 1,
		.queue = queue_id,
	};

	RTE_VERIFY(iface->hw_filter_ntuple);

	if (!ipv4_configured)
		goto ipv6;

	for (i = 0; i < iface->num_ports; i++) {
		uint16_t port_id = iface->ports[i];
		ret = rte_eth_dev_filter_ctrl(port_id,
			RTE_ETH_FILTER_NTUPLE,
			RTE_ETH_FILTER_ADD,
			&filter_v4);
		if (ret == -ENOTSUP) {
			G_LOG(ERR,
				"net: hardware doesn't support adding an IPv4 ntuple filter on port %hhu\n",
				port_id);
			ret = -1;
			goto out;
		} else if (ret == -ENODEV) {
			G_LOG(ERR,
				"net: port %hhu is invalid for adding an IPv4 ntuple filter\n",
				port_id);
			ret = -1;
			goto out;
		} else if (ret != 0) {
			G_LOG(ERR,
				"net: other errors that depend on the specific operations implementation on port %hhu for adding an IPv4 ntuple filter\n",
				port_id);
			ret = -1;
			goto out;
		}
	}
ipv6:
	if (!ipv6_configured)
		goto out;

	for (i = 0; i < iface->num_ports; i++) {
		uint16_t port_id = iface->ports[i];
		ret = rte_eth_dev_filter_ctrl(port_id,
			RTE_ETH_FILTER_NTUPLE,
			RTE_ETH_FILTER_ADD,
			&filter_v6);
		if (ret == -ENOTSUP) {
			G_LOG(ERR,
				"net: hardware doesn't support adding an IPv6 ntuple filter on port %hhu\n",
				port_id);
			ret = -1;
			goto out;
		} else if (ret == -ENODEV) {
			G_LOG(ERR,
				"net: port %hhu is invalid for adding an IPv6 ntuple filter\n",
				port_id);
			ret = -1;
			goto out;
		} else if (ret != 0) {
			G_LOG(ERR,
				"net: other errors that depend on the specific operations implementation on port %hhu for adding an IPv6 ntuple filter\n",
				port_id);
			ret = -1;
			goto out;
		}
	}

	ret = 0;
out:
	return ret;
}

static uint32_t
find_num_numa_nodes(void)
{
	unsigned int i;
	uint32_t nb_numa_nodes = 0;

	RTE_LCORE_FOREACH(i) {
		uint32_t socket_id = rte_lcore_to_socket_id(i);
		if (nb_numa_nodes <= socket_id)
			nb_numa_nodes = socket_id + 1;
	}
	
	return nb_numa_nodes;
}

static int
configure_queue(struct gatekeeper_if *iface, uint16_t port_id,
	uint16_t queue_id, enum queue_type ty,
	unsigned int numa_node, struct rte_mempool *mp)
{
	int ret;

	switch (ty) {
	case QUEUE_TYPE_RX:
		ret = rte_eth_rx_queue_setup(port_id, queue_id,
			iface->num_rx_desc, numa_node, NULL, mp);
		if (ret < 0) {
			G_LOG(ERR, "net: failed to configure port %hhu rx_queue %hu (err=%d)\n",
				port_id, queue_id, ret);
			return ret;
		}
		break;
	case QUEUE_TYPE_TX:
		ret = rte_eth_tx_queue_setup(port_id, queue_id,
			iface->num_tx_desc, numa_node, NULL);
		if (ret < 0) {
			G_LOG(ERR, "net: failed to configure port %hhu tx_queue %hu (err=%d)\n",
				port_id, queue_id, ret);
			return ret;
		}
		break;
	default:
		G_LOG(ERR, "net: unsupported queue type (%d) passed to %s\n",
			ty, __func__);
		return -1;
	}

	return 0;
}

static inline int
iface_bonded(struct gatekeeper_if *iface)
{
	return iface->num_ports > 1 ||
		iface->bonding_mode == BONDING_MODE_8023AD;
}

/*
 * Get a queue identifier for a given functional block instance (lcore),
 * using a certain interface for either RX or TX.
 */
int
get_queue_id(struct gatekeeper_if *iface, enum queue_type ty,
	unsigned int lcore, struct rte_mempool *mp)
{
	int16_t *queues;
	int ret;
	uint16_t port;
	unsigned int numa_node;
	int16_t new_queue_id;

	RTE_VERIFY(lcore < RTE_MAX_LCORE);
	RTE_VERIFY(ty < QUEUE_TYPE_MAX);

	queues = (ty == QUEUE_TYPE_RX) ? iface->rx_queues : iface->tx_queues;

	if (queues[lcore] != GATEKEEPER_QUEUE_UNALLOCATED)
		goto queue;

	/* Get next queue identifier. */
	new_queue_id = rte_atomic16_add_return(ty == QUEUE_TYPE_RX ?
		&iface->rx_queue_id : &iface->tx_queue_id, 1);
	if (new_queue_id == GATEKEEPER_QUEUE_UNALLOCATED) {
		G_LOG(ERR, "net: exhausted all %s queues for the %s interface; this is likely a bug\n",
			(ty == QUEUE_TYPE_RX) ? "RX" : "TX", iface->name);
		return -1;
	}
	queues[lcore] = new_queue_id;

	/*
	 * Configure this queue on all ports of this interface.
	 *
	 * Note that if we are using a bonded port, it is not
	 * sufficient to only configure the queue on that bonded
	 * port. All slave ports must be configured and started
	 * before the bonded port can be started.
	 */
	numa_node = rte_lcore_to_socket_id(lcore);
	for (port = 0; port < iface->num_ports; port++) {
		ret = configure_queue(iface, iface->ports[port],
			(uint16_t)new_queue_id, ty, numa_node, mp);
		if (ret < 0)
			return ret;
	}

	/* If there's a bonded port, configure it too. */
	if (iface_bonded(iface)) {
		ret = configure_queue(iface, iface->id, (uint16_t)new_queue_id,
			ty, numa_node, mp);
		if (ret < 0)
			return ret;
	}

queue:
	return queues[lcore];
}

static void
stop_iface_ports(struct gatekeeper_if *iface, uint8_t nb_ports)
{
	uint8_t i;
	for (i = 0; i < nb_ports; i++)
		rte_eth_dev_stop(iface->ports[i]);
}

static void
rm_slave_ports(struct gatekeeper_if *iface, uint8_t nb_slave_ports)
{
	uint8_t i;
	for (i = 0; i < nb_slave_ports; i++)
		rte_eth_bond_slave_remove(iface->id, iface->ports[i]);
}

static void
close_iface_ports(struct gatekeeper_if *iface, uint8_t nb_ports)
{
	uint8_t i;
	for (i = 0; i < nb_ports; i++)
		rte_eth_dev_close(iface->ports[i]);
}

enum iface_destroy_cmd {
	/* Destroy only the data allocated by Lua. */
	IFACE_DESTROY_LUA,
	/* Destroy the data associated with initializing the ports. */
	IFACE_DESTROY_PORTS,
	/* Destroy the data initialized by the first phase of net config. */
	IFACE_DESTROY_INIT,
	/* Destroy all data for this interface. */
	IFACE_DESTROY_ALL,
};

static void
destroy_iface(struct gatekeeper_if *iface, enum iface_destroy_cmd cmd)
{
	if (!iface->alive)
		return;

	switch (cmd) {
	case IFACE_DESTROY_ALL:
		/* Destroy the ACLs for each socket. */
		if (ipv6_acl_enabled(iface))
			destroy_acls(&iface->ipv6_acls);
		if (ipv4_acl_enabled(iface))
			destroy_acls(&iface->ipv4_acls);
		/* Stop interface ports (bonded port is stopped below). */
		stop_iface_ports(iface, iface->num_ports);
		/* FALLTHROUGH */
	case IFACE_DESTROY_INIT:
		/* Remove any slave ports added to a bonded port. */
		if (iface_bonded(iface))
			rm_slave_ports(iface, iface->num_ports);
		/* FALLTHROUGH */
	case IFACE_DESTROY_PORTS:
		/* Stop and close bonded port, if needed. */
		if (iface_bonded(iface))
			rte_eth_bond_free(iface->name);

		/* Close and free interface ports. */
		close_iface_ports(iface, iface->num_ports);
		rte_free(iface->ports);
		iface->ports = NULL;
		/* FALLTHROUGH */
	case IFACE_DESTROY_LUA: {
		/* Free PCI addresses. */
		uint8_t i;
		for (i = 0; i < iface->num_ports; i++)
			rte_free(iface->pci_addrs[i]);
		rte_free(iface->pci_addrs);
		iface->pci_addrs = NULL;

		/* Free interface name. */
		rte_free(iface->name);
		iface->name = NULL;

		iface->alive = false;

		break;
	}
	default:
		rte_panic("Unexpected condition\n");
		break;
	}
}

int
get_ip_type(const char *ip_addr)
{
	int ret;
	struct addrinfo hint;
	struct addrinfo *res = NULL;

	memset(&hint, 0, sizeof(hint));

	hint.ai_family = PF_UNSPEC;
	hint.ai_flags = AI_NUMERICHOST;

	ret = getaddrinfo(ip_addr, NULL, &hint, &res);
	if (ret) {
		G_LOG(ERR, "net: invalid ip address %s; %s\n",
			ip_addr, gai_strerror(ret));
		return AF_UNSPEC;
	}

	if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
		G_LOG(ERR, "net: %s is an is unknown address format %d\n",
			ip_addr, res->ai_family);

	ret = res->ai_family;
   	freeaddrinfo(res);

	return ret;
}

int
convert_str_to_ip(const char *ip_addr, struct ipaddr *res)
{
	int ip_type = get_ip_type(ip_addr);
	if (ip_type == AF_INET) {
		if (inet_pton(AF_INET, ip_addr, &res->ip.v4) != 1)
			return -1;

		res->proto = RTE_ETHER_TYPE_IPV4;
	} else if (likely(ip_type == AF_INET6)) {
		if (inet_pton(AF_INET6, ip_addr, &res->ip.v6) != 1)
			return -1;

		res->proto = RTE_ETHER_TYPE_IPV6;
	} else
		return -1;

	return 0;
}

int
convert_ip_to_str(const struct ipaddr *ip_addr, char *res, int n)
{
	if (ip_addr->proto == RTE_ETHER_TYPE_IPV4) {
		if (inet_ntop(AF_INET, &ip_addr->ip.v4, res, n) == NULL) {
			G_LOG(ERR, "net: %s: failed to convert a number to an IPv4 address (%s)\n",
				__func__, strerror(errno));
			return -1;
		}
	} else if (likely(ip_addr->proto == RTE_ETHER_TYPE_IPV6)) {
		if (inet_ntop(AF_INET6, &ip_addr->ip.v6, res, n) == NULL) {
			G_LOG(ERR, "net: %s: failed to convert a number to an IPv6 address (%s)\n",
				__func__, strerror(errno));
			return -1;
		}
	} else {
		G_LOG(ERR, "net: unexpected condition at %s: unknown IP type %hu\n",
			__func__, ip_addr->proto);
		return -1;
	}

	return 0;
}

int
lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs,
	const char **ip_cidrs, uint8_t num_ip_cidrs, uint16_t vlan_tag)
{
	uint8_t i, j;

	if (num_ip_cidrs < 1 || num_ip_cidrs > 2) {
		G_LOG(ERR,
			"net: an interface has at least 1 IP address, also at most 1 IPv4 and 1 IPv6 address.\n");
		return -1;
	}

	iface->num_ports = num_pci_addrs;

	iface->name = rte_malloc("iface_name", strlen(iface_name) + 1, 0);
	if (iface->name == NULL) {
		G_LOG(ERR, "net: %s: Out of memory for iface name\n",
			__func__);
		return -1;
	}
	strcpy(iface->name, iface_name);

	iface->pci_addrs = rte_calloc("pci_addrs", num_pci_addrs,
		sizeof(*pci_addrs), 0);
	if (iface->pci_addrs == NULL) {
		G_LOG(ERR, "net: %s: Out of memory for PCI array\n",
			__func__);
		goto name;
	}

	for (i = 0; i < num_pci_addrs; i++) {
		iface->pci_addrs[i] = rte_malloc(NULL,
			strlen(pci_addrs[i]) + 1, 0);
		if (iface->pci_addrs[i] == NULL) {
			G_LOG(ERR,
				"net: %s: Out of memory for PCI address %s\n",
				__func__, pci_addrs[i]);
			for (j = 0; j < i; j++)
				rte_free(iface->pci_addrs[j]);
			rte_free(iface->pci_addrs);
			iface->pci_addrs = NULL;
			goto name;
		}
		strcpy(iface->pci_addrs[i], pci_addrs[i]);
	}

	for (i = 0; i < num_ip_cidrs; i++) {
		/* Need to make copy to tokenize. */
		size_t ip_cidr_len = strlen(ip_cidrs[i]);
		char ip_cidr_copy[ip_cidr_len + 1];
		char *ip_addr;

		char *saveptr;
		char *prefix_len_str;
		char *end;
		long prefix_len;
		int gk_type;

		strncpy(ip_cidr_copy, ip_cidrs[i], ip_cidr_len + 1);

		ip_addr = strtok_r(ip_cidr_copy, "/", &saveptr);
		if (ip_addr == NULL)
			goto pci_addrs;

		gk_type = get_ip_type(ip_addr);
		if (gk_type == AF_INET &&
				inet_pton(AF_INET, ip_addr,
				&iface->ip4_addr) == 1) {
			iface->configured_proto |= CONFIGURED_IPV4;
		}
		else if (gk_type == AF_INET6 &&
				inet_pton(AF_INET6, ip_addr,
				&iface->ip6_addr) == 1) {
			iface->configured_proto |= CONFIGURED_IPV6;
		}
		else
			goto pci_addrs;

		prefix_len_str = strtok_r(NULL, "\0", &saveptr);
		if (prefix_len_str == NULL)
			goto pci_addrs;

		prefix_len = strtol(prefix_len_str, &end, 10);
		if (prefix_len_str == end || !*prefix_len_str || *end) {
			G_LOG(ERR,
				"net: prefix length \"%s\" is not a number\n",
				prefix_len_str);
			goto pci_addrs;
		}
		if ((prefix_len == LONG_MAX || prefix_len == LONG_MIN) &&
				errno == ERANGE) {
			G_LOG(ERR,
				"net: prefix length \"%s\" caused underflow or overflow\n",
				prefix_len_str);
			goto pci_addrs;
		}
		if (prefix_len < 0 || prefix_len > max_prefix_len(gk_type)) {
			G_LOG(ERR,
				"net: prefix length \"%s\" is out of range\n",
				prefix_len_str);
			goto pci_addrs;
		}

		if (gk_type == AF_INET) {
			ip4_prefix_mask(prefix_len, &iface->ip4_mask);
			iface->ip4_addr_plen = prefix_len;
		} else if (gk_type == AF_INET6) {
			ip6_prefix_mask(prefix_len, &iface->ip6_mask);
			iface->ip6_addr_plen = prefix_len;
		}
	}

	iface->l2_len_out = sizeof(struct rte_ether_hdr);
	if (iface->vlan_insert) {
		iface->vlan_tag_be = rte_cpu_to_be_16(vlan_tag);
		iface->l2_len_out += sizeof(struct rte_vlan_hdr);
	}

	return 0;

pci_addrs:
	for (i = 0; i < num_pci_addrs; i++)
		rte_free(iface->pci_addrs[i]);
	rte_free(iface->pci_addrs);
	iface->pci_addrs = NULL;
name:
	rte_free(iface->name);
	iface->name = NULL;
	return -1;
}

struct net_config *
get_net_conf(void)
{
	return &config;
}

struct gatekeeper_if *
get_if_front(struct net_config *net_conf)
{
	return &net_conf->front;
}

struct gatekeeper_if *
get_if_back(struct net_config *net_conf)
{
	return net_conf->back_iface_enabled ? &net_conf->back : NULL;
}

/*
 * Split up ETH_RSS_IP into IPv4-related and IPv6-related hash functions.
 * For each type of IP being used in Gatekeeper, check the supported
 * hashes of the device. If none are supported, disable RSS. If
 * ETH_RSS_IPV{4,6} is not supported, issue a warning since we expect
 * this to be a common and critical hash function. Some devices (i40e
 * and AVF) do not support the ETH_RSS_IPV{4,6} hashes, but the hashes
 * they do support may be enough.
 */

#define GATEKEEPER_IPV4_RSS_HF ( \
	ETH_RSS_IPV4 | \
	ETH_RSS_FRAG_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_OTHER)

#define GATEKEEPER_IPV6_RSS_HF ( \
	ETH_RSS_IPV6 | \
	ETH_RSS_FRAG_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_OTHER | \
	ETH_RSS_IPV6_EX)

static int
check_port_rss(struct gatekeeper_if *iface, unsigned int port_idx,
	const struct rte_eth_dev_info *dev_info,
	struct rte_eth_conf *port_conf)
{
	uint8_t rss_hash_key[GATEKEEPER_RSS_KEY_LEN];
	struct rte_eth_rss_conf rss_conf = {
		.rss_key = rss_hash_key,
		.rss_key_len = GATEKEEPER_RSS_KEY_LEN,
	};
	uint64_t rss_off = dev_info->flow_type_rss_offloads;
	int ret = rte_eth_dev_rss_hash_conf_get(
		iface->ports[port_idx], &rss_conf);
	if (ret == -ENOTSUP) {
		G_LOG(NOTICE, "net: port %hu (%s) on the %s interface does not support to get RSS configuration, disable RSS\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name);
		goto disable_rss;
	} else if (ret != 0) {
		G_LOG(WARNING, "net: failed to get RSS hash configuration at port %hu (%s) on the %s interface - ret = %d\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name, ret);
		return ret;
	}

	/* This port doesn't support RSS, so disable RSS. */
	if (rss_off == 0) {
		G_LOG(NOTICE, "net: port %hu (%s) on the %s interface does not support RSS\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name);
		goto disable_rss;
	}

	if (dev_info->hash_key_size != sizeof(default_rss_key)) {
		G_LOG(NOTICE, "net: port %hu (%s) on the %s interface does not provide a valid hash key size %hhu (%lu)\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name, dev_info->hash_key_size,
			sizeof(default_rss_key));
		goto disable_rss;
	}

	/* Check IPv4 RSS hashes. */
	if (port_conf->rx_adv_conf.rss_conf.rss_hf & GATEKEEPER_IPV4_RSS_HF) {
		/* No IPv4 hashes are supported, so disable RSS. */
		if ((rss_off & GATEKEEPER_IPV4_RSS_HF) == 0) {
			G_LOG(NOTICE, "net: port %hu (%s) on the %s interface does not support any IPv4 related RSS hashes\n",
				iface->ports[port_idx], iface->pci_addrs[port_idx],
				iface->name);
			goto disable_rss;
		}

		/*
		 * The IPv4 hash that we think is typically
		 * used is not supported, so warn the user.
		 */
		if ((rss_off & ETH_RSS_IPV4) == 0) {
			G_LOG(WARNING, "net: port %hu (%s) on the %s interface does not support the ETH_RSS_IPV4 hash function; the device may not hash packets to the correct queues\n",
				iface->ports[port_idx],
				iface->pci_addrs[port_idx],
				iface->name);
		}
	}

	/* Check IPv6 RSS hashes. */
	if (port_conf->rx_adv_conf.rss_conf.rss_hf & GATEKEEPER_IPV6_RSS_HF) {
		/* No IPv6 hashes are supported, so disable RSS. */
		if ((rss_off & GATEKEEPER_IPV6_RSS_HF) == 0) {
			G_LOG(NOTICE, "net: port %hu (%s) on the %s interface does not support any IPv6 related RSS hashes\n",
				iface->ports[port_idx], iface->pci_addrs[port_idx],
				iface->name);
			goto disable_rss;
		}

		/*
		 * The IPv6 hash that we think is typically
		 * used is not supported, so warn the user.
		 */
		if ((rss_off & ETH_RSS_IPV6) == 0) {
			G_LOG(WARNING, "net: port %hu (%s) on the %s interface does not support the ETH_RSS_IPV6 hash function; the device may not hash packets to the correct queues\n",
				iface->ports[port_idx],
				iface->pci_addrs[port_idx],
				iface->name);
		}
	}

	/*
	 * Any missing hashes that will cause RSS to definitely fail
	 * or are likely to cause RSS to fail are handled above.
	 * Here, also log if the device doesn't support any of the requested
	 * hashes, including the hashes considered non-essential.
	 */
	if ((rss_off & port_conf->rx_adv_conf.rss_conf.rss_hf) !=
			port_conf->rx_adv_conf.rss_conf.rss_hf) {
		G_LOG(NOTICE,
			"net: port %hu (%s) on the %s interface only supports RSS hash functions 0x%"PRIx64", but Gatekeeper asks for 0x%"PRIx64"\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name, rss_off,
			port_conf->rx_adv_conf.rss_conf.rss_hf);
	}

	port_conf->rx_adv_conf.rss_conf.rss_hf &= rss_off;
	return 0;

disable_rss:
	iface->rss = false;
	port_conf->rx_adv_conf.rss_conf.rss_hf = 0;
	return 0;
}

static int
check_port_mtu(struct gatekeeper_if *iface, unsigned int port_idx,
	const struct rte_eth_dev_info *dev_info,
	struct rte_eth_conf *port_conf)
{
	if (dev_info->max_rx_pktlen < port_conf->rxmode.max_rx_pkt_len) {
		G_LOG(ERR,
			"net: port %hu (%s) on the %s interface only supports MTU of size %"PRIu32", but Gatekeeper is configured to be %"PRIu16"\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name, dev_info->max_rx_pktlen,
			port_conf->rxmode.max_rx_pkt_len);
		return -1;
	}

	if ((port_conf->rxmode.offloads & DEV_RX_OFFLOAD_JUMBO_FRAME) &&
			!(dev_info->rx_offload_capa &
			DEV_RX_OFFLOAD_JUMBO_FRAME)) {
		G_LOG(NOTICE, "net: port %hu (%s) on the %s interface doesn't support offloading for jumbo frames\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name);
		return -1;
	}

	if ((port_conf->txmode.offloads & DEV_TX_OFFLOAD_MULTI_SEGS) &&
			!(dev_info->tx_offload_capa &
			DEV_TX_OFFLOAD_MULTI_SEGS)) {
		G_LOG(NOTICE, "net: port %hu (%s) on the %s interface doesn't support offloading multi-segment TX buffers\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name);
		port_conf->txmode.offloads &= ~DEV_TX_OFFLOAD_MULTI_SEGS;
	}

	return 0;
}

static int
check_port_cksum(struct gatekeeper_if *iface, unsigned int port_idx,
	const struct rte_eth_dev_info *dev_info,
	struct rte_eth_conf *port_conf)
{
	if ((port_conf->txmode.offloads & DEV_TX_OFFLOAD_IPV4_CKSUM) &&
			!(dev_info->tx_offload_capa &
			DEV_TX_OFFLOAD_IPV4_CKSUM)) {
		G_LOG(NOTICE, "net: port %hu (%s) on the %s interface doesn't support offloading IPv4 checksumming\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name);
		port_conf->txmode.offloads &= ~DEV_TX_OFFLOAD_IPV4_CKSUM;
		return -1;
	}

	if ((port_conf->txmode.offloads & DEV_TX_OFFLOAD_UDP_CKSUM) &&
			!(dev_info->tx_offload_capa &
			DEV_TX_OFFLOAD_UDP_CKSUM)) {
		G_LOG(NOTICE, "net: port %hu (%s) on the %s interface doesn't support offloading UDP checksumming; will use software UDP checksums\n",
			iface->ports[port_idx], iface->pci_addrs[port_idx],
			iface->name);
		port_conf->txmode.offloads &= ~DEV_TX_OFFLOAD_UDP_CKSUM;
		iface->ipv4_hw_udp_cksum = false;
		iface->ipv6_hw_udp_cksum = false;
	}

	return 0;
}

static int
check_port_offloads(struct gatekeeper_if *iface,
	struct rte_eth_conf *port_conf)
{
	unsigned int i;

	RTE_BUILD_BUG_ON((GATEKEEPER_IPV4_RSS_HF | GATEKEEPER_IPV6_RSS_HF) !=
		ETH_RSS_IP);

	/*
	 * Set up device RSS.
	 *
	 * Assume all ports support RSS until shown otherwise.
	 * If not, RSS will be disabled and only one queue is used.
	 *
	 * Check each port for the RSS hash functions it supports,
	 * and configure each to use the intersection of supported
	 * hash functions.
	 */
	iface->rss = true;
	port_conf->rx_adv_conf.rss_conf.rss_hf = 0;
	if (ipv4_if_configured(iface)) {
		port_conf->rx_adv_conf.rss_conf.rss_hf |=
			GATEKEEPER_IPV4_RSS_HF;
	}
	if (ipv6_if_configured(iface)) {
		port_conf->rx_adv_conf.rss_conf.rss_hf |=
			GATEKEEPER_IPV6_RSS_HF;
	}

	/*
	 * Set up device MTU.
	 *
	 * If greater than the traditional MTU, then add the
	 * jumbo frame RX offload flag. All ports must support
	 * this offload in this case.
	 *
	 * If greater than the size of the mbufs, then add the
	 * multi-segment buffer flag. This is optional and
	 * if any ports don't support it, it will be removed.
	 */
	port_conf->rxmode.max_rx_pkt_len = iface->mtu;
	if (iface->mtu > RTE_ETHER_MTU)
		port_conf->rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	if (iface->mtu > RTE_MBUF_DEFAULT_BUF_SIZE)
		port_conf->txmode.offloads |= DEV_TX_OFFLOAD_MULTI_SEGS;

	/*
	 * Set up checksumming.
	 *
	 * If IPv4 is supported, both Grantor and Gatekeeper
	 * need to support IPv4 checksumming in hardware.
	 *
	 * Grantor uses UDP checksumming if available. Assume
	 * UDP checksumming is supported until shown otherwise.
	 */
	if (ipv4_if_configured(iface))
		port_conf->txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
	if (!config.back_iface_enabled &&
			(iface->ipv4_hw_udp_cksum || iface->ipv6_hw_udp_cksum))
		port_conf->txmode.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;

	for (i = 0; i < iface->num_ports; i++) {
		struct rte_eth_dev_info dev_info;
		uint16_t port_id = iface->ports[i];
		int ret;

		rte_eth_dev_info_get(port_id, &dev_info);

		/* Check for RSS capabilities and offloads. */
		ret = check_port_rss(iface, i, &dev_info, port_conf);
		if (ret < 0)
			return ret;

		/* Check for MTU capability and offloads. */
		ret = check_port_mtu(iface, i, &dev_info, port_conf);
		if (ret < 0)
			return ret;

		/* Check for checksum capability and offloads. */
		ret = check_port_cksum(iface, i, &dev_info, port_conf);
		if (ret < 0)
			return ret;
	}

	if (iface->rss) {
		port_conf->rxmode.mq_mode = ETH_MQ_RX_RSS;
		port_conf->rx_adv_conf.rss_conf.rss_key = default_rss_key;
		port_conf->rx_adv_conf.rss_conf.rss_key_len =
			GATEKEEPER_RSS_KEY_LEN;
	} else {
		/* Configured hash functions are not supported. */
		G_LOG(WARNING, "net: the %s interface does not have RSS capabilities; the GK or GT block will receive all packets and send them to the other blocks as needed. Gatekeeper or Grantor should only be run with one lcore dedicated to GK or GT in this mode; restart with only one GK or GT lcore if necessary\n",
			iface->name);
		iface->num_rx_queues = 1;
	}

	return 0;
}

int
gatekeeper_setup_rss(uint16_t port_id, uint16_t *queues, uint16_t num_queues)
{
	int ret = 0;
	uint32_t i;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rss_reta_entry64 reta_conf[GATEKEEPER_RETA_MAX_SIZE];

	/* Get RSS redirection table (RETA) information. */
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
	if (dev_info.reta_size == 0) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (invalid RETA size = 0)\n",
			port_id);
		ret = -1;
		goto out;
	}

	if (dev_info.reta_size > ETH_RSS_RETA_SIZE_512) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (invalid RETA size = %u)\n",
			port_id, dev_info.reta_size);
		ret = -1;
		goto out;
	}

	/* Setup RSS RETA contents. */
	memset(reta_conf, 0, sizeof(reta_conf));

	for (i = 0; i < dev_info.reta_size; i++) {
		uint32_t idx = i / RTE_RETA_GROUP_SIZE;
		uint32_t shift = i % RTE_RETA_GROUP_SIZE;
		uint32_t queue_idx = i % num_queues; 

		/* Select all fields to set. */
		reta_conf[idx].mask = ~0LL;
		reta_conf[idx].reta[shift] = (uint16_t)queues[queue_idx];
	}

	/* RETA update. */
	ret = rte_eth_dev_rss_reta_update(port_id, reta_conf,
		dev_info.reta_size);
	if (ret == -ENOTSUP) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu hardware doesn't support\n",
			port_id);
		ret = -1;
		goto out;
	} else if (ret == -EINVAL) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (RETA update with bad redirection table parameter)\n",
			port_id);
		ret = -1;
		goto out;
	}

	/* RETA query. */
	ret = rte_eth_dev_rss_reta_query(port_id, reta_conf,
		dev_info.reta_size);
	if (ret == -ENOTSUP) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu hardware doesn't support\n",
			port_id);
		ret = -1;
	} else if (ret == -EINVAL) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (RETA query with bad redirection table parameter)\n",
			port_id);
		ret = -1;
	}

out:
	return ret;
}

int
gatekeeper_get_rss_config(uint16_t port_id,
	struct gatekeeper_rss_config *rss_conf)
{
	int ret = 0;
	uint16_t i;
	struct rte_eth_dev_info dev_info;

	/* Get RSS redirection table (RETA) information. */
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
	rss_conf->reta_size = dev_info.reta_size;
	if (rss_conf->reta_size == 0 ||
			rss_conf->reta_size > ETH_RSS_RETA_SIZE_512) {
		G_LOG(ERR,
			"net: failed to setup RSS at port %hhu (invalid RETA size = %hu)\n",
			port_id, rss_conf->reta_size);
		ret = -1;
		goto out;
	}

	for (i = 0; i < dev_info.reta_size; i++) {
		uint32_t idx = i / RTE_RETA_GROUP_SIZE;
		/* Select all fields to query. */
		rss_conf->reta_conf[idx].mask = ~0LL;
	}

	/* RETA query. */
	ret = rte_eth_dev_rss_reta_query(port_id,
		rss_conf->reta_conf, rss_conf->reta_size);
	if (ret == -ENOTSUP) {
		G_LOG(ERR,
			"net: ailed to query RSS configuration at port %hhu hardware doesn't support\n",
			port_id);
		ret = -1;
	} else if (ret == -EINVAL) {
		G_LOG(ERR,
			"net: failed to query RSS configuration at port %hhu (RETA query with bad redirection table parameter)\n",
			port_id);
		ret = -1;
	}

out:
	return ret;
}

int
gatekeeper_setup_user(struct net_config *net_conf, const char *user)
{
	struct passwd *pw;

	if (user == NULL) {
		net_conf->pw_uid = 0;
		net_conf->pw_gid = 0;
		return 0;
	}

	if ((pw = getpwnam(user)) == NULL) {
		G_LOG(ERR, "%s: failed to call getpwnam() for user %s - %s\n",
			__func__, user, strerror(errno));
		return -1;
	}

	net_conf->pw_uid = pw->pw_uid;
	net_conf->pw_gid = pw->pw_gid;
	return 0;
}

/*
 * @port_idx represents index of port in iface->ports when it is >= 0.
 * When it is -1, @port_id is a bonded port and has no entry in iface->ports.
 */
static int
init_port(struct gatekeeper_if *iface, uint16_t port_id, int port_idx,
	const struct rte_eth_conf *port_conf)
{
	int ret = rte_eth_dev_configure(port_id, iface->num_rx_queues,
		iface->num_tx_queues, port_conf);
	if (ret < 0) {
		G_LOG(ERR, "net: failed to configure port %hu (%s) on the %s interface (err=%d)\n",
			port_id,
			port_idx >= 0 ? iface->pci_addrs[port_idx] : "bonded",
			iface->name, ret);
		return ret;
	}
	return 0;
}

static int
init_iface(struct gatekeeper_if *iface)
{
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_NONE,
		},
		/* Other offloads configured below. */
	};
	int ret;
	uint8_t i;
	uint8_t num_succ_ports;

	iface->alive = true;

	/* Initialize all potential queues on this interface. */
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		iface->rx_queues[i] = GATEKEEPER_QUEUE_UNALLOCATED;
		iface->tx_queues[i] = GATEKEEPER_QUEUE_UNALLOCATED;
	}
	rte_atomic16_set(&iface->rx_queue_id, -1);
	rte_atomic16_set(&iface->tx_queue_id, -1);

	iface->ports = rte_calloc("ports", iface->num_ports,
		sizeof(*iface->ports), 0);
	if (iface->ports == NULL) {
		G_LOG(ERR, "net: %s: out of memory for %s ports\n",
			__func__, iface->name);
		destroy_iface(iface, IFACE_DESTROY_LUA);
		return -1;
	}

	/* Initialize all ports on this interface. */
	for (i = 0; i < iface->num_ports; i++) {
		ret = rte_eth_dev_get_port_by_name(iface->pci_addrs[i],
			&iface->ports[i]);
		if (ret < 0) {
			G_LOG(ERR,
				"net: failed to map PCI %s to a port on the %s interface (err=%d)\n",
				iface->pci_addrs[i], iface->name, ret);
			goto free_ports;
		}
	}

	/* Make sure the ports support hardware offloads. */
	ret = check_port_offloads(iface, &port_conf);
	if (ret < 0) {
		G_LOG(ERR,
			"net: %s interface doesn't support a critical hardware capability\n",
			iface->name);
		goto free_ports;
	}

	num_succ_ports = 0;
	for (i = 0; i < iface->num_ports; i++) {
		ret = init_port(iface, iface->ports[i], i, &port_conf);
		if (ret < 0)
			goto close_partial;
		num_succ_ports++;
	}

	/* Initialize bonded port, if needed. */
	if (!iface_bonded(iface))
		iface->id = iface->ports[0];
	else {
		uint8_t num_slaves_added;
		char dev_name[64];
		ret = snprintf(dev_name, sizeof(dev_name), "net_bonding%s",
			iface->name);
		RTE_VERIFY(ret > 0 && ret < (int)sizeof(dev_name));
		ret = rte_eth_bond_create(dev_name, iface->bonding_mode, 0);
		if (ret < 0) {
			G_LOG(ERR,
				"net: failed to create bonded port on the %s interface (err=%d)\n",
				iface->name, ret);
			goto close_partial;
		}

		iface->id = (uint8_t)ret;

		/*
		 * Bonded port inherits RSS and offload settings
		 * from the slave ports added to it.
		 */
		num_slaves_added = 0;
		for (i = 0; i < iface->num_ports; i++) {
			ret = rte_eth_bond_slave_add(iface->id,
				iface->ports[i]);
			if (ret < 0) {
				G_LOG(ERR, "net: failed to add slave port %hhu to bonded port %hhu (err=%d)\n",
					iface->ports[i], iface->id, ret);
				rm_slave_ports(iface, num_slaves_added);
				goto close_ports;
			}
			num_slaves_added++;
		}

		ret = init_port(iface, iface->id, -1, &port_conf);
		if (ret < 0)
			goto close_ports;
	}

	return 0;

close_ports:
	destroy_iface(iface, IFACE_DESTROY_PORTS);
	return ret;
close_partial:
	close_iface_ports(iface, num_succ_ports);
free_ports:
	rte_free(iface->ports);
	iface->ports = NULL;
	destroy_iface(iface, IFACE_DESTROY_LUA);
	return ret;
}

static int
start_port(uint8_t port_id, uint8_t *pnum_succ_ports,
	unsigned int num_attempts_link_get)
{
	struct rte_eth_link link;
	uint8_t attempts = 0;

	/* Start device. */
	int ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		G_LOG(ERR, "net: failed to start port %hhu (err=%d)\n",
			port_id, ret);
		return ret;
	}
	if (pnum_succ_ports != NULL)
		(*pnum_succ_ports)++;

	/*
	 * The following code ensures that the device is ready for
	 * full speed RX/TX.
	 *
	 * When the initialization is done without this,
	 * the initial packet transmission may be blocked.
	 *
	 * Optionally, we can wait for the link to come up before
	 * continuing. This is useful for bonded ports where the
	 * slaves must be activated after starting the bonded
	 * device in order for the link to come up. The slaves
	 * are activated on a timer, so this can take some time.
	 */
	do {
		rte_eth_link_get(port_id, &link);

		/* Link is up. */
		if (link.link_status)
			break;

		G_LOG(ERR, "net: querying port %hhu, and link is down\n",
			port_id);

		if (attempts > num_attempts_link_get) {
			G_LOG(ERR, "net: giving up on port %hhu\n", port_id);
			ret = -1;
			return ret;
		}

		attempts++;
		sleep(1);
	} while (true);

	return 0;
}

static inline void
gen_ipv6_link_local(struct gatekeeper_if *iface)
{
	/* Link-local IPv6 calculation according to RFC 4291. */
	struct in6_addr *addr = &iface->ll_ip6_addr;
	uint64_t *pmask = (uint64_t *)iface->ll_ip6_mask.s6_addr;

	addr->s6_addr[0] = 0xFE;
	addr->s6_addr[1] = 0x80;
	memset(addr->s6_addr + 2, 0, 6);

	rte_memcpy(addr->s6_addr + 8, iface->eth_addr.addr_bytes, 3);
	addr->s6_addr[11] = 0xFF;
	addr->s6_addr[12] = 0xFE;
	rte_memcpy(addr->s6_addr + 13, iface->eth_addr.addr_bytes + 3, 3);

	addr->s6_addr[8] ^= 2;

	pmask[0] = ~0ULL;
	pmask[1] = 0ULL;
}

static void
setup_ipv6_addrs(struct gatekeeper_if *iface)
{
	/*
	 * Generate and assign IPv6 solicited-node multicast
	 * address for our global address.
	 */
	uint8_t ip6_mc_addr[16] = IPV6_SN_MC_ADDR(iface->ip6_addr.s6_addr);
	struct rte_ether_addr eth_mc_addr = {
		.addr_bytes = {
			           0x33,            0x33,
			ip6_mc_addr[12], ip6_mc_addr[13],
			ip6_mc_addr[14], ip6_mc_addr[15],
		},
	};
	rte_memcpy(iface->ip6_mc_addr.s6_addr, ip6_mc_addr,
		sizeof(iface->ip6_mc_addr.s6_addr));
	rte_ether_addr_copy(&eth_mc_addr, &iface->eth_mc_addr);

	/*
	 * Generate a link-local address, and then use it to
	 * generate a solicited-node multicast address for
	 * that link-local address.
	 */
	gen_ipv6_link_local(iface);
	{
		uint8_t ll_ip6_mc_addr[16] =
			IPV6_SN_MC_ADDR(iface->ll_ip6_addr.s6_addr);
		struct rte_ether_addr ll_eth_mc_addr = {
			.addr_bytes = {
				              0x33,               0x33,
				ll_ip6_mc_addr[12], ll_ip6_mc_addr[13],
				ll_ip6_mc_addr[14], ll_ip6_mc_addr[15],
			},
		};
		struct rte_ether_addr mc_addrs[2] =
			{ eth_mc_addr, ll_eth_mc_addr };
		rte_memcpy(iface->ll_ip6_mc_addr.s6_addr, ll_ip6_mc_addr,
			sizeof(iface->ll_ip6_mc_addr.s6_addr));
		rte_ether_addr_copy(&ll_eth_mc_addr, &iface->ll_eth_mc_addr);

		/* Add to list of accepted MAC addresses. */
		rte_eth_dev_set_mc_addr_list(iface->id, mc_addrs, 2);
	}
}

static int
check_port_rss_key_update(struct gatekeeper_if *iface, uint16_t port_id)
{
	uint8_t rss_hash_key[GATEKEEPER_RSS_KEY_LEN];
	struct rte_eth_rss_conf rss_conf = {
		.rss_key = rss_hash_key,
		.rss_key_len = GATEKEEPER_RSS_KEY_LEN,
	};
	int ret;

	if (!iface->rss)
		return 0;

	ret = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	switch (ret) {
	case 0:
		break;
	case -ENODEV:
		G_LOG(WARNING,
			"net: failed to get RSS hash configuration at port %d on the %s interface - port identifier is invalid\n",
			port_id, iface->name);
		return ret;
	case -EIO:
		G_LOG(WARNING,
			"net: failed to get RSS hash configuration at port %d on the %s interface - device is removed\n",
			port_id, iface->name);
		return ret;
	case -ENOTSUP:
		G_LOG(WARNING,
			"net: failed to get RSS hash configuration at port %d on the %s interface - hardware doesn't support\n",
			port_id, iface->name);
		return ret;
	default:
		G_LOG(WARNING,
			"net: failed to get RSS hash configuration at port %d on the %s interface - ret = %d\n",
			port_id, iface->name, ret);
		return ret;
	}

	if ((rss_conf.rss_key_len !=
			sizeof(default_rss_key) ||
			memcmp(rss_conf.rss_key,
				default_rss_key,
				rss_conf.rss_key_len) != 0)) {
		G_LOG(WARNING,
			"net: the RSS hash configuration obtained at port %d on the %s interface doesn't match the expected RSS configuration\n",
			port_id, iface->name);
		return -EINVAL;
	}

	return 0;
}

static int
start_iface(struct gatekeeper_if *iface, unsigned int num_attempts_link_get)
{
	int ret;
	uint8_t i;
	uint8_t num_succ_ports;

	/*
	 * The MTU of the device should be changed while the device
	 * is down. Otherwise, drivers for some NICs and in some cases
	 * (when multiple ports are bonded) fail to set the MTU.
	 */
	ret = rte_eth_dev_set_mtu(iface->id, iface->mtu);
	if (ret < 0) {
		G_LOG(ERR,
			"net: cannot set the MTU on the %s iface (error %d)\n",
			iface->name, -ret);
		goto destroy_init;
	}

	num_succ_ports = 0;
	for (i = 0; i < iface->num_ports; i++) {
		ret = start_port(iface->ports[i],
			&num_succ_ports, num_attempts_link_get);
		if (ret < 0)
			goto stop_partial;

		/*
		 * If we try to update/get the RSS hash configuration before
		 * the start of the NICs, no meaningful operations will be
		 * done even the return values indicate no errors.
		 *
		 * After checking the source code of DPDK library,
		 * it turns out that RSS is disabled in the MRQC register
		 * before we start the NICs.
		 *
		 * Only after the NICs start, we can check whether the RSS hash
		 * is configured correctly or not.
		 */
		if (check_port_rss_key_update(iface, iface->ports[i])) {
			G_LOG(ERR,
				"net: port %hu (%s) on the %s interface does get the RSS hash key updated correctly\n",
				iface->ports[i], iface->pci_addrs[i],
				iface->name);
			ret = -1;
			goto stop_partial;
		}
	}

	/* Bonding port(s). */
	if (iface_bonded(iface)) {
		ret = start_port(iface->id, NULL, num_attempts_link_get);
		if (ret < 0)
			goto stop_partial;
	}

	iface->hw_filter_eth = true;
	iface->hw_filter_ntuple = true;
	for (i = 0; i < iface->num_ports; i++) {
		if (iface->hw_filter_eth &&
				(rte_eth_dev_filter_supported(iface->ports[i],
					RTE_ETH_FILTER_ETHERTYPE) != 0))
			iface->hw_filter_eth = false;

		if (iface->hw_filter_ntuple &&
				(rte_eth_dev_filter_supported(iface->ports[i],
					RTE_ETH_FILTER_NTUPLE) != 0))
			iface->hw_filter_ntuple = false;
	}

	G_LOG(NOTICE,
		"net: EtherType filters %s supported on the %s iface\n",
		iface->hw_filter_eth ? "are" : "are NOT", iface->name);
	G_LOG(NOTICE,
		"net: ntuple filters %s supported on the %s iface\n",
		iface->hw_filter_ntuple ? "are" : "are NOT", iface->name);

	if (ipv4_acl_enabled(iface)) {
		ret = init_ipv4_acls(iface);
		if (ret < 0)
			goto stop_partial;
	}

	rte_eth_macaddr_get(iface->id, &iface->eth_addr);
	if (ipv6_acl_enabled(iface)) {
		ret = init_ipv6_acls(iface);
		if (ret < 0)
			goto ipv4_acls;
		setup_ipv6_addrs(iface);
	}

	return 0;

ipv4_acls:
	if (ipv4_acl_enabled(iface))
		destroy_acls(&iface->ipv4_acls);
stop_partial:
	stop_iface_ports(iface, num_succ_ports);
destroy_init:
	destroy_iface(iface, IFACE_DESTROY_INIT);
	return ret;
}

unsigned int
calculate_mempool_config_para(const char *block_name,
	struct net_config *net_conf, unsigned int total_pkt_burst)
{
	unsigned int num_mbuf;

	/*
	 * The total number of receive descriptors to
	 * allocate per lcore for the receive ring over all interfaces.
	 */
	uint16_t total_rx_desc = net_conf->front.num_rx_desc +
		(net_conf->back_iface_enabled ? net_conf->back.num_rx_desc : 0);

	/*
	 * The total number of transmit descriptors to
	 * allocate per lcore for the transmit ring over all interfaces.
	 */
	uint16_t total_tx_desc = net_conf->front.num_tx_desc +
		(net_conf->back_iface_enabled ? net_conf->back.num_tx_desc : 0);

	/*
	 * The number of elements in the mbuf pool.
	 *
	 * Need to provision enough memory for the worst case.
	 * It's the number of RX descriptors, the number of TX descriptors,
	 * and the number of packet burst buffers.
	 */
	uint32_t max_num_pkt = total_rx_desc + total_tx_desc + total_pkt_burst;

	/*
	 * The optimum size (in terms of memory usage) for a mempool is when
	 * it is a power of two minus one.
	 */
	num_mbuf = rte_align32pow2(max_num_pkt) - 1;

	G_LOG(NOTICE, "%s: %s: total_pkt_burst = %hu packets, total_rx_desc = %hu descriptors, total_tx_desc = %hu descriptors, max_num_pkt = %u packets, num_mbuf = %u packets.\n",
		block_name, __func__, total_pkt_burst, total_rx_desc,
		total_tx_desc, max_num_pkt, num_mbuf);

	return num_mbuf;
}

struct rte_mempool *
create_pktmbuf_pool(const char *block_name, unsigned int lcore,
	unsigned int num_mbuf)
{
	struct rte_mempool *mp;
	char pool_name[64];
	int ret = snprintf(pool_name, sizeof(pool_name), "pktmbuf_pool_%s_%u",
		block_name, lcore);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(pool_name));
	mp = rte_pktmbuf_pool_create_by_ops(pool_name, num_mbuf, 0,
		sizeof(struct list_head), RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_lcore_to_socket_id(lcore), "ring_mp_sc");
	if (mp == NULL) {
		G_LOG(ERR,
			"net: failed to allocate mbuf for block %s at lcore %u\n",
			block_name, lcore);

		if (rte_errno == E_RTE_NO_CONFIG) G_LOG(ERR, "function could not get pointer to rte_config structure\n");
		else if (rte_errno == E_RTE_SECONDARY) G_LOG(ERR, "function was called from a secondary process instance\n");
		else if (rte_errno == EINVAL) G_LOG(ERR, "cache size provided is too large\n");
		else if (rte_errno == ENOSPC) G_LOG(ERR, "the maximum number of memzones has already been allocated\n");
		else if (rte_errno == EEXIST) G_LOG(ERR, "a memzone with the same name already exists\n");
		else if (rte_errno == ENOMEM) G_LOG(ERR, "no appropriate memory area found in which to create memzone\n");
		else G_LOG(ERR, "unknown error creating mbuf pool\n");

		return NULL;
	}

	return mp;
}

static int
init_iface_stage1(void *arg)
{
	struct gatekeeper_if *iface = arg;
	return init_iface(iface);
}

static int
start_network_stage2(void *arg)
{
	struct net_config *net = arg;
	int ret;

	ret = start_iface(&net->front, net->num_attempts_link_get);
	if (ret < 0)
		goto fail;

	if (net->back_iface_enabled) {
		ret = start_iface(&net->back, net->num_attempts_link_get);
		if (ret < 0)
			goto destroy_front;
	}

	return 0;

destroy_front:
	destroy_iface(&net->front, IFACE_DESTROY_ALL);
fail:
	G_LOG(ERR, "net: failed to start Gatekeeper network\n");
	return ret;
}

static int
drop_privileges(void)
{
	int ret;
	char user[128];

	ret = getlogin_r(user, sizeof(user));
	if (ret != 0) {
		G_LOG(ERR, "%s: failed to get the current logged in user - %s\n",
			__func__, strerror(errno));
		return ret;
	}

	ret = initgroups(user, config.pw_gid);
	if (ret != 0) {
		G_LOG(ERR, "%s: failed to call initgrous(%s, %u) - %s\n",
			__func__, user, config.pw_gid, strerror(errno));
		return ret;
	}

	/* Drop privileges. */
	if (setgid(config.pw_gid) != 0 || setuid(config.pw_uid) != 0) {
		G_LOG(ERR, "%s: failed to drop privileges for user with user id %u and group id %u: %s\n",
			__func__, config.pw_uid,
			config.pw_gid, strerror(errno));
		return -1;
	}

	return (seteuid(0) == -1 && setegid(0) == -1) ? 0 : -1;
}

int
finalize_stage2(void *arg)
{
	int ret;

	if (ipv4_acl_enabled(&config.front)) {
		ret = build_ipv4_acls(&config.front);
		if (ret < 0)
			return ret;
	}
	if (ipv4_acl_enabled(&config.back)) {
		ret = build_ipv4_acls(&config.back);
		if (ret < 0)
			return ret;
	}
	if (ipv6_acl_enabled(&config.front)) {
		ret = build_ipv6_acls(&config.front);
		if (ret < 0)
			return ret;
	}
	if (ipv6_acl_enabled(&config.back)) {
		ret = build_ipv6_acls(&config.back);
		if (ret < 0)
			return ret;
	}
	if (config.pw_uid != 0) {
		int log_fd = (intptr_t)arg;
		ret = fchown(log_fd, config.pw_uid, config.pw_gid);
		if (ret != 0) {
			G_LOG(ERR, "Failed to change the owner of the file (with descriptor %d) to user with uid %u and gid %u - %s\n",
				log_fd, config.pw_uid,
				config.pw_gid, strerror(errno));
			return ret;
		}
		return drop_privileges();
	}
	return 0;
}

/* Initialize the network. */
int
gatekeeper_init_network(struct net_config *net_conf)
{
	int num_ports;
	int ret = -1;

	if (net_conf == NULL)
		return -1;

	net_conf->log_type = gatekeeper_logtype;

	ret = rte_log_set_level(net_conf->log_type, net_conf->log_level);
	if (ret < 0)
		return -1;

	if (net_conf->back_iface_enabled) {
		if (ipv4_if_configured(&net_conf->front) !=
				ipv4_if_configured(&net_conf->back)) {
			G_LOG(ERR, "net: front and back interfaces must either both support IPv4 or neither support IPv4\n");
			return -1;
		}
		if (ipv6_if_configured(&net_conf->front) !=
				ipv6_if_configured(&net_conf->back)) {
			G_LOG(ERR, "net: front and back interfaces must either both support IPv6 or neither support IPv6\n");
			return -1;
		}
	}

	net_conf->numa_nodes = find_num_numa_nodes();
	net_conf->numa_used = rte_calloc("numas", net_conf->numa_nodes,
		sizeof(*net_conf->numa_used), 0);
	if (net_conf->numa_used == NULL) {
		G_LOG(ERR, "net: %s: out of memory for NUMA used array\n",
			__func__);
		return -1;
	}

	if (randomize_rss_key(net_conf->guarantee_random_entropy) < 0) {
		G_LOG(ERR, "net: failed to initialize RSS key.\n");
		ret = -1;
		goto numa;
	}

	RTE_BUILD_BUG_ON(sizeof(default_rss_key) % 4 != 0);

	/* Convert RSS key. */
	rte_convert_rss_key((uint32_t *)default_rss_key,
		(uint32_t *)rss_key_be, sizeof(default_rss_key));

	/* Check port limits. */
	num_ports = net_conf->front.num_ports +
		(net_conf->back_iface_enabled ? net_conf->back.num_ports : 0);
	if (num_ports > rte_eth_dev_count_avail()) {
		G_LOG(ERR, "net: there are only %i network ports available to DPDK/Gatekeeper, but configuration is using %i ports\n",
			rte_eth_dev_count_avail(), num_ports);
		ret = -1;
		goto numa;
	}
	net_conf->front.total_pkt_burst = 0;
	net_conf->back.total_pkt_burst = 0;

	/* Initialize interfaces. */

	ret = launch_at_stage1(init_iface_stage1, &net_conf->front);
	if (ret < 0)
		goto numa;

	ret = launch_at_stage2(start_network_stage2, net_conf);
	if (ret < 0)
		goto destroy_front;

	if (net_conf->back_iface_enabled) {
		ret = launch_at_stage1(init_iface_stage1, &net_conf->back);
		if (ret < 0)
			goto do_not_start_net;
	}

	goto out;

do_not_start_net:
	pop_n_at_stage2(1);
destroy_front:
	pop_n_at_stage1(1);
numa:
	rte_free(net_conf->numa_used);
	net_conf->numa_used = NULL;
out:
	return ret;
}

void
gatekeeper_free_network(void)
{
	if (config.back_iface_enabled)
		destroy_iface(&config.back, IFACE_DESTROY_ALL);
	destroy_iface(&config.front, IFACE_DESTROY_ALL);
	rte_free(config.numa_used);
	config.numa_used = NULL;
}

int
net_launch_at_stage1(struct net_config *net,
	int front_rx_queues, int front_tx_queues,
	int back_rx_queues, int back_tx_queues,
	lcore_function_t *f, void *arg)
{
	int ret = launch_at_stage1(f, arg);

	if (ret < 0)
		return ret;

	RTE_VERIFY(front_rx_queues >= 0);
	RTE_VERIFY(front_tx_queues >= 0);
	net->front.num_rx_queues += front_rx_queues;
	net->front.num_tx_queues += front_tx_queues;

	if (net->back_iface_enabled) {
		RTE_VERIFY(back_rx_queues >= 0);
		RTE_VERIFY(back_tx_queues >= 0);
		net->back.num_rx_queues += back_rx_queues;
		net->back.num_tx_queues += back_tx_queues;
	}

	return 0;
}

bool
ipv4_configured(struct net_config *net_conf)
{
	if (net_conf->back_iface_enabled) {
		return ipv4_if_configured(&net_conf->front) &&
			ipv4_if_configured(&net_conf->back);
	}
	return ipv4_if_configured(&net_conf->front);
}

bool
ipv6_configured(struct net_config *net_conf)
{
	if (net_conf->back_iface_enabled) {
		return ipv6_if_configured(&net_conf->front) &&
			ipv6_if_configured(&net_conf->back);
	}
	return ipv6_if_configured(&net_conf->front);
}

void
send_pkts(uint8_t port, uint16_t tx_queue,
	uint16_t num_pkts, struct rte_mbuf **bufs)
{
	uint16_t i, num_tx_succ;

	if (num_pkts == 0)
		return;

	/* Send burst of TX packets, to second port of pair. */
	num_tx_succ = rte_eth_tx_burst(port, tx_queue, bufs, num_pkts);

	/* XXX #71 Do something better here! For now, free any unsent packets. */
	if (unlikely(num_tx_succ < num_pkts)) {
		for (i = num_tx_succ; i < num_pkts; i++)
			drop_packet(bufs[i]);
	}
}
