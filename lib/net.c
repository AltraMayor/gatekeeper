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

#include <rte_mbuf.h>
#include <rte_thash.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>
#include <rte_malloc.h>

#include "gatekeeper_main.h"
#include "gatekeeper_net.h"
#include "gatekeeper_config.h"
#include "gatekeeper_launch.h"

/* Number of attempts to wait for a link to come up. */
#define NUM_ATTEMPTS_LINK_GET	(5)

#define GATEKEEPER_PKT_DROP_QUEUE (127)

static struct net_config config;

/*
 * XXX The secret key of the RSS hash must be random
 * in order to avoid hackers to know it.
 */
uint8_t default_rss_key[GATEKEEPER_RSS_KEY_LEN] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

/* To support the optimized implementation of generic RSS hash function. */
uint8_t rss_key_be[RTE_DIM(default_rss_key)];

/* TODO Implement the configuration for Flow Director. */

/*
 * TODO Add support for VLAN tags.
 *
 * Assume for now that hardware support is available for
 * VLAN stripping -- then only this configuration needs
 * to be changed.
 *
 * For VLAN insertion, hardware support can't be
 * assumed, so it must be added in software.
 */
static struct rte_eth_conf gatekeeper_port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},

	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = default_rss_key,
			.rss_key_len = GATEKEEPER_RSS_KEY_LEN,
			.rss_hf = ETH_RSS_IP,
		},
	},
};

/* @ether_type should be in host ordering. */
int
ethertype_filter_add(uint8_t port_id, uint16_t ether_type, uint16_t queue_id)
{
	struct rte_eth_ethertype_filter filter = {
		.ether_type = ether_type,
		.flags = 0,
		.queue = queue_id,
	};

	int ret = rte_eth_dev_filter_supported(port_id,
		RTE_ETH_FILTER_ETHERTYPE);
	if (ret < 0) {
		RTE_LOG(ERR, PORT,
			"EtherType filters are not supported on port %hhu.\n",
			port_id);
		ret = -1;
		goto out;
	}

	ret = rte_eth_dev_filter_ctrl(port_id,
		RTE_ETH_FILTER_ETHERTYPE,
		RTE_ETH_FILTER_ADD,
		&filter);
	if (ret == -ENOTSUP) {
		RTE_LOG(ERR, PORT,
			"Hardware doesn't support adding an EtherType filter for 0x%02hx on port %hhu!\n",
			ether_type, port_id);
		ret = -1;
		goto out;
	} else if (ret == -ENODEV) {
		RTE_LOG(ERR, PORT,
			"Port %hhu is invalid for adding an EtherType filter for 0x%02hx!\n",
			ether_type, port_id);
		ret = -1;
		goto out;
	} else if (ret != 0) {
		RTE_LOG(ERR, PORT,
			"Other errors that depend on the specific operations implementation on port %hhu for adding an EtherType filter for 0x%02hx!\n",
			port_id, ether_type);
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	return ret;
}

/*
 * @dst_ip, @src_port and @dst_port must be in big endian.
 * By specifying the tuple (proto, src_port, dst_port),
 * it can filter both IPv4 and IPv6 addresses.
 */
int
ntuple_filter_add(uint8_t portid, uint32_t dst_ip,
	uint16_t src_port, uint16_t dst_port, uint16_t queue_id)
{
	int ret = 0;
	struct rte_eth_ntuple_filter filter_v4 = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = dst_ip,
		.dst_ip_mask = UINT32_MAX,
		.src_ip = 0,
		.src_ip_mask = 0,
		.dst_port = dst_port,
		.dst_port_mask = UINT16_MAX,
		.src_port = src_port,
		.src_port_mask = UINT16_MAX,
		.proto = IPPROTO_UDP,
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
		.dst_port_mask = UINT16_MAX,
		.src_port = src_port,
		.src_port_mask = UINT16_MAX,
		.proto = IPPROTO_UDP,
		.proto_mask = UINT8_MAX,
		.tcp_flags = 0,
		.priority = 1,
		.queue = queue_id,
	};

	ret = rte_eth_dev_filter_supported(portid, RTE_ETH_FILTER_NTUPLE);
	if (ret < 0) {
		RTE_LOG(ERR, PORT,
			"Ntuple filter is not supported on port %hhu.\n",
			portid);
		ret = -1;
		goto out;
	}

	if (dst_ip != 0) {
		ret = rte_eth_dev_filter_ctrl(portid,
			RTE_ETH_FILTER_NTUPLE,
			RTE_ETH_FILTER_ADD,
			&filter_v4);
		if (ret == -ENOTSUP) {
			RTE_LOG(ERR, PORT,
				"Hardware doesn't support adding an IPv4 ntuple filter on port %hhu!\n",
				portid);
			ret = -1;
			goto out;
		} else if (ret == -ENODEV) {
			RTE_LOG(ERR, PORT,
				"Port %hhu is invalid for adding an IPv4 ntuple filter!\n",
				portid);
			ret = -1;
			goto out;
		} else if (ret != 0) {
			RTE_LOG(ERR, PORT,
				"Other errors that depend on the specific operations implementation on port %hhu for adding an IPv4 ntuple filter!\n",
				portid);
			ret = -1;
			goto out;
		}
	}

	ret = rte_eth_dev_filter_ctrl(portid,
		RTE_ETH_FILTER_NTUPLE,
		RTE_ETH_FILTER_ADD,
		&filter_v6);
	if (ret == -ENOTSUP) {
		RTE_LOG(ERR, PORT,
			"Hardware doesn't support adding an IPv6 ntuple filter on port %hhu!\n",
			portid);
		ret = -1;
		goto out;
	} else if (ret == -ENODEV) {
		RTE_LOG(ERR, PORT,
			"Port %hhu is invalid for adding an IPv6 ntuple filter!\n",
			portid);
		ret = -1;
		goto out;
	} else if (ret != 0) {
		RTE_LOG(ERR, PORT,
			"Other errors that depend on the specific operations implementation on port %hhu for adding an IPv6 ntuple filter!\n",
			portid);
		ret = -1;
		goto out;
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
configure_queue(uint8_t port_id, uint16_t queue_id, enum queue_type ty,
	unsigned int numa_node, struct rte_mempool *mp)
{
	int ret;

	switch (ty) {
	case QUEUE_TYPE_RX:
		ret = rte_eth_rx_queue_setup(port_id, queue_id,
			GATEKEEPER_NUM_RX_DESC, numa_node, NULL, mp);
		if (ret < 0) {
			RTE_LOG(ERR, PORT, "Failed to configure port %hhu rx_queue %hu (err=%d)!\n",
				port_id, queue_id, ret);
			return ret;
		}
		break;
	case QUEUE_TYPE_TX:
		ret = rte_eth_tx_queue_setup(port_id, queue_id,
			GATEKEEPER_NUM_TX_DESC, numa_node, NULL);
		if (ret < 0) {
			RTE_LOG(ERR, PORT, "Failed to configure port %hhu tx_queue %hu (err=%d)!\n",
				port_id, queue_id, ret);
			return ret;
		}
		break;
	default:
		RTE_LOG(ERR, GATEKEEPER,
			"Unsupported queue type (%d) passed to %s!\n",
			ty, __func__);
		return -1;
	}

	return 0;
}

/*
 * Get a queue identifier for a given functional block instance (lcore),
 * using a certain interface for either RX or TX.
 */
int
get_queue_id(struct gatekeeper_if *iface, enum queue_type ty,
	unsigned int lcore)
{
	int16_t *queues;
	int ret;
	uint8_t port;
	unsigned int numa_node;
	struct rte_mempool *mp;
	int16_t new_queue_id;

	RTE_ASSERT(lcore < RTE_MAX_LCORE);
	RTE_ASSERT(ty < QUEUE_TYPE_MAX);

	queues = (ty == QUEUE_TYPE_RX) ? iface->rx_queues : iface->tx_queues;

	if (queues[lcore] != GATEKEEPER_QUEUE_UNALLOCATED)
		goto queue;

	/* Get next queue identifier. */
	new_queue_id = rte_atomic16_add_return(ty == QUEUE_TYPE_RX ?
		&iface->rx_queue_id : &iface->tx_queue_id, 1);
	if (new_queue_id == GATEKEEPER_QUEUE_UNALLOCATED) {
		RTE_LOG(ERR, GATEKEEPER, "net: exhausted all %s queues for the %s interface; this is likely a bug\n",
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
	mp = config.gatekeeper_pktmbuf_pool[numa_node];
	for (port = 0; port < iface->num_ports; port++) {
		ret = configure_queue(iface->ports[port],
			(uint16_t)new_queue_id, ty, numa_node, mp);
		if (ret < 0)
			return ret;
	}

	/* If there's a bonded port, configure it too. */
	if (iface->num_ports > 1) {
		ret = configure_queue(iface->id, (uint16_t)new_queue_id,
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
	switch (cmd) {
	case IFACE_DESTROY_ALL:
		/* Stop interface ports (bonded port is stopped below). */
		stop_iface_ports(iface, iface->num_ports);
		/* FALLTHROUGH */
	case IFACE_DESTROY_INIT:
		/* Remove any slave ports added to a bonded port. */
		if (iface->num_ports > 1)
			rm_slave_ports(iface, iface->num_ports);
		/* FALLTHROUGH */
	case IFACE_DESTROY_PORTS:
		/* Stop and close bonded port, if needed. */
		if (iface->num_ports > 1)
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
		break;
	}
	default:
		RTE_ASSERT(0);
		break;
	}
}

void
lua_free_iface(struct gatekeeper_if *iface)
{
	destroy_iface(iface, IFACE_DESTROY_LUA);
}

static int
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
        	RTE_LOG(ERR, GATEKEEPER,
			"gk: invalid ip address %s; %s\n",
			ip_addr, gai_strerror(ret));
        	return 1;
    	}

    	if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
		RTE_LOG(ERR, GATEKEEPER,
			"gk: %s is an is unknown address format %d\n",
			ip_addr, res->ai_family);

	ret = res->ai_family;
   	freeaddrinfo(res);

	return ret;
}

int
lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs,
	const char **ip_addrs, uint8_t num_ip_addrs)
{
	uint8_t i, j;

	if (num_ip_addrs < 1 || num_ip_addrs > 2) {
		RTE_LOG(ERR, GATEKEEPER,
			"net: an interface has at least 1 IP address, also at most 1 IPv4 and 1 IPv6 address.\n");
		return -1;
	}

	iface->num_ports = num_pci_addrs;

	iface->name = rte_malloc("iface_name", strlen(iface_name) + 1, 0);
	if (iface->name == NULL) {
		RTE_LOG(ERR, MALLOC, "%s: Out of memory for iface name\n",
			__func__);
		return -1;
	}
	strcpy(iface->name, iface_name);

	iface->pci_addrs = rte_calloc("pci_addrs", num_pci_addrs,
		sizeof(*pci_addrs), 0);
	if (iface->pci_addrs == NULL) {
		RTE_LOG(ERR, MALLOC, "%s: Out of memory for PCI array\n",
			__func__);
		goto name;
	}

	for (i = 0; i < num_pci_addrs; i++) {
		iface->pci_addrs[i] = rte_malloc(NULL,
			strlen(pci_addrs[i]) + 1, 0);
		if (iface->pci_addrs[i] == NULL) {
			RTE_LOG(ERR, MALLOC,
				"%s: Out of memory for PCI address %s\n",
				__func__, pci_addrs[i]);
			for (j = 0; j < i; j++)
				rte_free(iface->pci_addrs[j]);
			rte_free(iface->pci_addrs);
			iface->pci_addrs = NULL;
			goto name;
		}
		strcpy(iface->pci_addrs[i], pci_addrs[i]);
	}

	for (i = 0; i < num_ip_addrs; i++) {
		int gk_type = get_ip_type(ip_addrs[i]);
		if (gk_type == AF_INET &&
				inet_pton(AF_INET, ip_addrs[i],
				&iface->ip4_addr) == 1) {
			iface->configured_proto |= GK_CONFIGURED_IPV4;
			continue;
		}
		else if (gk_type == AF_INET6 &&
				inet_pton(AF_INET6, ip_addrs[i],
				&iface->ip6_addr) == 1) {
			iface->configured_proto |= GK_CONFIGURED_IPV6;
			continue;
		}
		else
			goto name;
	}

	return 0;

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

int
gatekeeper_setup_rss(uint8_t portid, uint16_t *queues, uint16_t num_queues)
{
	int ret = 0;
	uint32_t i;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rss_reta_entry64 reta_conf[GATEKEEPER_RETA_MAX_SIZE];

	/* Get RSS redirection table (RETA) information. */
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(portid, &dev_info);
	if (dev_info.reta_size == 0) {
		RTE_LOG(ERR, PORT,
			"Failed to setup RSS at port %hhu (invalid RETA size = 0)!\n",
			portid);
		ret = -1;
		goto out;
	}

	if (dev_info.reta_size > ETH_RSS_RETA_SIZE_512) {
		RTE_LOG(ERR, PORT,
			"Failed to setup RSS at port %hhu (invalid RETA size = %u)!\n",
			portid, dev_info.reta_size);
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
	ret = rte_eth_dev_rss_reta_update(portid, reta_conf,
		dev_info.reta_size);
	if (ret == -ENOTSUP) {
		RTE_LOG(ERR, PORT,
			"Failed to setup RSS at port %hhu hardware doesn't support.",
			portid);
		ret = -1;
		goto out;
	} else if (ret == -EINVAL) {
		RTE_LOG(ERR, PORT,
			"Failed to setup RSS at port %hhu (RETA update with bad redirection table parameter)!\n",
			portid);
		ret = -1;
		goto out;
	}

	/* RETA query. */
	ret = rte_eth_dev_rss_reta_query(portid, reta_conf, dev_info.reta_size);
	if (ret == -ENOTSUP) {
		RTE_LOG(ERR, PORT,
			"Failed to setup RSS at port %hhu hardware doesn't support.",
			portid);
		ret = -1;
	} else if (ret == -EINVAL) {
		RTE_LOG(ERR, PORT,
			"Failed to setup RSS at port %hhu (RETA query with bad redirection table parameter)!\n",
			portid);
		ret = -1;
	}

out:
	return ret;
}

int
gatekeeper_get_rss_config(uint8_t portid,
	struct gatekeeper_rss_config *rss_conf)
{
	int ret = 0;
	uint16_t i;
	struct rte_eth_dev_info dev_info;

	/* Get RSS redirection table (RETA) information. */
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(portid, &dev_info);
	rss_conf->reta_size = dev_info.reta_size;
	if (rss_conf->reta_size == 0 ||
			rss_conf->reta_size > ETH_RSS_RETA_SIZE_512) {
		RTE_LOG(ERR, PORT,
			"Failed to setup RSS at port %hhu (invalid RETA size = %hu)!\n",
			portid, rss_conf->reta_size);
		ret = -1;
		goto out;
	}

	for (i = 0; i < dev_info.reta_size; i++) {
		uint32_t idx = i / RTE_RETA_GROUP_SIZE;
		/* Select all fields to query. */
		rss_conf->reta_conf[idx].mask = ~0LL;
	}

	/* RETA query. */
	ret = rte_eth_dev_rss_reta_query(portid,
		rss_conf->reta_conf, rss_conf->reta_size);
	if (ret == -ENOTSUP) {
		RTE_LOG(ERR, PORT,
			"Failed to query RSS configuration at port %hhu hardware doesn't support!\n",
			portid);
		ret = -1;
	} else if (ret == -EINVAL) {
		RTE_LOG(ERR, PORT,
			"Failed to query RSS configuration at port %hhu (RETA query with bad redirection table parameter)!\n",
			portid);
		ret = -1;
	}

out:
	return ret;
}

static int
init_port(struct gatekeeper_if *iface, uint8_t port_id,
	uint8_t *pnum_succ_ports)
{
	int ret = rte_eth_dev_configure(port_id, iface->num_rx_queues,
		iface->num_tx_queues, &gatekeeper_port_conf);
	if (ret < 0) {
		RTE_LOG(ERR, PORT,
			"Failed to configure port %hhu (err=%d)!\n",
			port_id, ret);
		return ret;
	}
	if (pnum_succ_ports != NULL)
		(*pnum_succ_ports)++;

	return 0;
}

static int
init_iface(struct gatekeeper_if *iface)
{
	int ret;
	uint8_t i;
	uint8_t num_succ_ports = 0;
	uint8_t num_slaves_added = 0;

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
		RTE_LOG(ERR, MALLOC, "%s: Out of memory for %s ports\n",
			__func__, iface->name);
		destroy_iface(iface, IFACE_DESTROY_LUA);
		return -1;
	}

	/* Initialize all ports on this interface. */
	for (i = 0; i < iface->num_ports; i++) {
		struct rte_pci_addr pci_addr;
		uint8_t port_id;

		ret = eal_parse_pci_DomBDF(iface->pci_addrs[i], &pci_addr);
		if (ret < 0) {
			RTE_LOG(ERR, PORT,
				"Failed to parse PCI %s (err=%d)!\n",
				iface->pci_addrs[i], ret);
			goto close_partial;
		}

		ret = rte_eth_dev_get_port_by_addr(&pci_addr, &port_id);
		if (ret < 0) {
			RTE_LOG(ERR, PORT,
				"Failed to map PCI %s to a port (err=%d)!\n",
				iface->pci_addrs[i], ret);
			goto close_partial;
		}
		iface->ports[i] = port_id;

		ret = init_port(iface, port_id, &num_succ_ports);
		if (ret < 0)
			goto close_partial;
	}

	/* Initialize bonded port, if needed. */
	if (iface->num_ports == 1)
		iface->id = iface->ports[0];
	else {
		/* TODO Also allow LACP to be used. */
		ret = rte_eth_bond_create(iface->name,
			BONDING_MODE_ROUND_ROBIN, 0);
		if (ret < 0) {
			RTE_LOG(ERR, PORT,
				"Failed to create bonded port (err=%d)!\n",
				ret);
			goto close_partial;
		}

		iface->id = (uint8_t)ret;

		for (i = 0; i < iface->num_ports; i++) {
			ret = rte_eth_bond_slave_add(iface->id,
				iface->ports[i]);
			if (ret < 0) {
				RTE_LOG(ERR, PORT, "Failed to add slave port %hhu to bonded port %hhu (err=%d)!\n",
					iface->ports[i], iface->id, ret);
				rm_slave_ports(iface, num_slaves_added);
				goto close_ports;
			}
			num_slaves_added++;
		}

		ret = init_port(iface, iface->id, NULL);
		if (ret < 0)
			goto close_ports;
	}

	rte_eth_macaddr_get(iface->id, &iface->eth_addr);
	return 0;

close_ports:
	destroy_iface(iface, IFACE_DESTROY_PORTS);
	return ret;
close_partial:
	close_iface_ports(iface, num_succ_ports);
	rte_free(iface->ports);
	iface->ports = NULL;
	destroy_iface(iface, IFACE_DESTROY_LUA);
	return ret;
}

static int
init_iface_stage1(void *arg)
{
	struct gatekeeper_if *iface = arg;

	/* Make sure the interface has no more queues than permitted. */
	RTE_ASSERT(iface->num_rx_queues <= GATEKEEPER_MAX_QUEUES);
	RTE_ASSERT(iface->num_tx_queues <= GATEKEEPER_MAX_QUEUES);

	return init_iface(iface);
}

/* Initialize the network. */
int
gatekeeper_init_network(struct net_config *net_conf)
{
	int i, num_ports;
	int ret = -1;

	if (net_conf == NULL)
		return -1;

	if (config.gatekeeper_pktmbuf_pool == NULL) {
		config.numa_nodes = find_num_numa_nodes();
		config.gatekeeper_pktmbuf_pool =
			rte_calloc("mbuf_pool", config.numa_nodes,
				sizeof(struct rte_mempool *), 0);
		if (config.gatekeeper_pktmbuf_pool == NULL) {
			RTE_LOG(ERR, MALLOC, "%s: Out of memory\n", __func__);
			return -1;
		}
	}

	/* Convert RSS key. */
	rte_convert_rss_key((uint32_t *)&default_rss_key,
		(uint32_t *)rss_key_be, RTE_DIM(default_rss_key));

	/* Initialize pktmbuf pool on each numa node. */
	for (i = 0; (uint32_t)i < net_conf->numa_nodes; i++) {
		char pool_name[64];

		if (net_conf->gatekeeper_pktmbuf_pool[i] != NULL)
			continue;

		/* XXX For RTE_ASSERT(), default RTE_LOG_LEVEL=7,
		 * so it does nothing.
		 */
		ret = snprintf(pool_name, sizeof(pool_name), "pktmbuf_pool_%u",
			i);
		RTE_ASSERT(ret < sizeof(pool_name));
		net_conf->gatekeeper_pktmbuf_pool[i] =
			rte_pktmbuf_pool_create(pool_name,
                		GATEKEEPER_MBUF_SIZE, GATEKEEPER_CACHE_SIZE, 0,
                		RTE_MBUF_DEFAULT_BUF_SIZE, (unsigned)i);

		/* No cleanup for this step,
		 * since DPDK doesn't offer a way to deallocate pools.
		 */
		if (net_conf->gatekeeper_pktmbuf_pool[i] == NULL) {
			RTE_LOG(ERR, MEMPOOL,
				"Failed to allocate mbuf for numa node %u!\n",
				i);

			if (rte_errno == E_RTE_NO_CONFIG) RTE_LOG(ERR, MEMPOOL, "Function could not get pointer to rte_config structure!\n");
			else if (rte_errno == E_RTE_SECONDARY) RTE_LOG(ERR, MEMPOOL, "Function was called from a secondary process instance!\n");
			else if (rte_errno == EINVAL) RTE_LOG(ERR, MEMPOOL, "Cache size provided is too large!\n");
			else if (rte_errno == ENOSPC) RTE_LOG(ERR, MEMPOOL, "The maximum number of memzones has already been allocated!\n");
			else if (rte_errno == EEXIST) RTE_LOG(ERR, MEMPOOL, "A memzone with the same name already exists!\n");
			else if (rte_errno == ENOMEM) RTE_LOG(ERR, MEMPOOL, "No appropriate memory area found in which to create memzone!\n");
			else RTE_LOG(ERR, MEMPOOL, "Unknown error!\n");

			ret = -1;
			goto out;
		}
	}

	/* Check port limits. */
	num_ports = net_conf->front.num_ports +
		(net_conf->back_iface_enabled ? net_conf->back.num_ports : 0);
	if (num_ports > rte_eth_dev_count()) {
		RTE_LOG(ERR, GATEKEEPER, "There are only %i network ports available to DPDK/Gatekeeper, but configuration is using %i ports\n",
			rte_eth_dev_count(), num_ports);
		ret = -1;
		goto out;
	}
	if (num_ports > GATEKEEPER_MAX_PORTS) {
		RTE_LOG(ERR, GATEKEEPER, "Gatekeeper was compiled to support at most %i network ports, but configuration is using %i ports\n",
			GATEKEEPER_MAX_PORTS, num_ports);
		ret = -1;
		goto out;
	}

	/* Initialize interfaces. */

	ret = launch_at_stage1(net_conf, 0, 0, 0, 0,
		init_iface_stage1, &net_conf->front);
	if (ret < 0)
		goto out;

	if (net_conf->back_iface_enabled) {
		ret = launch_at_stage1(net_conf, 0, 0, 0, 0,
			init_iface_stage1, &net_conf->back);
		if (ret < 0)
			goto destroy_front;
	}

	goto out;

destroy_front:
	pop_n_at_stage1(1);
out:
	return ret;
}

static int
start_port(uint8_t port_id, uint8_t *pnum_succ_ports, int wait_for_link)
{
	struct rte_eth_link link;
	uint8_t attempts = 0;

	/* Start device. */
	int ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, PORT,
			"Failed to start port %hhu (err=%d)!\n",
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

		RTE_LOG(ERR, PORT, "Querying port %hhu, and link is down!\n",
			port_id);

		if (!wait_for_link || attempts > NUM_ATTEMPTS_LINK_GET) {
			RTE_LOG(ERR, PORT, "Giving up on port %hhu\n", port_id);
			ret = -1;
			return ret;
		}

		attempts++;
		sleep(1);
	} while (true);

	return 0;
}

static int
start_iface(struct gatekeeper_if *iface)
{
	int ret;
	uint8_t i;
	uint8_t num_succ_ports = 0;

	for (i = 0; i < iface->num_ports; i++) {
		ret = start_port(iface->ports[i], &num_succ_ports, false);
		if (ret < 0)
			goto stop_partial;
	}

	/* If there's no bonded port, we're done. */
	if (iface->num_ports == 1)
		return 0;

	ret = start_port(iface->id, NULL, true);
	if (ret < 0)
		goto stop_partial;

	return 0;

stop_partial:
	stop_iface_ports(iface, num_succ_ports);
	destroy_iface(iface, IFACE_DESTROY_INIT);
	return ret;
}

int
gatekeeper_start_network(void)
{
	int ret;

	ret = start_iface(&config.front);
	if (ret < 0)
		return ret;

	if (config.back_iface_enabled) {
		ret = start_iface(&config.back);
		if (ret < 0)
			destroy_iface(&config.front, IFACE_DESTROY_ALL);
	}
 
	return ret;
}

void
gatekeeper_free_network(void)
{
	if (config.back_iface_enabled)
		destroy_iface(&config.back, IFACE_DESTROY_ALL);
	destroy_iface(&config.front, IFACE_DESTROY_ALL);
}
