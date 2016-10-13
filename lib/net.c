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

#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_eth_bond.h>
#include <rte_malloc.h>

#include "gatekeeper_net.h"
#include "gatekeeper_config.h"

static struct net_config config;

/* TODO Implement the configuration for Flow Director, RSS, and Filters. */
static struct rte_eth_conf gatekeeper_port_conf = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
};

static uint32_t
find_num_numa_nodes(void)
{
	int i;
	uint32_t nb_numa_nodes = 0;
	int nb_lcores = rte_lcore_count();

	for (i = 0; i < nb_lcores; i++) {
		uint32_t socket_id = rte_lcore_to_socket_id(i);
		if (nb_numa_nodes <= socket_id)
			nb_numa_nodes = socket_id + 1;
	}
	
	return nb_numa_nodes;
}

int
lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs)
{
	uint8_t i, j;

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

	return 0;

name:
	rte_free(iface->name);
	iface->name = NULL;
	return -1;
}

static void
free_pci_addrs(struct gatekeeper_if *iface)
{
	uint8_t i;
	for (i = 0; i < iface->num_ports; i++)
		rte_free(iface->pci_addrs[i]);
	rte_free(iface->pci_addrs);
	iface->pci_addrs = NULL;
}

void
lua_free_iface(struct gatekeeper_if *iface)
{
	free_pci_addrs(iface);
	rte_free(iface->name);
	iface->name = NULL;
}

static void
close_iface_id(struct gatekeeper_if *iface, uint8_t nb_slave_ports)
{
	uint8_t i;

	/* If there's only one port, there's no bonded port. */
	if (iface->num_ports == 1)
		return;

	for (i = 0; i < nb_slave_ports; i++)
		rte_eth_bond_slave_remove(iface->id, iface->ports[i]);

	rte_eth_bond_free(iface->name);
}

static void
close_iface_ports(struct gatekeeper_if *iface, uint8_t nb_ports)
{
	uint8_t i;
	for (i = 0; i < nb_ports; i++) {
		rte_eth_dev_stop(iface->ports[i]);
		rte_eth_dev_close(iface->ports[i]);
	}
}

static void
close_iface(struct gatekeeper_if *iface)
{
	close_iface_id(iface, iface->num_ports);
	close_iface_ports(iface, iface->num_ports);
	rte_free(iface->ports);
	iface->ports = NULL;
	free_pci_addrs(iface);
	rte_free(iface->name);
	iface->name = NULL;
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
	return &net_conf->back;
}

static int
init_port(struct net_config *net_conf, uint8_t port_id, uint8_t *num_succ_ports)
{
	unsigned int lcore;
	struct rte_eth_link link;
	int ret = rte_eth_dev_configure(port_id,
		net_conf->num_rx_queues, net_conf->num_tx_queues,
		&gatekeeper_port_conf);
	if (ret < 0) {
		RTE_LOG(ERR, PORT,
			"Failed to configure port %hhu (err=%d)!\n",
			port_id, ret);
		return ret;
	}

	/*
	 * TODO This initialization assumes that every block wants
	 * to use the same queue identifier for both RX and TX on
	 * both interfaces. This is not the case, and should be
	 * changed in future patches.
	 */
	RTE_LCORE_FOREACH_SLAVE(lcore) {
		unsigned int numa_node = rte_lcore_to_socket_id(lcore);
		struct rte_mempool *mp = net_conf->
			gatekeeper_pktmbuf_pool[numa_node];
		uint16_t queue = (uint16_t)(lcore - 1);

		if (queue < net_conf->num_rx_queues) {
			ret = rte_eth_rx_queue_setup(port_id, queue,
				GATEKEEPER_NUM_RX_DESC,
				numa_node, NULL, mp);
			if (ret < 0) {
				RTE_LOG(ERR, PORT, "Failed to configure port %hhu rx_queue %hu (err=%d)!\n",
					port_id, queue, ret);
				return ret;
			}
		}

		if (queue < net_conf->num_tx_queues) {
			ret = rte_eth_tx_queue_setup(port_id, queue,
				GATEKEEPER_NUM_TX_DESC, numa_node, NULL);
			if (ret < 0) {
				RTE_LOG(ERR, PORT, "Failed to configure port %hhu tx_queue %hu (err=%d)!\n",
					port_id, queue, ret);
				return ret;
			}
		}
	}

	/* Start device. */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, PORT, "Failed to start port %hhu (err=%d)!\n",
			port_id, ret);
		return ret;
	}
	if (num_succ_ports != NULL)
		num_succ_ports++;

	/*
	 * The following code ensures that the device is ready for
	 * full speed RX/TX.
	 * When the initialization is done without this,
	 * the initial packet transmission may be blocked.
	 */
	rte_eth_link_get(port_id, &link);
	if (!link.link_status) {
		RTE_LOG(ERR, PORT, "Querying port %hhu, and link is down!\n",
			port_id);
		ret = -1;
		return ret;
	}

	/* TODO Configure the Flow Director and RSS. */

	return 0;
}

static int
init_iface(struct net_config *net_conf, struct gatekeeper_if *iface)
{
	int ret = 0;
	uint8_t i;
	uint8_t num_succ_ports = 0;
	uint8_t num_slaves_added = 0;

	iface->ports = rte_calloc("ports", iface->num_ports,
		sizeof(*iface->ports), 0);
	if (iface->ports == NULL) {
		RTE_LOG(ERR, MALLOC, "%s: Out of memory for %s ports\n",
			__func__, iface->name);
		return -1;
	}

	for (i = 0; i < iface->num_ports; i++) {
		struct rte_pci_addr pci_addr;
		uint8_t port_id;

		int ret = eal_parse_pci_DomBDF(iface->pci_addrs[i], &pci_addr);
		if (ret < 0) {
			RTE_LOG(ERR, PORT,
				"Failed to parse PCI %s (err=%d)!\n",
				iface->pci_addrs[i], ret);
			goto close_ports;
		}

		ret = rte_eth_dev_get_port_by_addr(&pci_addr, &port_id);
		if (ret < 0) {
			RTE_LOG(ERR, PORT,
				"Failed to map PCI %s to a port (err=%d)!\n",
				iface->pci_addrs[i], ret);
			goto close_ports;
		}
		iface->ports[i] = port_id;

		ret = init_port(net_conf, port_id, &num_succ_ports);
		if (ret < 0)
			goto close_ports;
	}

	/* Initialize bonded port, if needed. */
	if (iface->num_ports == 1) {
		iface->id = iface->ports[0];
		return 0;
	}

	/* TODO Also allow LACP to be used. */
	ret = rte_eth_bond_create(iface->name, BONDING_MODE_ROUND_ROBIN, 0);
	if (ret < 0) {
		RTE_LOG(ERR, PORT, "Failed to create bonded port (err=%d)!\n",
			ret);
		goto close_ports;
	}

	iface->id = (uint8_t)ret;

	ret = init_port(net_conf, iface->id, NULL);
	if (ret < 0)
		goto close_id;

	for (i = 0; i < iface->num_ports; i++) {
		ret = rte_eth_bond_slave_add(iface->id, iface->ports[i]);
		if (ret < 0) {
			RTE_LOG(ERR, PORT, "Failed to add slave port %hhu to bonded port %hhu (err=%d)!\n",
				iface->ports[i], iface->id, ret);
			goto close_id;
		}
		num_slaves_added++;
	}

	return 0;

close_id:
	close_iface_id(iface, num_slaves_added);
close_ports:
	close_iface_ports(iface, num_succ_ports);
	rte_free(iface->ports);
	iface->ports = NULL;
	return ret;
}

/* Initialize the network. */
int
gatekeeper_init_network(struct net_config *net_conf)
{
	int i;
	int ret = -1;

	if (!net_conf)
		return -1;

	if (!config.gatekeeper_pktmbuf_pool) {
		config.numa_nodes = find_num_numa_nodes();
		config.gatekeeper_pktmbuf_pool =
			rte_calloc("mbuf_pool", config.numa_nodes,
				sizeof(struct rte_mempool *), 0);
		if (!config.gatekeeper_pktmbuf_pool) {
			RTE_LOG(ERR, MALLOC, "%s: Out of memory\n", __func__);
			return -1;
		}
	}

	RTE_ASSERT(net_conf->num_rx_queues <= GATEKEEPER_MAX_QUEUES);
	RTE_ASSERT(net_conf->num_tx_queues <= GATEKEEPER_MAX_QUEUES);

	/* Initialize pktmbuf on each numa node. */
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
	net_conf->num_ports = rte_eth_dev_count();
	RTE_ASSERT(net_conf->num_ports != 0 &&
		net_conf->num_ports <= GATEKEEPER_MAX_PORTS &&
		net_conf->num_ports ==
			(net_conf->front.num_ports + net_conf->back.num_ports));

	/* Initialize interfaces. */
	ret = init_iface(net_conf, &net_conf->front);
	if (ret < 0)
		goto out;

	ret = init_iface(net_conf, &net_conf->back);
	if (ret < 0)
		goto close_front;

	goto out;

close_front:
	close_iface_id(&net_conf->front, net_conf->front.num_ports);
	close_iface_ports(&net_conf->front, net_conf->front.num_ports);
	rte_free(net_conf->front.ports);
	net_conf->front.ports = NULL;
out:
	return ret;
}

void
gatekeeper_free_network(void)
{
	close_iface(&config.back);
	close_iface(&config.front);
}
