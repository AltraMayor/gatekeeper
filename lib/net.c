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

#include <stdio.h>

#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>

#include "gatekeeper_net.h"
#include "gatekeeper_config.h"

static struct net_config config;

/* TODO Implement the configuration for Flow Director, RSS, and Filters. */
static struct rte_eth_conf gatekeeper_port_conf = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
};

static int
find_num_numa_nodes(void)
{
	int i;
	int nb_numa_nodes = 0;
	int nb_lcores = rte_lcore_count();

	for (i = 0; i < nb_lcores; i++) {
		uint32_t socket_id;
		socket_id = rte_lcore_to_socket_id(i);
		if ((uint32_t)nb_numa_nodes <= socket_id)
			nb_numa_nodes = socket_id + 1;
	}
	
	return nb_numa_nodes;
}

static void
close_num_ports(uint8_t nb_ports)
{
	uint8_t port_id;

	for (port_id = 0; port_id < nb_ports; port_id++) {
		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
	}
}

struct net_config *
get_net_conf(void)
{
	if (!config.gatekeeper_pktmbuf_pool)
		config.gatekeeper_pktmbuf_pool =
			calloc(GATEKEEPER_MAX_NUMA_NODES,
				sizeof(struct rte_mempool *));

	return &config;
}

/* Initialize the network. */
int
gatekeeper_init_network(struct net_config *net_conf)
{
	int i;
	int ret = -1;
	uint8_t port_id;
	int num_numa_nodes = 0;
	uint8_t num_succ_ports = 0;
	uint32_t num_lcores = 0;

	if (!net_conf)
		return -1;

	num_lcores = rte_lcore_count();
	
	RTE_ASSERT(net_conf->num_rx_queues <= GATEKEEPER_MAX_QUEUES);
	RTE_ASSERT(net_conf->num_tx_queues <= GATEKEEPER_MAX_QUEUES);

	num_numa_nodes = find_num_numa_nodes();
	RTE_ASSERT(num_numa_nodes <= GATEKEEPER_MAX_NUMA_NODES);

	/* Initialize pktmbuf on each numa node. */
	for (i = 0; i < num_numa_nodes; i++) {
		char pool_name[64];

		if (net_conf->gatekeeper_pktmbuf_pool[i] != NULL)
			continue;

		/* XXX For RTE_ASSERT(), default RTE_LOG_LEVEL=7, so it does nothing. */
		ret = snprintf(pool_name, sizeof(pool_name), "pktmbuf_pool_%u", i);
		RTE_ASSERT(ret < sizeof(pool_name));
		net_conf->gatekeeper_pktmbuf_pool[i] = rte_pktmbuf_pool_create(pool_name,
                		GATEKEEPER_MBUF_SIZE, GATEKEEPER_CACHE_SIZE, 0,
                		RTE_MBUF_DEFAULT_BUF_SIZE, (unsigned)i);

		/* No cleanup for this step, since DPDK doesn't offer a way to deallocate pools. */
		if (net_conf->gatekeeper_pktmbuf_pool[i] == NULL) {
			RTE_LOG(ERR, MEMPOOL, "Failed to allocate mbuf for numa node %u!\n", i);

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
	RTE_ASSERT(net_conf->num_ports != 0 && net_conf->num_ports <= GATEKEEPER_MAX_PORTS);

	/* Initialize ports. */
	for (port_id = 0; port_id < net_conf->num_ports; port_id++) {
		uint32_t lcore;
		struct rte_eth_link link;
		
		ret = rte_eth_dev_configure(port_id, net_conf->num_rx_queues, net_conf->num_tx_queues, 
				&gatekeeper_port_conf);
		if (ret < 0) {
			RTE_LOG(ERR, PORT, "Failed to configure port %hhu (err=%d)!\n", port_id, ret);
			goto port;
		}

		for (lcore = 0; lcore < num_lcores; lcore++) {
			size_t numa_node;
			
			/* XXX Map queue = lcore, if necessary, change the queues mapping. */
			uint16_t queue = (uint16_t)lcore;

			/* XXX In case the number of lcores is greater than number of queues. */
			if (lcore >= net_conf->num_rx_queues || lcore >= net_conf->num_tx_queues)
				break;

			numa_node = rte_lcore_to_socket_id(lcore);

			ret = rte_eth_rx_queue_setup(port_id, queue, GATEKEEPER_NUM_RX_DESC, 
					(unsigned int)numa_node, NULL, 
					net_conf->gatekeeper_pktmbuf_pool[numa_node]);
			if (ret < 0) {
				RTE_LOG(ERR, PORT, "Failed to configure port %hhu rx_queue %hu (err=%d)!\n",\
					 port_id, queue, ret);
				goto port;
			}

			ret = rte_eth_tx_queue_setup(port_id, queue, GATEKEEPER_NUM_TX_DESC, 
					numa_node, NULL);
			if (ret < 0) {
				RTE_LOG(ERR, PORT, "Failed to configure port %hhu tx_queue %hu (err=%d)!\n",\
					 port_id, queue, ret);
				goto port;
			}
		}

		/* Start device. */
		ret = rte_eth_dev_start(port_id);
		if (ret < 0) {
			RTE_LOG(ERR, PORT, "Failed to start port %hhu (err=%d)!\n", port_id, ret);
			goto port;
		}
		num_succ_ports++;
		
		/*
		 * The following code ensures that the device is ready for full speed RX/TX.
		 * When the initialization is done without this, the initial packet 
		 * transmission may be blocked.
		 */
		rte_eth_link_get(port_id, &link);
		if (!link.link_status) {
			RTE_LOG(ERR, PORT, "Querying port %hhu, and link is down!\n", port_id);
			ret = -1;
			goto port;
		}
	}

	/* TODO Configure the Flow Director, RSS, and Filters. */

	goto out;

port:
	close_num_ports(num_succ_ports);
out:
	return ret;
}

void
gatekeeper_free_network(void)
{
	close_num_ports(config.num_ports);
}
