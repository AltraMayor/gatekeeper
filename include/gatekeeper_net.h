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

#ifndef _GATEKEEPER_NET_H_
#define _GATEKEEPER_NET_H_

#include <stdint.h>

/*
 * A Gatekeeper interface is specified by a set of PCI addresses
 * that map to DPDK port numbers. If multiple ports are specified,
 * then the ports are bonded.
 */
struct gatekeeper_if {
	/* The ports (in PCI address format) that compose this interface. */
	char		**pci_addrs;

	/* The number of ports that in this interface (length of @pci_addrs). */
	uint8_t		num_ports;

	/* Name of the interface. Needed for setting/getting bonded port. */
	char		*name;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* DPDK port IDs corresponding to each address in @pci_addrs. */
	uint8_t		*ports;

	/*
	 * The DPDK port ID for this interface.
	 *
	 * If @ports only has one element, then @id is that port.
	 * If @ports has multiple elements, then @id is the DPDK
	 * *bonded* port ID representing all of those ports.
	 */
	uint8_t         id;
};

/* Configuration for the Network. */
struct net_config {
	uint16_t		num_rx_queues;
	uint16_t		num_tx_queues;

	struct gatekeeper_if	front;
	struct gatekeeper_if	back;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	uint32_t		num_ports;
	uint32_t		numa_nodes;
	struct rte_mempool 	**gatekeeper_pktmbuf_pool;
};

int lua_init_iface(struct gatekeeper_if *iface, const char *iface_name,
	const char **pci_addrs, uint8_t num_pci_addrs);
void lua_free_iface(struct gatekeeper_if *iface);

struct net_config *get_net_conf(void);
struct gatekeeper_if *get_if_front(struct net_config *net_conf);
struct gatekeeper_if *get_if_back(struct net_config *net_conf);
int gatekeeper_init_network(struct net_config *net_conf);
void gatekeeper_free_network(void);

#endif /* _GATEKEEPER_NET_H_ */
