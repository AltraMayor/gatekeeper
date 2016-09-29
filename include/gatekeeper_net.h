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

/* Configuration for the Network. */
struct net_config {
	uint16_t		num_rx_queues;
	uint16_t		num_tx_queues;
	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	uint32_t		num_ports;
	struct rte_mempool 	**gatekeeper_pktmbuf_pool;
};

struct net_config *get_net_conf(void);

int gatekeeper_init_network(struct net_config *net_conf);

void gatekeeper_free_network(void);

#endif /* _GATEKEEPER_NET_H_ */
