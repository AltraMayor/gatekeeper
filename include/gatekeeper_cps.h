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

#ifndef _GATEKEEPER_CPS_H_
#define _GATEKEEPER_CPS_H_

#include "gatekeeper_mailbox.h"

/* Configuration for the Control Plane Support functional block. */
struct cps_config {
	/* lcore that the CPS block runs on. */
	unsigned int      lcore_id;
	/* Source and destination TCP ports to capture BGP traffic. */
	uint16_t          tcp_port_bgp;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	struct net_config *net;

	/* Kernel NIC interfaces for control plane messages */
	struct rte_kni    *front_kni;
	struct rte_kni    *back_kni;

	/* Mailbox to hold requests from other blocks. */
	struct mailbox    mailbox;

	/* Receive and transmit queues for both interfaces. */
	uint16_t          rx_queue_front;
	uint16_t          tx_queue_front;
	uint16_t          rx_queue_back;
	uint16_t          tx_queue_back;
};

struct cps_config *get_cps_conf(void);
int run_cps(struct net_config *net_conf, struct cps_config *cps_conf,
	const char *kni_kmod_path);

#endif /* _GATEKEEPER_CPS_H_ */
