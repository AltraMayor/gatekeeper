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

#include <rte_timer.h>

#include "gatekeeper_mailbox.h"
#include "list.h"

/* Configuration for the Control Plane Support functional block. */
struct cps_config {
	/* lcore that the CPS block runs on. */
	unsigned int      lcore_id;
	/* Source and destination TCP ports to capture BGP traffic. */
	uint16_t          tcp_port_bgp;

	/*
	 * When non-zero, routing table update information
	 * from the KNI will be displayed.
	 */
	int               debug;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	struct net_config *net;
	struct lls_config *lls;

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

	/* Unanswered resolution requests from the KNIs. */
	struct list_head  arp_requests;
	struct list_head  nd_requests;

	/* Timer to scan over outstanding resolution requests. */
	struct rte_timer  scan_timer;

	/* Socket for receiving routing table updates. */
	struct mnl_socket *nl;
};

/* Information needed to submit IPv6 BGP packets to the CPS block. */
struct cps_bgp_req {
	/* IPv6 BGP packets. */
	struct rte_mbuf      *pkts[GATEKEEPER_MAX_PKT_BURST];

	/* Number of packets stored in @pkts. */
	unsigned int         num_pkts;

	/* KNI that should receive @pkts. */
	struct rte_kni       *kni;
};

/*
 * Information needed for the LLS block to submit a request for
 * the CPS block to send ARP/ND replies back to the KNI. To do so,
 * the CPS block needs to know the IP and hardware address of the
 * map, as well as the interface on which this map was received.
 */

struct cps_arp_req {
	uint32_t             ip;
	struct ether_addr    ha;
	struct gatekeeper_if *iface;
};

struct cps_nd_req {
	uint8_t              ip[16];
	struct ether_addr    ha;
	struct gatekeeper_if *iface;
};

/* Requests that can be made to the CPS block. */
enum cps_req_ty {
	/* Request to handle an IPv6 BGP packet received from another block. */
	CPS_REQ_BGP,
	/* Request to handle a response to an ARP packet. */
	CPS_REQ_ARP,
	/* Request to handle a response to an ND packet. */
	CPS_REQ_ND,
};

/* Request submitted to the CPS block. */
struct cps_request {
	/* Type of request. */
	enum cps_req_ty ty;

	union {
		/* If @ty is CPS_REQ_BGP, use @bgp. */
		struct cps_bgp_req bgp;
		/* If @ty is CPS_REQ_ARP, use @arp. */
		struct cps_arp_req arp;
		/* If @ty is CPS_REQ_ND, use @nd. */
		struct cps_nd_req nd;
	} u;
};

struct route_update {
	/* Type of update: RTM_NEWROUTE or RTM_DELROUTE. */
	int type;

	/* Address family of update: AF_INET or AF_INET6. */
	int family;

	/*
	 * Whether this update has all the fields and attributes
	 * necessary to update the LPM table.
	 */
	int valid;
};

struct cps_config *get_cps_conf(void);
int run_cps(struct net_config *net_conf, struct cps_config *cps_conf,
	struct lls_config *lls_conf, const char *kni_kmod_path);

#endif /* _GATEKEEPER_CPS_H_ */
