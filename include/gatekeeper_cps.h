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

#include "gatekeeper_gk.h"
#include "gatekeeper_gt.h"
#include "gatekeeper_mailbox.h"
#include "gatekeeper_log_ratelimit.h"
#include "list.h"

extern int cps_logtype;

#define CPS_LOG(level, ...)                              \
	rte_log_ratelimit(RTE_LOG_ ## level, cps_logtype,\
		"GATEKEEPER CPS: " __VA_ARGS__)

/* Configuration for the Control Plane Support functional block. */
struct cps_config {
	/* lcore that the CPS block runs on. */
	unsigned int       lcore_id;
	/* Source and destination TCP ports to capture BGP traffic. */
	uint16_t           tcp_port_bgp;

	/* Log level for CPS block. */
	uint32_t           log_level;
	/* Dynamic logging type, assigned at runtime. */
	int                log_type;
	/* Log ratelimit interval in ms for CPS block. */
	uint32_t           log_ratelimit_interval_ms;
	/* Log ratelimit burst size for CPS block. */
	uint32_t           log_ratelimit_burst;

	/* The maximum number of packets to retrieve/transmit. */
	uint16_t           front_max_pkt_burst;
	uint16_t           back_max_pkt_burst;

	/* Number of times to attempt bring a KNI interface up or down. */
	unsigned int       num_attempts_kni_link_set;

	/* Maximum number of route update packets to serve at once. */
	unsigned int       max_rt_update_pkts;

	/*
	 * Period between scans of the outstanding
	 * resolution requests from KNIs.
	 */
	unsigned int       scan_interval_sec;

	/* Parameters to setup the mailbox instance. */
	unsigned int       mailbox_max_entries_exp;
	unsigned int       mailbox_mem_cache_size;
	unsigned int       mailbox_burst_size;

	/* Netlink port ID for communicating with routing daemon. */
	uint32_t           nl_pid;

	/* Parameters to setup the ARP requests mempool. */
	unsigned int       arp_max_entries_exp;

	/* Parameters to setup the ND requests mempool. */
	unsigned int       nd_max_entries_exp;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */

	/* The maximum number of packets submitted to CPS mailbox. */
	unsigned int       mailbox_max_pkt_burst;

	struct net_config  *net;
	struct lls_config  *lls;

	/* Kernel NIC interfaces for control plane messages */
	struct rte_kni     *front_kni;
	struct rte_kni     *back_kni;

	/* Output interface IDs for the KNIs; used with routing daemons. */
	unsigned int       front_kni_index;
	unsigned int       back_kni_index;

	/* Mailbox to hold requests from other blocks. */
	struct mailbox     mailbox;

	/* Receive and transmit queues for both interfaces. */
	uint16_t           rx_queue_front;
	uint16_t           tx_queue_front;
	uint16_t           rx_queue_back;
	uint16_t           tx_queue_back;

	/* Unanswered resolution requests from the KNIs. */
	struct list_head   arp_requests;
	struct list_head   nd_requests;

	/* Timer to scan over outstanding resolution requests. */
	struct rte_timer   scan_timer;

	/*
	 * Netlink socket for receiving from the routing daemon.
	 * Bound to @nl_pid so that userspace routing daemons
	 * can be configured to update Gatekeeper.
	 */
	struct mnl_socket  *rd_nl;

	struct gk_config   *gk;
	struct gt_config   *gt;

	unsigned int       total_pkt_burst;
	/* The packet mbuf pool for the CPS block. */
	struct rte_mempool *mp;
	/* The ARP requests pool for the CPS block. */
	struct rte_mempool *arp_mp;
	/* The ND requests pool for the CPS block. */
	struct rte_mempool *nd_mp;
};

/* Information needed to submit packets directly to KNI. */
struct cps_direct_req {
	/* Number of packets stored in @pkts. */
	unsigned int         num_pkts;

	/* KNI that should receive @pkts. */
	struct rte_kni       *kni;

	/* Packets to submit to KNI. */
	struct rte_mbuf      *pkts[0];
};

/*
 * Information needed for the LLS block to submit a request for
 * the CPS block to send ARP/ND replies back to the KNI. To do so,
 * the CPS block needs to know the IP and hardware address of the
 * map, as well as the interface on which this map was received.
 */

struct cps_arp_req {
	uint32_t              ip;
	struct rte_ether_addr ha;
	struct gatekeeper_if  *iface;
};

struct cps_nd_req {
	uint8_t               ip[16];
	struct rte_ether_addr ha;
	struct gatekeeper_if  *iface;
};

/* Requests that can be made to the CPS block. */
enum cps_req_ty {
	/* Request to directly hand packets received by other blocks to KNI. */
	CPS_REQ_DIRECT,
	/* Request to handle a response to an ARP packet. */
	CPS_REQ_ARP,
	/* Request to handle a response to an ND packet. */
	CPS_REQ_ND,
};

/* Request submitted to the CPS block. */
struct cps_request {
	/* Type of request. */
	enum cps_req_ty ty;

	int end_of_header[0];

	union {
		/* If @ty is CPS_REQ_DIRECT, use @direct. */
		struct cps_direct_req direct;
		/* If @ty is CPS_REQ_ARP, use @arp. */
		struct cps_arp_req arp;
		/* If @ty is CPS_REQ_ND, use @nd. */
		struct cps_nd_req nd;
	} u;
};

int cps_submit_direct(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface);

struct cps_config *get_cps_conf(void);
int run_cps(struct net_config *net_conf, struct gk_config *gk_conf,
	struct gt_config *gt_conf, struct cps_config *cps_conf,
	struct lls_config *lls_conf, const char *kni_kmod_path);

#endif /* _GATEKEEPER_CPS_H_ */
