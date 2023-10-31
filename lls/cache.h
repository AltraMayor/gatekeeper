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

#ifndef _GATEKEEPER_LLS_CACHE_H_
#define _GATEKEEPER_LLS_CACHE_H_

#include "gatekeeper_lls.h"

/* Information needed to add a hold to a record. */
struct lls_hold_req {
	/* Cache that holds (or will hold) this map. */
	struct lls_cache *cache;

	/* IP address for this request. */
	struct ipaddr    addr;

	/* Hold that this is requesting. */
	struct lls_hold  hold;
};

/* Information needed to drop a struct lls_hold from a record. */
struct lls_put_req {
	/* Cache that (possibly) has this hold. */
	struct lls_cache *cache;

	/* IP address for this request. */
	struct ipaddr    addr;

	/* The lcore that requested this put. */
	unsigned int     lcore_id;
};

/* Information needed to submit packets to the LLS block. */
struct lls_packets_req {
	/* Number of packets stored in @pkts. */
	unsigned int         num_pkts;

	/* Interface that received the packets. */
	struct gatekeeper_if *iface;

	/* The packets already classified. */
	struct absflow_packet infos[0];
};

/* A modification to an LLS map. */
struct lls_mod_req {
	/* Cache that holds (or will hold) this map. */
	struct lls_cache      *cache;

	/* IP address for this modification. */
	struct ipaddr         addr;

	/*
	 * Ethernet address of modification, possibly
	 * not different from existing address in record.
	 */
	struct rte_ether_addr ha;

	/*
	 * Port of modification, possibly not
	 * different from existing port ID in record.
	 */
	uint16_t              port_id;

	/* Timestamp of this modification. */
	time_t                ts;
};

/* Request submitted to the LLS block. */
struct lls_request {
	/* Type of request. */
	enum lls_req_ty ty;

	int end_of_header[0];

	union {
		/* If @ty is LLS_REQ_HOLD, use @hold. */
		struct lls_hold_req    hold;
		/* If @ty is LLS_REQ_PUT, use @put. */
		struct lls_put_req     put;
		/* If @ty is LLS_REQ_PACKETS, use @packets. */
		struct lls_packets_req packets;
	} u;
};

int lls_cache_init(struct lls_config *lls_conf, struct lls_cache *cache,
	uint32_t key_len);
void lls_cache_destroy(struct lls_cache *cache);

/* Process any requests to the LLS block. */
unsigned int lls_process_reqs(struct lls_config *lls_conf);

/*
 * Modify a cache entry without going through the mailbox.
 *
 * NOTE
 *	This should only be used by the LLS block itself. Other
 *	requests to modify the cache should go through lls_req().
 */
void lls_process_mod(struct lls_config *lls_conf, struct lls_mod_req *mod);

/*
 * Fetch a map according to the key in @addr.
 *
 * NOTE
 *	This should only be used by the LLS block itself. Other
 *	requests to get maps should go through hold requests.
 */
struct lls_map *lls_cache_get(struct lls_cache *cache,
	const struct ipaddr *addr);

/* Scan the cache and send requests or remove entries as needed. */
void lls_cache_scan(struct lls_config *lls_conf, struct lls_cache *cache);

#endif /* _GATEKEEPER_LLS_CACHE_H_ */
