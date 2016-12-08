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

#ifndef _GATEKEEPER_LLS_H_
#define _GATEKEEPER_LLS_H_

#include <netinet/in.h>

#include <rte_timer.h>

#include "gatekeeper_mailbox.h"
#include "gatekeeper_net.h"

/*
 * Maximum key length (in bytes) for an LLS map. It should be set
 * to the maximum key length needed. Currently, this is set to 16 for
 * the number of bytes in an IPv6 address.
 */
#define LLS_MAX_KEY_LEN (16)

/* Number of records that a LLS cache can hold. */
#define LLS_CACHE_RECORDS (1024)

/* Requests that can be made to the LLS block. */
enum lls_req_ty {
	/* Express interest in a map by registering a callback function. */
	LLS_REQ_HOLD,
	/*
	 * Remove a previously-submitted hold, if not already deleted
	 * by virtue of a callback function signaling it should not
	 * be invoked again.
	 */
	LLS_REQ_PUT,
};

/* Replies that come from the LLS block. */
enum lls_reply_ty {
	/* The reply represents a map resolution (or update to one). */
	LLS_REPLY_RESOLUTION,
	/*
	 * The reply is a notification that the hold is
	 * removed, so the requester can free state as needed.
	 */
	LLS_REPLY_FREE,
};

/* Map that is returned to blocks that request resolution. */
struct lls_map {
	/* Ethernet address of this map. */
	struct ether_addr ha;

	/* Port on which this map exists. */
	uint8_t           port_id;

	/* Whether this map has been marked as stale. */
	int               stale;

	/* IP address for this map, in network ordering. */
	uint8_t           ip_be[LLS_MAX_KEY_LEN];
};

/*
 * Format of callback function for requesting LLS maps.
 *
 * The LLS block invokes the callbacks, so each block should ensure
 * that the callback function deals with any race conditions and
 * is aware that the blocks may reside in different NUMA nodes.
 *
 * If the requesting block wants future updates, it should set
 * *@pcall_again to true before returning. Otherwise, by default
 * the LLS block will remove the interest from the block. If
 * *@pcall_again is set to true, then the block may release all
 * resources attached to the callback before returning.
 *
 * When @ty is LLS_REPLY_FREE, @pcall_again is NULL to indicate
 * that this will be the last callback for this hold.
 */
typedef void (*lls_req_cb)(const struct lls_map *map, void *arg,
	enum lls_reply_ty ty, int *pcall_again);

/* A hold for an LLS map. */
struct lls_hold {
	/* Callback function for replies from the LLS block. */
	lls_req_cb   cb;

	/* Optional argument to @cb. */
	void         *arg;

	/* The lcore that requested this hold. */
	unsigned int lcore_id;
};

struct lls_record {
	/* IP --> Ethernet address map for this record. */
	struct lls_map  map;

	 /* Timestamp of the last update to the map. */
	time_t          ts;

	/*
	 * Number of requests to hold this map. Blocks
	 * should only request a hold for a map once
	 * to avoid multiple entries for an lcore in @holds.
	 */
	uint32_t        num_holds;

	/* Holds for @map. */
	struct lls_hold holds[RTE_MAX_LCORE];
};

struct lls_cache {
	/* Length (in bytes) of keys for this cache. */
	uint32_t          key_len;

	/* Maximum length (in bytes) for strings of keys for this cache. */
	uint32_t          key_str_len;

	/* Timeout value (in seconds) to mark entries as stale. */
	uint32_t          front_timeout_sec;
	uint32_t          back_timeout_sec;

	/* Name string (needed for cache hash). */
	const char        *name;

	/* Array of cache records indexed using @hash. */
	struct lls_record records[LLS_CACHE_RECORDS];

	/* Hash instance that maps IP address keys to LLS cache records. */
	struct rte_hash   *hash;

	/* Returns whether the cache is enabled for @iface. */
	int (*iface_enabled)(struct net_config *net,
		struct gatekeeper_if *iface);

	/* Convert @ip_be to string form and store it in @buf. */
	char *(*ip_str)(struct lls_cache *cache, const uint8_t *ip_be,
		char *buf, size_t len);

	/*
	 * Function to transmit a request out of @iface to resolve
	 * IP address @ip_be to an Ethernet address.
	 *
	 * If @ha is NULL, then broadcast. Otherwise, unicast to @ha.
	 */
	void (*xmit_req)(struct gatekeeper_if *iface, const uint8_t *ip_be,
		const struct ether_addr *ha, uint16_t tx_queue);

	/* Function to print a cache record. */
	void (*print_record)(struct lls_cache *cache,
		struct lls_record *record);
};

struct lls_config {
	/* lcore that the LLS block runs on. */
	unsigned int      lcore_id;

	/*
	 * When non-zero, all caches will be dumped when
	 * they are changed or periodically scanned.
	 */
	int               debug;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	struct net_config *net;

	/* Mailbox to hold requests from other blocks. */
	struct mailbox    requests;

	/* Cache of entries that map IPv4 addresses to Ethernet addresses. */
	struct lls_cache  arp_cache;

	/* Timer to scan over LLS cache(s). */
	struct rte_timer  timer;

	/* Receive and transmit queues for both interfaces. */
	uint16_t          rx_queue_front;
	uint16_t          tx_queue_front;
	uint16_t          rx_queue_back;
	uint16_t          tx_queue_back;
};

/*
 * Interface for functional blocks to resolve IPv4 --> Ethernet addresses.
 *
 * To obtain a map, a functional block running on @lcore_id should invoke
 * hold_arp() with a callback function @cb and an optional @arg. When
 * a resolution is available, @cb will be invoked by the LLS block to
 * deliver a struct lls_map (and @arg) to the functional block.
 *
 * For every map requested through hold_arp(), functional blocks should
 * also indicate in an invocation of the callback that they do not wish
 * for it to be called again and/or call put_arp().
 *
 * Blocks should not repeatedly call hold_arp() for an already-requested
 * map without first releasing the map by indicating the callback should
 * not be called again and/or by calling put_arp() to clear its request
 * from the LLS.
 */
int hold_arp(lls_req_cb cb, void *arg, struct in_addr *ip_be,
	unsigned int lcore_id);
int put_arp(struct in_addr *ip_be, unsigned int lcore_id);

struct lls_config *get_lls_conf(void);
int run_lls(struct net_config *net_conf, struct lls_config *lls_conf);

#endif /* _GATEKEEPER_LLS_H_ */
