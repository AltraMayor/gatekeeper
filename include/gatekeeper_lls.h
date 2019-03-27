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

#include <rte_arp.h>
#include <rte_ip.h>

#include "gatekeeper_acl.h"
#include "gatekeeper_mailbox.h"
#include "gatekeeper_log_ratelimit.h"

extern int lls_logtype;

#define LLS_LOG(level, ...)                               \
	rte_log_ratelimit(RTE_LOG_ ## level, lls_logtype, \
		"GATEKEEPER LLS: " __VA_ARGS__)

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
	/* Request to handle ARP packets received from another block. */
	LLS_REQ_ARP,
	/* Request to handle ND packets received from another block. */
	LLS_REQ_ND,
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
	uint16_t          port_id;

	/* Whether this map has been marked as stale. */
	int               stale;

	/* IP address for this map, in network ordering. */
	struct ipaddr     addr;
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

/* For dumping LLS entries using the Dynamic Config. */
struct lls_dump_entry {
	/* Whether this entry is stale. */
	bool              stale;
	/* The port on which this entry resides. */
	uint16_t          port_id;
	/* The IP address of the entry. */
	struct ipaddr     addr;
	/* The MAC address of the entry. */
	struct ether_addr ha;
};

struct lls_cache {
	/* Timeout value (in seconds) to mark entries as stale. */
	uint32_t          front_timeout_sec;
	uint32_t          back_timeout_sec;

	/* Name string (needed for cache hash). */
	const char        *name;

	/* Array of cache records indexed using @hash. */
	struct lls_record *records;

	/* Hash instance that maps IP address keys to LLS cache records. */
	struct rte_hash   *hash;

	/* Returns whether the cache is enabled for @iface. */
	int (*iface_enabled)(struct net_config *net,
		struct gatekeeper_if *iface);

	/*
	 * Returns whether @addr is in the same subnet as the
	 * relevant address for this cache assigned to @iface.
	 */
	int (*ip_in_subnet)(struct gatekeeper_if *iface,
		const struct ipaddr *addr);

	/*
	 * Function to transmit a request out of @iface to resolve
	 * IP address @addr to an Ethernet address.
	 *
	 * If @ha is NULL, then broadcast (IPv4) or multicast (IPv6).
	 * Otherwise, unicast to @ha.
	 */
	void (*xmit_req)(struct gatekeeper_if *iface,
		const struct ipaddr *addr,
		const struct ether_addr *ha, uint16_t tx_queue);
};

struct lls_config {
	/* lcore that the LLS block runs on. */
	unsigned int      lcore_id;

	/* The maximum number of packets to retrieve/transmit. */
	uint16_t          front_max_pkt_burst;
	uint16_t          back_max_pkt_burst;

	/* The maximum number of ARP or ND packets submitted by GK or GT. */
	unsigned int      mailbox_max_pkt_sub;

	/* Parameters to setup the mailbox instance. */
	unsigned int      mailbox_max_entries_exp;
	unsigned int      mailbox_mem_cache_size;
	unsigned int      mailbox_burst_size;

	/* Number of records that a LLS cache can hold. */
	unsigned int      lls_cache_records;

	/* Length of time (in seconds) to wait between scans of the cache. */
	unsigned int      lls_cache_scan_interval_sec;

	/* Log level for LLS block. */
	uint32_t          log_level;
	/* Dynamic logging type, assigned at runtime. */
	int               log_type;
	/* Log ratelimit interval in ms for LLS block. */
	uint32_t          log_ratelimit_interval_ms;
	/* Log ratelimit burst size for LLS block. */
	uint32_t          log_ratelimit_burst;

	/*
	 * The fields below are for internal use.
	 * Configuration files should not refer to them.
	 */
	struct net_config *net;

	/* Mailbox to hold requests from other blocks. */
	struct mailbox    requests;

	/* Cache of entries that map IPv4 addresses to Ethernet addresses. */
	struct lls_cache  arp_cache;

	/* Cache of entries that map IPv6 addresses to Ethernet addresses. */
	struct lls_cache  nd_cache;

	/* Timer to scan over LLS cache(s). */
	struct rte_timer  scan_timer;

	/* Timer to create new log files. */
	struct rte_timer  log_timer;

	/* Receive and transmit queues for both interfaces. */
	uint16_t          rx_queue_front;
	uint16_t          tx_queue_front;
	uint16_t          rx_queue_back;
	uint16_t          tx_queue_back;
};

/*
 * In LLS, it was a conscious design decision to push the task of
 * avoiding duplicates to the individual blocks, instead of
 * putting it in the LLS cache.
 *
 * For example, the CPS block maintains
 * a linked list of ARP and ND holds that it has made so that
 * it does not issue duplicate requests.
 *
 * For GK and GT blocks: GK blocks avoid the duplicates with the
 * help of their hash tables of neighbors that leaves inside of the LPM table.
 * And each GT block has a hash table of neighbors.
 */

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

/*
 * A Gratuitous ARP is an ARP request that serves as an announcement of
 * a neighbor's mapping. The sender and target IP address should be the same,
 * AND the target Ethernet address should be the same as the sender Ethernet
 * address OR zero.
 */
static inline int
is_garp_pkt(const struct arp_hdr *arp_hdr)
{
	return (arp_hdr->arp_data.arp_sip == arp_hdr->arp_data.arp_tip) &&
		(is_zero_ether_addr(&arp_hdr->arp_data.arp_tha) ||
		is_same_ether_addr(&arp_hdr->arp_data.arp_tha,
			&arp_hdr->arp_data.arp_sha));
}

#define rte_ipv6_icmpv6_cksum rte_ipv6_udptcp_cksum

struct icmpv6_hdr {
	/* The type of this ICMPv6 packet. */
	uint8_t  type;
	/* An additional value to describe the message, dependent on @type. */
	uint8_t  code;
	/* Checksum over the entire ICMPv6 message. */
	uint16_t cksum;
} __attribute__((__packed__));

struct nd_neigh_msg {
	/*
	 * For Neighbor Solicitations, @flags is reserved and should be 0.
	 *
	 * For Neighbor Advertisements, the most significant three bits
	 * of @flags should be: router (msb), solicited, and override.
	 * The other 29 bits of @flags are reserved and should be 0.
	 */
	uint32_t          flags;
	/* IPv6 address of the target of the ND messages. */
	uint8_t           target[16];
	/* Any ND options, if present. */
	uint8_t           opts[0];
} __attribute__((__packed__));

/* ND options as defined by RFC 4861. */
enum {
	/* Link-layer address of sender, optional in Solicitations. */
	ND_OPT_SOURCE_LL_ADDR = 1,
	/* Link-layer address of the target, optional in Advertisements. */
	ND_OPT_TARGET_LL_ADDR = 2,
	/* Other options exist but are not supported here. */
	ND_OPT_MAX,
};

struct nd_opts {
	/* Pointers to each option present in an ICMPv6 packet. */
	struct nd_opt_hdr *opt_array[ND_OPT_MAX];
};

struct nd_opt_hdr {
	/* Type of the option. */
	uint8_t type;
	/* Length of option (including @type and @len) in units of 64 bits. */
	uint8_t len;
} __attribute__((__packed__));

/* Used for both ND_OPT_SOURCE_LL_ADDR and ND_OPT_TARGET_LL_ADDR. */
struct nd_opt_lladdr {
	/* Type of the option. */
	uint8_t           type;
	/* Length of option (including @type and @len) in units of 64 bits. */
	uint8_t           len;
	/* Hardware address corresponding to @type. */
	struct ether_addr ha;
} __attribute__((__packed__));

#define ND_NEIGH_HDR_MIN_LEN (sizeof(struct nd_neigh_msg))

#define ND_NEIGH_PKT_MIN_LEN(l2_len) (l2_len + \
	sizeof(struct ipv6_hdr) + sizeof(struct icmpv6_hdr) + \
	ND_NEIGH_HDR_MIN_LEN)

/* Minimum size of a Neighbor Discovery packet with a link-layer option. */
#define ND_NEIGH_PKT_LLADDR_MIN_LEN(l2_len) (ND_NEIGH_PKT_MIN_LEN(l2_len) + \
	sizeof(struct nd_opt_lladdr))

/* Flags for Neighbor Advertisements. */
#define LLS_ND_NA_ROUTER    0x80000000
#define LLS_ND_NA_SOLICITED 0x40000000
#define LLS_ND_NA_OVERRIDE  0x20000000

/* Supported IPv6 ND packets via the type field in struct icmpv6_hdr. */
#define ND_NEIGHBOR_SOLICITATION (135)
#define ND_NEIGHBOR_ADVERTISEMENT (136)

static inline int
arp_enabled(struct lls_config *lls_conf)
{
	return lls_conf->arp_cache.iface_enabled(lls_conf->net,
			&lls_conf->net->front) ||
		lls_conf->arp_cache.iface_enabled(lls_conf->net,
			&lls_conf->net->back);
}

static inline int
nd_enabled(struct lls_config *lls_conf)
{
	return lls_conf->nd_cache.iface_enabled(lls_conf->net,
			&lls_conf->net->front) ||
		lls_conf->nd_cache.iface_enabled(lls_conf->net,
			&lls_conf->net->back);
}

/*
 * Interface for functional blocks to resolve IPv6 --> Ethernet addresses.
 *
 * Functionality is the same as for hold_arp() and put_arp(); see
 * comments above.
 */
int hold_nd(lls_req_cb cb, void *arg, struct in6_addr *ip_be,
	unsigned int lcore_id);
int put_nd(struct in6_addr *ip_be, unsigned int lcore_id);

static inline int
ipv6_addrs_equal(const uint8_t *addr1, const uint8_t *addr2)
{
	const uint64_t *paddr1 = (const uint64_t *)addr1;
	const uint64_t *paddr2 = (const uint64_t *)addr2;
	return (paddr1[0] == paddr2[0]) && (paddr1[1] == paddr2[1]);
}

/* Submit ARP packets to the LLS block (hardware filtering is not available). */
void submit_arp(struct rte_mbuf **pkts, unsigned int num_pkts,
	struct gatekeeper_if *iface);

struct lls_config *get_lls_conf(void);
int run_lls(struct net_config *net_conf, struct lls_config *lls_conf);

int l_list_lls_arp(lua_State *l);
int l_list_lls_nd(lua_State *l);

#endif /* _GATEKEEPER_LLS_H_ */
