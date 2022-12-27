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

#ifndef _GATEKEEPER_GK_RT_H_
#define _GATEKEEPER_GK_RT_H_

#include <lauxlib.h>

#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_spinlock.h>
#include <rte_atomic.h>

#include "gatekeeper_net.h"
#include "gatekeeper_lpm.h"
#include "gatekeeper_rib.h"
#include "seqlock.h"

enum gk_fib_action {

	/* Forward the packet to the corresponding Grantor. */
	GK_FWD_GRANTOR,

	/*
	 * Forward the packet to the corresponding gateway
	 * in the front network.
	 */
	GK_FWD_GATEWAY_FRONT_NET,

	/*
	 * Forward the packet to the corresponding gateway
	 * in the back network.
	 */
	GK_FWD_GATEWAY_BACK_NET,

	/*
	 * The destination address is a neighbor in the front network.
	 * Forward the packet to the destination directly.
	 */
	GK_FWD_NEIGHBOR_FRONT_NET,

	/*
	 * The destination address is a neighbor in the back network.
	 * Forward the packet to the destination directly.
	 */
	GK_FWD_NEIGHBOR_BACK_NET,

	/* Drop the packet. */
	GK_DROP,

	/* Invalid forward action. */
	GK_FIB_MAX,
};

/*
 * The Ethernet header cache.
 * Fields @stale and @eth_hdr.d_addr are protected by the lock of
 * the cached entry.
 */
struct ether_cache {

	/*
	 * The sequential lock to deal with the
	 * concurrency between GK and LLS on the cached
	 * Ethernet header.
	 *
	 * Notice that, the LLS block will only modify
	 * the @stale and @eth_hdr.d_addr fields.
	 * Therefore, @lock only applies to these two fields.
	 */
	seqlock_t        lock;

	/*
	 * The count of how many times the LPM tables refer to it,
	 * so a neighbor entry can go away only when no one referring to it.
	 * Notice, this field is atomic because it's handled by
	 * the LLS block and the GK blocks.
	 */
	rte_atomic32_t   ref_cnt;

	/*
	 * The fields below field fields_to_clear are zeroed
	 * when entry is released.
	 */
	int              fields_to_clear[0];

	/* Indicate whether the MAC address is stale or not. */
	bool             stale;

	/* The IP address of the nexthop. */
	struct ipaddr    ip_addr;

	/* The whole link-layer header. */
	struct {
		/* Ethernet header (required). */
		struct rte_ether_hdr eth_hdr;
		/* VLAN header (optional). */
		struct rte_vlan_hdr  vlan_hdr;
	} __attribute__((packed)) l2_hdr;
};

struct neighbor_hash_table {
	int                tbl_size;

	struct rte_hash    *hash_table;

	/* The tables that store the Ethernet headers. */
	struct ether_cache *cache_tbl;
};

struct grantor_entry {
	/* The Grantor IP address. */
	struct ipaddr gt_addr;
	/* The cached Ethernet header of the next hop. */
	struct ether_cache *eth_cache;
};

struct grantor_set {
	/* Protocol of the Grantor IPs. */
	uint8_t proto;
	/* Number of structs grantor_entry that start at @entries. */
	uint16_t num_entries;
	/* List of Grantors and their next hops' cached Ethernet headers. */
	struct grantor_entry entries[0];
};

/*
 * Route properties.
 *
 * Gatekeeper does not acts on these properties. They are needed to
 * support routing daemons that expect them.
 */
struct route_properties {
	/*
	 * Routing table protocol -- origin of the route.
	 * RTPROT_STATIC for routes added by user.
	 * RTPROT_BIRD for routes added by BIRD daemon, etc.
	 */
	uint8_t  rt_proto;

	uint32_t priority;
};

/* The gk forward information base (fib). */
struct gk_fib {

	/* The fib action. */
	enum gk_fib_action action;

	union {
		/*
	 	 * The nexthop information when the action is
		 * GK_FWD_GATEWAY_*_NET.
	 	 */
		struct {
			/* The cached Ethernet header. */
			struct ether_cache *eth_cache;

			struct route_properties props;
		} gateway;

		/* Route information when the action is GK_FWD_GRANTOR. */
		struct {
			/*
			 * Set of Grantors that packets to this
			 * destination should be load balanced to.
			 */
			struct grantor_set *set;
		} grantor;

		/*
		 * When the action is GK_FWD_NEIGHBOR_*_NET, it stores all
		 * the neighbors' Ethernet headers in a hash table.
		 * The entries can be accessed according to its IP address.
		 */
		struct neighbor_hash_table neigh;

		/* Route information when the action is GK_DROP. */
		struct {
			struct route_properties props;
		} drop;
	} u;
};

/* The global LPM table of Gatekeeper servers (not Grantor servers). */
struct gk_lpm {
	/* Use a spin lock to edit the FIB table. */
	rte_spinlock_t  lock;

	/* The IPv4 RIB. */
	struct rib_head rib;

	/* The IPv4 FIB. */
	struct rte_lpm  *lpm;

	/* The IPv4 FIB table that decides the actions on packets. */
	struct gk_fib   *fib_tbl;

	/* The IPv6 RIB. */
	struct rib_head rib6;

	/* The IPv6 FIB. */
	struct rte_lpm6 *lpm6;

	/* The IPv6 FIB table that decides the actions on packets. */
	struct gk_fib   *fib_tbl6;

	/*
	 * Indexes of the last FIB entries allocated at @fib_tbl and @fib_tbl6.
	 * get_empty_fib_id() is the only function that uses these fields.
	 */
	uint32_t        last_ipv4_index;
	uint32_t        last_ipv6_index;
};

struct ip_prefix {
	const char    *str;
	struct ipaddr addr;
	int           len;
};

/*
 * Since GK_FWD_GRANTOR entries can have mulitple Grantor IPs
 * for load balancing (and therefore multiple next hops),
 * we group together this information into an address set.
 */
struct fib_dump_addr_set {
	/*
	 * The Grantor IP address. Only applicable for
	 * FIB entries of type GK_FWD_GRANTOR.
	 */
	struct ipaddr grantor_ip;
	/* The next hop (gateway) IP address. */
	struct ipaddr nexthop_ip;
	/* The MAC address of @nexthop_ip. */
	struct rte_ether_addr d_addr;
	/* Whether the resolution for @nexthop_ip to @d_addr is invalid. */
	bool          stale;
};

struct gk_fib_dump_entry {
	/* The IP prefix. */
	struct ipaddr addr;

	/* The prefix length of @addr. */
	int           prefix_len;

	/* The FIB action. */
	enum gk_fib_action action;

	/* Unique ID of this FIB entry. */
	unsigned int  fib_id;

	/*
	 * The number of entries starting at @addr_sets.
	 *
	 *  - For GK_GWD_GRANTOR, this value is the number
	 *    of (Grantor, gateway) pairs.
	 *  - For GK_DROP, this is 0.
	 *  - For all other @action values, this is 1.
	 */
	unsigned int  num_addr_sets;

	/*
	 * Address sets.
	 *
	 * When @action is GK_FWD_GRANTOR, all fields
	 * are valid (Grantor IP, next hop IP, next hop MAC, stale),
	 * and there can be multiple address sets.
	 *
	 * When @action is GK_DROP, there are no address sets.
	 *
	 * When @action is anything else, only the fields related
	 * to the next hop are valid (next hop IP, next hop MAC, stale),
	 * and there should only be one address set.
	 */
	struct fib_dump_addr_set addr_sets[0];
};

struct gk_neighbor_dump_entry {

	bool          stale;

	/* The fib action. */
	enum gk_fib_action action;

	/* The IP address of the neighbor. */
	struct ipaddr neigh_ip;

	/* The the MAC address of neigh_ip. */
	struct rte_ether_addr d_addr;
};

struct gk_config;

int clear_ether_cache(struct ether_cache *eth_cache);
uint32_t custom_ipv4_hash_func(const void *key,
	uint32_t length, uint32_t initval);
int setup_neighbor_tbl(unsigned int socket_id, int identifier,
	int ip_ver, int ht_size, struct neighbor_hash_table *neigh,
	rte_hash_function hash_func);
int setup_gk_lpm(struct gk_config *gk_conf, unsigned int socket_id);
void destroy_neigh_hash_table(struct neighbor_hash_table *neigh);

int parse_ip_prefix(const char *ip_prefix, struct ipaddr *res);

int add_fib_entry_numerical(const struct ip_prefix *prefix_info,
	struct ipaddr *gt_addrs, struct ipaddr *gw_addrs,
	unsigned int num_addrs, enum gk_fib_action action,
	const struct route_properties *props, struct gk_config *gk_conf);
int add_fib_entry_numerical_locked(const struct ip_prefix *prefix_info,
	struct ipaddr *gt_addrs, struct ipaddr *gw_addrs,
	unsigned int num_addrs, enum gk_fib_action action,
	const struct route_properties *props, struct gk_config *gk_conf);
int add_fib_entry(const char *prefix, const char *gt_ip, const char *gw_ip,
	enum gk_fib_action action, struct gk_config *gk_conf);
int del_fib_entry_numerical(const struct ip_prefix *prefix_info,
	struct gk_config *gk_conf);
int del_fib_entry_numerical_locked(const struct ip_prefix *prefix_info,
	struct gk_config *gk_conf);
int del_fib_entry(const char *ip_prefix, struct gk_config *gk_conf);

int l_list_gk_fib4(lua_State *l);
int l_list_gk_fib6(lua_State *l);
int l_list_gk_neighbors4(lua_State *l);
int l_list_gk_neighbors6(lua_State *l);
int l_ether_format_addr(lua_State *l);
int l_ip_format_addr(lua_State *l);
int l_add_grantor_entry_lb(lua_State *l);
int l_update_grantor_entry_lb(lua_State *l);

#define CTYPE_STRUCT_GK_CONFIG_PTR "struct gk_config *"

static inline struct ether_cache *
lookup_ether_cache(struct neighbor_hash_table *neigh_tbl, void *key)
{
	struct ether_cache *eth_cache;
	int ret = rte_hash_lookup_data(neigh_tbl->hash_table,
		key, (void **)&eth_cache);
	if (ret < 0)
		return NULL;

	return eth_cache;
}

#endif /* _GATEKEEPER_GK_RT_H_ */
