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

#ifndef _SPACE_SAVING_H_
#define _SPACE_SAVING_H_

#define OVRFLOW 1000000

#include <netinet/in.h>

#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "list.h"
//#include "gatekeeper_gk.h"
//#include "gatekeeper_net.h"
//#include "gatekeeper_flow.h"

#define DEFAULT_HASH_FUNC rte_jhash

extern struct ip_key *hh_table;
extern struct list_head bkt_head_ip4;
extern struct list_head bkt_head_ip6;
extern int streamlen;
extern int mx;

struct ip_key {
	uint16_t proto;
	union {
		struct v4{
			struct in_addr src;
			struct in_addr dst;
		} v4;

		struct v6{
			struct in6_addr src;
			struct in6_addr dst;
		} v6; 
	} k;	
};

/* Data structure for Counter bucket. */
struct counter_bucket
{
	uint16_t proto;
	int bkt_id;

	union {
		/* Bucket for IPV4 address. */
		struct rte_hash *bkt_ip4;

		/* Bucket for IPV6 address. */
		struct rte_hash *bkt_ip6;
	} bkt;

	struct list_head list;
};

/* Data structure of IP data. */
struct ip_data
{
	int err;
	int bkt_id;
	struct ip_key key;
	struct counter_bucket ct_bucket;
};

int max(int a, int b);

/* 
 * Create a counter table of size = 1.0/epsion.
 * @epsilon is the error parameter for space saving algorithm.
 */
struct rte_hash *
create_counter_table(unsigned int socket_id, uint16_t proto, int counter_id,
	int ht_size);

/* Destroy a counter table. */
void destroy_counter_table(uint16_t proto, int counter_id);

/* 
 * Create a counter bucket.
 * Size of each bucket is set to 100 by default.
 * TODO: Find a way to vary the size of a bucket to ensure 
 *		 optimum memory usage.
 */
struct rte_hash *
create_bucket(unsigned int socket_id, uint16_t proto, int bkt_id);

/* Increment Counter Algorithm. */
static int
increment_counter(unsigned int socket_id, uint16_t proto, 
	struct ip_data **element);

/* Space Saving algorithm. */
int space_saving(unsigned int socket_id, uint16_t proto, struct ip_key *key,
	struct rte_hash *ct_table);

/* 
 * Iterate through the elements in the Counter Table and find the heavy hitters.  
 */
int SSiterate(struct rte_hash *ct_table, int proto, int threshold);

/* Estimate a lower bound for the frequency of an element. */ 
int SSEstLow(struct rte_hash *ct_table, struct ip_key *key);

/* Estimate an upper bound on the frequency of an element. */
int SSEstUpp(struct rte_hash *ct_table, struct ip_key *key);
 
#endif /* _SPACE_SAVING_H */
