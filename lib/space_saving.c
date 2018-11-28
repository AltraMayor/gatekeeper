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

/*
 * This Implementation is similar to the stream summary data structure decribed
 * in the research paper on space saving algorithm by Ahmed Metwally,
 * Divyakant Agrawal and Amr El Abbadi. 
 * https://pdfs.semanticscholar.org/72f1/5aba2e67b1cc9cd1fb12c99e101c4c1aae4b.pdf.
 */

#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <rte_ring.h>

#include "space_saving.h"

struct list_head bkt_head_ip4 = LIST_HEAD_INIT(bkt_head_ip4);
struct list_head bkt_head_ip6 = LIST_HEAD_INIT(bkt_head_ip6);

struct ip_key *hh_table;
int hh_size = 1;
int numhitter;

int streamlen = 0;
int mx = 0;

int max(int a, int b) {
	return (a > b) ? a : b;
}

struct rte_hash *
create_counter_table(unsigned int socket_id, uint16_t proto, int counter_id,
	int ht_size) 
{

	int ret;
	char ct_name[64];
	ret = snprintf(ct_name, sizeof(ct_name), "counter_hash_%d_%d",
		proto, counter_id);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(ct_name));	

	int key_len = proto == ETHER_TYPE_IPv4 ? 2 * sizeof(struct in_addr) : 
		2 * sizeof(struct in6_addr);
	
	struct rte_hash_parameters ct_hash_params = { 
		.name = ct_name,
                .entries = ht_size,
                .key_len = key_len,
                .hash_func = rte_jhash,
                .hash_func_init_val = 0,
		.reserved = 0,
		.socket_id = socket_id,
	};
	
	if (proto == ETHER_TYPE_IPv4) {
		/* Create IPv4 counter table. */
		struct rte_hash *ct_table = rte_hash_create(&ct_hash_params);
		if (ct_table == NULL) {
			RTE_LOG(ERR, HASH,"Counter table %d_%d cannot be "
				"created\n", proto, counter_id);
		}
		return ct_table;
	} else if (proto == ETHER_TYPE_IPv6) {
		/* Create IPv6 counter table. */
		struct rte_hash *ct_table = rte_hash_create(&ct_hash_params);
		if (ct_table == NULL) {
			RTE_LOG(ERR, HASH, "Counter table %d_%d cannot be "
				"created\n", proto, counter_id);
		}
		return ct_table;
	}
	RTE_LOG(ERR, HASH, "Unsupported Protocol\n");
	return NULL;
}

void
destroy_counter_table(uint16_t proto, int counter_id)
{
	int ret;
	char ct_name[64];

	ret = snprintf(ct_name, sizeof(ct_name), "counter_hash_%d_%d", 
		proto, counter_id);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(ct_name));

	struct rte_hash *ct_table =  rte_hash_find_existing(ct_name);
	if (ct_table == NULL)
		RTE_LOG(ERR, HASH, "Counter Table does not exist\n");

	rte_hash_free(ct_table);	
}

struct rte_hash *
create_bucket(unsigned int socket_id, uint16_t proto, int bkt_id)
{
	//printf("Socket id = %d, proto = %d, bkt_id = %d\n", socket_id, proto, 
		//bkt_id);
	int ret;
	char bkt_name[64];
	ret = snprintf(bkt_name, sizeof(bkt_name), "Bucket_hash_%d_%d",
		proto, bkt_id);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(bkt_name));	

	int key_len = proto == ETHER_TYPE_IPv4 ? 2 * sizeof(struct in_addr) : 
		2 * sizeof(struct in6_addr);
	
	struct rte_hash_parameters bkt_hash_params = { 
		.name = bkt_name,
                .entries = 2048,
                .key_len = key_len,
                .hash_func = rte_jhash,
                .hash_func_init_val = 0,
		.reserved = 0,
		.socket_id = socket_id,
	};
	
	if (proto == ETHER_TYPE_IPv4) {
		/* Create IPv4 counter table. */
		struct rte_hash *ct_bkt = rte_hash_create(&bkt_hash_params);
		if (ct_bkt == NULL) {
			RTE_LOG(ERR, HASH,"Counter bucket %d_%d cannot be "
				"created\n", proto, bkt_id);
			printf("%d\n", streamlen);
		}
		return ct_bkt;
	} else if (proto == ETHER_TYPE_IPv6) {
		/* Create IPv6 counter table. */
		struct rte_hash *ct_bkt = rte_hash_create(&bkt_hash_params);
		if (ct_bkt == NULL) {
			RTE_LOG(ERR, HASH, "Counter bucket %d_%d cannot be "
				"created\n", proto, bkt_id);
			printf("%d\n", streamlen);
		}
		return ct_bkt;
	}
	RTE_LOG(ERR, HASH, "Unsupported Protocol\n");
	return NULL;
}


static int
increment_counter(unsigned int socket_id, uint16_t proto, 
	struct ip_data **element1)
{
	int ret;
	struct ip_data *element = *element1;
	element->bkt_id++;
	
	mx = max(mx, element->bkt_id);

	if (streamlen == 100000) {
		printf("MAx = %d %u\n", mx, sizeof(struct ip_data));
	}
	//printf("Incrementing counter for src = %u, dst = %u\n", 
		//element->key.k.v4.src.s_addr, element->key.k.v4.dst.s_addr);
	
	struct counter_bucket *cur_bkt = &element->ct_bucket;
	struct counter_bucket *nxt_bkt = list_first_entry(
		&element->ct_bucket.list, struct counter_bucket, list);
	//printf("Curr bkt_id = %d Nxt bkt id = %d\n", cur_bkt->bkt_id, 
		//nxt_bkt->bkt_id);
	
	if (element->bkt_id > 1) {
		/* Min bkt_id > 1. */
		//printf("Key exists\n");		
		if (proto == ETHER_TYPE_IPv4)
			ret = rte_hash_del_key(cur_bkt->bkt.bkt_ip4, 
				&element->key.k.v4);
		else if (proto == ETHER_TYPE_IPv6)
			ret = rte_hash_del_key(cur_bkt->bkt.bkt_ip6, 
				&element->key.k.v6);
		else
			ret = -1;
		if (ret < 0)
			return ret;	
	}
	
	if ((nxt_bkt->bkt_id != 0) && (element->bkt_id == nxt_bkt->bkt_id)) {
		//printf("Bucket exists\n");		
		element->ct_bucket = *nxt_bkt;
		if (proto == ETHER_TYPE_IPv4)
			ret = rte_hash_add_key_data(
				element->ct_bucket.bkt.bkt_ip4, 
				&element->key.k.v4, element);
		else if (proto == ETHER_TYPE_IPv6)
			ret = rte_hash_add_key_data(
				element->ct_bucket.bkt.bkt_ip6, 
				&element->key.k.v6, element);
		else
			ret = -1;
		if (ret < 0)
			return ret;
		
	} else {
		//printf("Bucket doesn't exist\n");
		element->ct_bucket.proto = proto;
		element->ct_bucket.bkt_id = element->bkt_id;
		INIT_LIST_HEAD(&element->ct_bucket.list);

		char bkt_name[64];
		ret = snprintf(bkt_name, sizeof(bkt_name), "Bucket_hash_%d_%d",
			proto, element->bkt_id);
		struct rte_hash *ct_bkt = rte_hash_find_existing(bkt_name);		
			
		if (proto == ETHER_TYPE_IPv4) {
			if (ct_bkt != NULL)
				element->ct_bucket.bkt.bkt_ip4 = ct_bkt;			
			else 
				element->ct_bucket.bkt.bkt_ip4 = create_bucket(
					socket_id, proto, element->bkt_id);
			if (element->ct_bucket.bkt.bkt_ip4 == NULL) 
				return -1;			
			ret = rte_hash_add_key_data(
				element->ct_bucket.bkt.bkt_ip4, 
				&element->key.k.v4, element);		
		} else if (proto == ETHER_TYPE_IPv6) {
			if (ct_bkt != NULL)
				element->ct_bucket.bkt.bkt_ip6 = ct_bkt;			
			else
				element->ct_bucket.bkt.bkt_ip6 = create_bucket(
					socket_id, proto, element->bkt_id);
			if (element->ct_bucket.bkt.bkt_ip6 == NULL) 
				return -1;			
			ret = rte_hash_add_key_data(
				element->ct_bucket.bkt.bkt_ip6, 
				&element->key.k.v6, element);
		} else {
			RTE_LOG(ERR, HASH, "Unsupported protocol\n");
			return -1;
		}		
		list_add(&element->ct_bucket.list, &cur_bkt->list);
		
	}
 
	void *key, *data;
	uint32_t next = 0;
	if (cur_bkt->bkt_id > 1) {
		//printf("Cleaning Up\n");	
		//printf("%d \n",cur_bkt->bkt_id);
		if (proto == ETHER_TYPE_IPv4) {
			struct rte_hash *bkt_ip4 = cur_bkt->bkt.bkt_ip4;
			if (bkt_ip4 != NULL)	
				ret = rte_hash_iterate(bkt_ip4, 
					(const void **)&key, (void **)&data, 
					&next);
		} else if (proto == ETHER_TYPE_IPv6) {
			struct rte_hash *bkt_ip6 = cur_bkt->bkt.bkt_ip6;
			if (bkt_ip6 != NULL)
				ret = rte_hash_iterate(bkt_ip6, 
					(const void **)&key, (void **)&data, 
					&next);
		} else
			ret = -1;
		if (ret == -ENOENT) {
			//printf("Deleting\n");
			list_del(&cur_bkt->list);
			free(cur_bkt);
		}
	}

	return ret;
}

int
space_saving(unsigned int socket_id, uint16_t proto, struct ip_key *key,
	struct rte_hash *ct_table)
{
	
	int ret;
	streamlen++;
	int ht_size = 1024 * 1024;
	/* Check if flow is monitored. */
	struct ip_data chk;
	struct ip_data *element = (struct ip_data *)malloc(
		sizeof(struct ip_data));
	

	if (proto == ETHER_TYPE_IPv4) 
		ret = rte_hash_lookup_data(ct_table, (const void *)&key->k.v4, 
			(void **)&chk);
	else if (proto == ETHER_TYPE_IPv6)
		ret = rte_hash_lookup_data(ct_table, (const void *)&key->k.v6, 
			(void **)&chk);
	else {
		RTE_LOG(ERR, HASH, "Unsupported Protocol!\n");
		return -1;
	}
	if (ret == -EINVAL) {
		RTE_LOG(ERR, HASH, "Invalid Parameters!\n");
		return ret;

	} else if (ret >= 0) {
		/* If flow is monitored, increment its bucket id. */
		increment_counter(socket_id, proto, &chk);
		
	} else if (ret == -ENOENT) {
		/* Flow is not monitored. */
		struct counter_bucket *ct_bkt;
		if (proto == ETHER_TYPE_IPv4)
			ct_bkt = list_first_entry(&bkt_head_ip4, 
				struct counter_bucket, list);
		else if (proto == ETHER_TYPE_IPv6)
			ct_bkt = list_first_entry(&bkt_head_ip6, 
				struct counter_bucket, list);
		else {
			RTE_LOG(ERR, HASH, "Unsupported Protocol!\n");
			return -1;
		}		
		if (streamlen < ht_size) {
			element->err = 0;						
			element->bkt_id = 0;
			element->key = *key;
			element->ct_bucket = *ct_bkt;
		} else {
			struct ip_key key;
			uint32_t next = 0;
			if (proto == ETHER_TYPE_IPv4)
				ret = rte_hash_iterate(ct_bkt->bkt.bkt_ip4,
					(const void **)&key.k.v4, 
					(void **)&element, &next);
			else if (proto == ETHER_TYPE_IPv6)
				ret = rte_hash_iterate(ct_bkt->bkt.bkt_ip6,
					(const void **)&key.k.v6, 
					(void **)&element, &next);
			if (ret == -EINVAL) {
				RTE_LOG(ERR, HASH, "Invalid parameters!\n");
				return ret;
			} else if (ret == -ENOENT) {
				RTE_LOG(ERR, HASH, "Counter bucket empty!\n");
				return ret;
			} else if (ret == 0) {
				element->err = element->bkt_id;
				element->key = key;
			}
		}			
		ret = increment_counter(socket_id, proto, &element);
		if (ret < 0)
			return ret;
		if (proto == ETHER_TYPE_IPv4)
			ret = rte_hash_add_key_data(ct_table, 
				&element->key.k.v4, element);
		else if (proto == ETHER_TYPE_IPv6)
			ret = rte_hash_add_key_data(ct_table, 
				&element->key.k.v6, element);
		if (ret < 0)
			return ret;
	}
	return ret;
}

int SSiterate(struct rte_hash *ct_table, int proto, int threshold)
{
	int ret = 0;

	char ip4_src[INET_ADDRSTRLEN];
	char ip4_dst[INET_ADDRSTRLEN];
	char ip6_src[INET6_ADDRSTRLEN];
	char ip6_dst[INET6_ADDRSTRLEN];
	
	hh_size = 1;
	hh_table = (struct ip_key *)malloc(hh_size*sizeof(struct ip_key));
	
	//printf("Packet Summary\n");

	struct ip_key *key;
	struct ip_data *element;
	uint32_t next = 0;
	ret = rte_hash_iterate(ct_table, (const void **)&key, 
		(void **)&element, &next);
	while(ret >= 0) {
		if (proto == ETHER_TYPE_IPv4) {
			inet_ntop(AF_INET, &(element->key.k.v4.src), ip4_src, 
				INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(element->key.k.v4.dst), ip4_dst,
				INET_ADDRSTRLEN);
			//printf("Src = %s Dst = %s Count = %u Err = %u\n", 
			//ip4_src, ip4_dst, element->bkt_id, element->err);
		} else if (proto == ETHER_TYPE_IPv6) {
			inet_ntop(AF_INET6, &(element->key.k.v6.src), ip6_src, 
				INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(element->key.k.v6.dst), ip6_dst, 
				INET6_ADDRSTRLEN);
			//printf("Src = %s Dst = %s Count = %u Err = %u\n", 
			//ip6_src, ip6_dst, element->bkt_id, element->err);
		} else {
			RTE_LOG(ERR, HASH, "Unknown Protocol\n");
			return -1;
		}
		if (element->bkt_id >= threshold) {
			numhitter++;
			while(hh_size <= numhitter)
				hh_size = hh_size * 2;
			hh_table = (struct ip_key *)realloc(hh_table, 
				hh_size*sizeof(struct ip_key));
			hh_table[numhitter] = element->key;
		}
		ret = rte_hash_iterate(ct_table, (const void **)&key, 
			(void **)&element, &next);	
	}
	int i;
	if (proto == ETHER_TYPE_IPv4) {
		printf("\nNum of IPv4 heavy hitters = %d.\n", numhitter);
	} else if (proto == ETHER_TYPE_IPv6) {
		printf("Num of IPv6 heavy hitters = %d.\n", numhitter);
	}
	for(i = 1; i <= numhitter; i++){
		if (proto == ETHER_TYPE_IPv4) {
			inet_ntop(AF_INET, &(hh_table[i].k.v4.src), ip4_src, 
				INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &(hh_table[i].k.v4.dst), ip4_dst, 
				INET_ADDRSTRLEN);
			printf("Src = %s Dst = %s\n", ip4_src, ip4_dst);
		} else if (proto == ETHER_TYPE_IPv6) {
			inet_ntop(AF_INET6, &(hh_table[i].k.v6.src), ip6_src, 
				INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(hh_table[i].k.v6.dst), ip6_dst, 
				INET6_ADDRSTRLEN);
			printf("Src = %s Dst = %s\n", ip6_src, ip6_dst);
		}
	}
	printf("\n");
	free(hh_table);
	numhitter = 0;
	return ret = 0;
}

int SSEstUpp(struct rte_hash *ct_table, struct ip_key *key)
{
	int ret;
	struct ip_data element;
	
	ret = rte_hash_lookup_data(ct_table, (void *)&key, (void **)&element);
	if (ret < 0)
		return 0;
	return element.bkt_id; 
}

int SSEstLow(struct rte_hash *ct_table, struct ip_key *key)
{
	int ret;
	struct ip_data element;

	ret = rte_hash_lookup_data(ct_table, (void *)&key, (void **)&element);
	if (ret < 0)
		return 0;
	return (element.bkt_id - element.err);
}
