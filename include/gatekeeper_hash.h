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

#ifndef _GATEKEEPER_HASH_H_
#define _GATEKEEPER_HASH_H_

#include <stdint.h>

#include "gatekeeper_qid.h"

#define	HS_HASH_MISS	((uint32_t)~0)

/*
 * Format of callback function for comparing keys.
 *
 * In order to avoid keeping track of keys inside of the hash table
 * itself, the caller must provide a function that compares two keys.
 */
typedef int (*hs_hash_key_cmp_t)(const void *key1, const void *key2,
	size_t key_len, const void *data);

/*
 * Format of callback function for getting key addresses.
 *
 * While it is not required, the key should be the first field of the
 * struct that holds the value of the hash table. The reason for this
 * recommendation is that the memory prefetch is done on the key, so
 * if the key is the first field, the bytes after the key that complete
 * the cache line are also prefetched.
 *
 * This helps perform prefetching when doing bulk lookups.
 */
typedef const void *(*hs_hash_key_addr_t)(uint32_t idx, const void *data);

/* Type of function that can be used for calculating the hash value. */
typedef uint32_t (*hs_hash_function)(const void *key, uint32_t key_len,
	uint32_t init_val, const void *data);

struct hs_hash_bucket {
	/* High bits of the hash and neighborhood. */
	uint32_t hh_nbh;

	/* The index of this bucket in the entries array. */
	uint32_t idx;
};

struct hs_hash {
	/* Hopscotch hash buckets. */
	struct hs_hash_bucket *buckets;

	/* Number of buckets in @buckets array. */
	uint32_t              num_buckets;

	/* Maximum number of neighborhoods to probe to find an empty bucket. */
	uint32_t              max_probes;

	/*
	 * The size of the neighborhood portion of the field
	 * @hh_nbh of struct hs_hash_bucket.
	 */
	uint8_t               neighborhood_size;

	/*
	 * The mask for the neighborhood portion of
	 * the field @hh_nbh of struct hs_hash_bucket.
	 */
	uint32_t              neighborhood_mask;

	/*
	 * The mask for the high bits of the hash portion of
	 * the field @hh_nbh of struct hs_hash_bucket.
	 */
	uint32_t              high_hash_mask;

	/* IDs for the client's array of entries. */
	struct qid            entry_qid;

	/* Hash function. */
	hs_hash_function      hash_func;

	/* Length of hash key. */
	uint32_t              key_len;

	/* Initial value used by @hash_func. */
	uint32_t              hash_func_init_val;

	/* User-defined data for @hash_func. */
	void                  *hash_func_data;

	/* Function used to compare keys. */
	hs_hash_key_cmp_t     key_cmp_fn;

	/* Data to be passed to @key_cmp_fn. */
	void                  *key_cmp_fn_data;

	/* Function used to compare keys. */
	hs_hash_key_addr_t    key_addr_fn;

	/* Data to be passed to @key_addr_fn. */
	void                  *key_addr_fn_data;
};

struct hs_hash_parameters {
	/* Name of the hash. */
	const char         *name;

	/* Length of client's array of entries. */
	uint32_t           num_entries;

	/* Maximum number of probes for an empty bucket. */
	uint32_t           max_probes;

	/* NUMA socket ID for memory. */
	int                socket_id;

	/* Length of hash key. */
	uint32_t           key_len;

	/* Hash function. */
	hs_hash_function   hash_func;

	/* Initial value used by @hash_func. */
	uint32_t           hash_func_init_val;

	/* User-defined data for @hash_func. */
	void               *hash_func_data;

	/* Function used to compare keys. */
	hs_hash_key_cmp_t  key_cmp_fn;

	/* Data to be passed to @key_cmp_fn. */
	void               *key_cmp_fn_data;

	/* Function used to compare keys. */
	hs_hash_key_addr_t key_addr_fn;

	/* Data to be passed to @key_addr_fn. */
	void               *key_addr_fn_data;
};

int hs_hash_create(struct hs_hash *h, const struct hs_hash_parameters *params);

void hs_hash_free(struct hs_hash *h);

int hs_hash_add_key_with_hash(struct hs_hash *h,
	const void *key, uint32_t hash, uint32_t *p_val_idx);

int hs_hash_del_key_with_hash(struct hs_hash *h,
	const void *key, uint32_t hash, uint32_t *p_val_idx);

static inline uint32_t
hs_hash_hash(const struct hs_hash *h, const void *key)
{
	return h->hash_func(key, h->key_len, h->hash_func_init_val,
		h->hash_func_data);
}

int hs_hash_lookup_with_hash(const struct hs_hash *h,
	const void *key, uint32_t hash, uint32_t *p_idx);

int hs_hash_iterate(const struct hs_hash *h, uint32_t *next, uint32_t *p_idx);

int hs_hash_lookup_with_hash_bulk(const struct hs_hash *h,
	const void **keys, const uint32_t *hashes, uint32_t n,
	uint32_t *indexes);

void hs_hash_prefetch_bucket_non_temporal(const struct hs_hash *h,
	uint32_t hash);

#endif /* _GATEKEEPER_HASH_H_ */
