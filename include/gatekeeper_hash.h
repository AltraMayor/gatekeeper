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

/*
 * The struct hs_hash_bucket defined below is so small (i.e., 64 bits) that
 * increasing the number of buckets for the same number of entries in order
 * to allocate 100% of the entries is more effective than implementing anything
 * more sophisticated. For example, the paper *Hopscotch Hashing* by
 * Maurice Herlihy, Nir Shavit, and Moran Tzafrir ("the Hopscotch paper")
 * implemented neighborhoods as a linked list instead of as a bitmap (as here)
 * to reach almost 100% occupancy of the buckets.
 *
 * Any other implementation is very likely going to add at least 32 bits to
 * struct hs_hash_bucket due to memory alignment. Those extra 32 bits mean a
 * 50% growth in memory consumption for the same number of buckets. This 50%
 * increase in memory consumption means that our version of Hopscotch can have
 * 50% more buckets for the same amount of memory.
 *
 * By increasing the number of buckets by only 25% relative to the number of
 * entries, and having an occupancy of only 4/5 = 80% of the buckets, we can
 * allocate 100% (i.e., 1.25 * 4/5 = 1) of the entries.
 *
 * A typical flow table of a GK instance has at least 250M entries. This means
 * that there are at least ceiling(log_2(250M)) = 28 bits to track
 * neighborhoods. Using Lemma 6 of the Hopscotch paper, and assuming that all
 * 28 entries belong to the same neighborhood (the worst case), the expected
 * occupancy of the buckets is 1 - 1 / (sqrt(2 * 28 - 1) > 86.5% which is
 * safely greater than 80%.
 *
 * An upper bound for the occupancy of the buckets is to be obtained by setting
 * field @max_probes of struct hs_hash equal to 80 (i.e., 10 cache lines of 64
 * bytes) and assuming that all those buckets can be allocated. By Lemma 6
 * again, the occupancy of the buckets is 1 - 1 / (sqrt(2 * 80 - 1) > 92%.
 *
 * Since hs_hash_create() aligns the number of buckets to the next power of 2,
 * the number of buckets can be double the number of entries. In this extreme
 * case -- namely, 50% occupancy of the buckets -- not only is 100% allocation
 * of the entries virtually guaranteed (i.e., 2 * 0.5 = 1), but each
 * neighborhood has at most 3 entries; according to Lemma 6 and assuming all
 * entries belong to the same neighborhood (1 + (1/(1 - 50%))^2)/2 = 2.5.
 * Therefore, even the smallest hash table with 8 entries (see hs_hash_create())
 * has enough bits (i.e., 3 bits) to track all entries in a neighborhood.
 * Moreover, having at most 3 entries per neighborhood implies that most
 * neighborhoods are placed in a single cache line; the exception happens when
 * a neighborhood falls between cache lines.
 *
 * As a reference for future changes to this library, it's worth noticing that
 * one can free the most significant bit of the field @idx by removing the most
 * significant bit from HS_HASH_MISS and adjusting the code to free the bit.
 * This is possible because the largest index is (HS_HASH_MAX_NUM_ENTRIES - 1).
 */
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

	/* Factor by which to scale the number of buckets. */
	double             scale_num_bucket;

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
