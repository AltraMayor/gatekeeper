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

#include <math.h>

#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include <rte_prefetch.h>

#include "gatekeeper_main.h"
#include "gatekeeper_hash.h"

#define HS_HASH_MAX_NUM_ENTRIES	((uint32_t)1 << 31)

static inline bool
is_in_use(const struct hs_hash_bucket *bucket)
{
	return bucket->user_idx != HS_HASH_MISS;
}

static inline bool
is_neighborhood_full(const struct hs_hash *h,
	const struct hs_hash_bucket *bucket)
{
	return (bucket->hh_nbh & h->neighborhood_mask) == h->neighborhood_mask;
}

static inline uint32_t
bucket_difference(const struct hs_hash *h, uint32_t bucket1, uint32_t bucket2)
{
	if (likely(bucket1 <= bucket2))
		return bucket2 - bucket1;
	return bucket2 + (h->num_buckets - bucket1);
}

static inline uint32_t
cycle_buckets(const struct hs_hash *h, uint32_t hash)
{
	return hash & (h->num_buckets - 1);
}

static inline uint32_t
hs_jhash(const void *key, uint32_t key_len, uint32_t init_val,
	__attribute__((unused)) const void *data)
{
	return rte_jhash(key, key_len, init_val);
}

static inline uint32_t
hs_hash_crc(const void *key, uint32_t key_len, uint32_t init_val,
	__attribute__((unused)) const void *data)
{
	return rte_hash_crc(key, key_len, init_val);
}

static inline hs_hash_function
default_hash_func(void)
{
	hs_hash_function default_hash_func = hs_jhash;
#if defined(RTE_ARCH_X86)
	default_hash_func = hs_hash_crc;
#elif defined(RTE_ARCH_ARM64)
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_CRC32))
		default_hash_func = hs_hash_crc;
#endif
	return default_hash_func;
}

static void
init_buckets(struct hs_hash_bucket *buckets, uint32_t num_buckets)
{
	uint32_t i;
	for (i = 0; i < num_buckets; i++) {
		buckets[i].hh_nbh = 0;
		buckets[i].user_idx = HS_HASH_MISS;
	}
}

int
hs_hash_create(struct hs_hash *h, const struct hs_hash_parameters *params)
{
	struct hs_hash_bucket *buckets;
	uint32_t num_buckets, scaled_num_entries;
	char hash_name[128];
	int ret;

	RTE_BUILD_BUG_ON(HS_HASH_MISS <= HS_HASH_MAX_NUM_ENTRIES);

	if (unlikely(h == NULL)) {
		G_LOG(ERR, "%s(): hash data structure not allocated\n", __func__);
		return -EINVAL;
	}

	if (unlikely(params == NULL)) {
		G_LOG(ERR, "%s(): no parameters\n", __func__);
		return -EINVAL;
	}

	if (unlikely(params->name == NULL)) {
		G_LOG(ERR, "%s(): must provide name in struct hs_hash_parameters\n",
			__func__);
		return -EINVAL;
	}

	if (unlikely(params->key_len == 0)) {
		G_LOG(ERR, "%s(%s): given key length 0\n",
			__func__, params->name);
		return -EINVAL;
	}

	if (unlikely(params->key_cmp_fn == NULL)) {
		G_LOG(ERR, "%s(%s): must be given a key_cmp_fn in struct hs_hash_parameters\n",
			__func__, params->name);
		return -EINVAL;
	}

	if (unlikely(params->key_addr_fn == NULL)) {
		G_LOG(ERR, "%s(%s): must be given a key_addr_fn in struct hs_hash_parameters\n",
			__func__, params->name);
		return -EINVAL;
	}

	if (unlikely(params->num_entries == 0)) {
		G_LOG(ERR, "%s(%s): must be given a positive value for the number of entries in struct hs_hash_parameters\n",
			__func__, params->name);
		return -EINVAL;
	}

	if (unlikely(params->scale_num_bucket <= 0)) {
		G_LOG(ERR, "%s(%s): must be given a positive value for the number of buckets scale factor in struct hs_hash_parameters\n",
			__func__, params->name);
		return -EINVAL;
	}

	scaled_num_entries = round(params->num_entries *
		params->scale_num_bucket);
	if (unlikely(scaled_num_entries == 0)) {
		G_LOG(ERR, "%s(%s): number of entries (%u*%f=%u) must be > 0 in struct hs_hash_parameters\n",
			__func__, params->name, params->num_entries,
			params->scale_num_bucket, scaled_num_entries);
		return -EINVAL;

	}
	if (unlikely(scaled_num_entries > HS_HASH_MAX_NUM_ENTRIES)) {
		/*
		 * If we allow @params->num_entries to be any
		 * greater, rte_align32pow2() could return 0.
		 */
		G_LOG(ERR, "%s(%s): number of entries (%u*%f=%u) must be <= max entries (%u) in struct hs_hash_parameters\n",
			__func__, params->name, params->num_entries,
			params->scale_num_bucket, scaled_num_entries,
			HS_HASH_MAX_NUM_ENTRIES);
		return -EINVAL;
	}

	/*
	 * Making the number of buckets a power of two makes
	 * the bucket mask of struct hs_hash possible.
	 *
	 * However, we allow the entries array to be shorter
	 * than the number of buckets, so that we can utilize
	 * additional buckets without having to bump the number
	 * of entries up to the next power of 2.
	 */
	num_buckets = rte_align32pow2(RTE_MAX(8, scaled_num_entries));

	ret = snprintf(hash_name, sizeof(hash_name), "HSHT_buckets_%s",
		params->name);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(hash_name));
	/*
	 * Zeroed allocation is not needed here, since the initial
	 * state of the buckets is to have a non-zero index HS_HASH_MISS.
	 */
	buckets = rte_malloc_socket(hash_name,
		num_buckets * sizeof(*buckets),
		RTE_CACHE_LINE_SIZE, params->socket_id);
	if (unlikely(buckets == NULL)) {
		G_LOG(ERR, "%s(%s): buckets memory allocation failed\n",
			__func__, params->name);
		return -ENOMEM;
	}

	ret = snprintf(hash_name, sizeof(hash_name), "HSHT_qid_%s",
		params->name);
	RTE_VERIFY(ret > 0 && ret < (int)sizeof(hash_name));
	ret = qid_init(&h->entry_qid, params->num_entries, hash_name,
		params->socket_id);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(%s): failed to create QID for managing hash table entries (errno=%i): %s\n",
			__func__, params->name, -ret, strerror(-ret));
		goto free_buckets;
	}

	h->buckets = buckets;
	h->num_buckets = num_buckets;
	init_buckets(h->buckets, h->num_buckets);

	h->max_probes = RTE_MIN(params->max_probes, num_buckets);
	h->neighborhood_size = rte_log2_u32(num_buckets);
	h->neighborhood_mask = num_buckets - 1;
	h->high_hash_mask = ~h->neighborhood_mask;

	h->hash_func = (params->hash_func == NULL)
		? default_hash_func()
		: params->hash_func;
	h->key_len = params->key_len;
	h->hash_func_init_val = params->hash_func_init_val;
	h->hash_func_data = params->hash_func_data;
	h->key_cmp_fn = params->key_cmp_fn;
	h->key_cmp_fn_data = params->key_cmp_fn_data;
	h->key_addr_fn = params->key_addr_fn;
	h->key_addr_fn_data = params->key_addr_fn_data;

	return 0;

free_buckets:
	rte_free(buckets);
	return ret;
}

void
hs_hash_free(struct hs_hash *h)
{
	if (unlikely(h == NULL))
		return;

	h->key_addr_fn_data = NULL;
	h->key_addr_fn = NULL;
	h->key_cmp_fn_data = NULL;
	h->key_cmp_fn = NULL;
	h->hash_func_data = NULL;
	h->hash_func_init_val = 0;
	h->key_len = 0;
	h->hash_func = NULL;

	h->high_hash_mask = 0;
	h->neighborhood_mask = 0;
	h->neighborhood_size = 0;
	h->max_probes = 0;

	qid_free(&h->entry_qid);

	h->num_buckets = 0;
	rte_free(h->buckets);
	h->buckets = NULL;
}

/*
 * Finds the index of an empty bucket and stores it in @p_empty_idx
 * and returns 0 on success. If there is no empty bucket available,
 * returns -ENOENT.
 */
static int
find_empty_bucket(const struct hs_hash *h, uint32_t start_idx,
	uint32_t *p_empty_idx)
{
	uint32_t i;
	for (i = 0; i < h->max_probes; i++) {
		uint32_t idx = cycle_buckets(h, start_idx + i);
		if (!is_in_use(&h->buckets[idx])) {
			*p_empty_idx = idx;
			return 0;
		}
	}
	return -ENOENT;
}

static inline void
toggle_neighbor(struct hs_hash *h, uint32_t bucket_idx, uint32_t neigh_distance)
{
	if (unlikely(neigh_distance >= h->neighborhood_size)) {
		G_LOG(CRIT, "%s(): bug: neigh_distance=%u >= neighborhood_size=%u\n",
			__func__, neigh_distance, h->neighborhood_size);
		return;
	}
	h->buckets[bucket_idx].hh_nbh ^= (uint32_t)1 << neigh_distance;
}

/*
 * Swaps an entry in a neighborhood into an empty slot.
 *
 * @neigh_idx is the index of the neighborhood in question.
 * @empty_idx is the index of the empty slot in the neighborhood.
 * @empty_neigh_bit is the bit that represents @empty_idx in the neighborhood.
 * @to_swap_idx is the index of the entry to be swapped.
 * @to_swap_neigh_bit is the bit that represents @to_swap_idx in the
 * neighborhood.
 */
static void
swap_value_into_empty_bucket(struct hs_hash *h, uint32_t neigh_idx,
	uint32_t empty_idx, uint32_t empty_neigh_bit,
	uint32_t to_swap_idx, uint32_t to_swap_neigh_bit)
{
	h->buckets[empty_idx].hh_nbh &= h->neighborhood_mask;
	h->buckets[empty_idx].hh_nbh |= h->buckets[to_swap_idx].hh_nbh &
		h->high_hash_mask;
	h->buckets[empty_idx].user_idx = h->buckets[to_swap_idx].user_idx;
	/* Add the previously empty bucket to this neighborhood. */
	toggle_neighbor(h, neigh_idx, empty_neigh_bit);

	h->buckets[to_swap_idx].hh_nbh &= h->neighborhood_mask;
	h->buckets[to_swap_idx].user_idx = HS_HASH_MISS;
	/* Remove the previously used bucket from this neighborhood. */
	toggle_neighbor(h, neigh_idx, to_swap_neigh_bit);
}

static bool
swap_empty_bucket_closer(struct hs_hash *h, uint32_t *p_empty_idx)
{
	uint8_t i;
	/*
	 * Can only let i be less than h->neighborhood_size - 1, since the
	 * entry at exactly h->neighborhood_size - 1 is the empty one.
	 */
	for (i = 0; i < h->neighborhood_size - 1; i++) {
		/*
		 * Start looking a neighborhood "back" from @empty_idx,
		 * which might cause the index to temporarily go negative,
		 * hence the assignment to @tmp_64idx.
		 *
		 * In the cases where the index becomes negative, we wrap
		 * back around to the *end* of the buckets array by adding
		 * h->num_buckets.
		 *
		 * Either way, ultimately @tmp_64idx holds a proper 32-bit
		 * index.
		 */
		int64_t tmp_64idx = (int64_t)*p_empty_idx -
			h->neighborhood_size + 1 + i;
		if (unlikely(tmp_64idx < 0))
			tmp_64idx += h->num_buckets;
		uint32_t current_idx = cycle_buckets(h, tmp_64idx);
		uint32_t neighborhood = h->buckets[current_idx].hh_nbh &
			h->neighborhood_mask;
		uint32_t empty_distance, next_bit, swap_idx;

		/*
		 * There is no need to test if
		 * is_in_use(&h->buckets[current_idx]) is false because
		 * hs_hash_add_key_with_hash(), the only caller, calls
		 * this function after testing all buckets are in use.
		 */

		if (neighborhood == 0)
			continue;

		empty_distance = h->neighborhood_size - 1 - i;
		next_bit = rte_bsf32(neighborhood);
		if (unlikely(next_bit >= empty_distance))
			continue;
		swap_idx = cycle_buckets(h, current_idx + next_bit);

		swap_value_into_empty_bucket(h, current_idx,
			*p_empty_idx, empty_distance,
			swap_idx, next_bit);

		*p_empty_idx = swap_idx;
		return true;
	}

	/* Could not swap an empty bucket closer. */
	return false;
}

static inline bool
hashes_equal(const struct hs_hash *h, uint32_t key1_hash,
	uint32_t key2_hash_idx)
{
	return !((h->buckets[key2_hash_idx].hh_nbh ^ key1_hash) &
		h->high_hash_mask);
}

static inline bool
keys_equal(const struct hs_hash *h, const void *key1, uint32_t key2_hash_idx)
{
	return h->key_cmp_fn(key1,
		h->key_addr_fn(h->buckets[key2_hash_idx].user_idx,
			h->key_addr_fn_data),
		h->key_len,
		h->key_cmp_fn_data) == 0;
}

/*
 * Returns whether @key1 is equal to the existing key
 * represented by the bucket at index @key2_hash_idx.
 */
static bool
hashes_and_keys_equal(const struct hs_hash *h, const void *key1,
	uint32_t key1_hash, uint32_t key2_hash_idx)
{
	return hashes_equal(h, key1_hash, key2_hash_idx) &&
		likely(keys_equal(h, key1, key2_hash_idx));
}

static int
find_in_neighborhood(const struct hs_hash *h, const void *key, uint32_t hash,
	uint32_t hash_idx, uint32_t *p_val_idx)
{
	uint32_t neighborhood =
		h->buckets[hash_idx].hh_nbh & h->neighborhood_mask;

	while (neighborhood != 0) {
		uint32_t next_bit = rte_bsf32(neighborhood);
		hash_idx = cycle_buckets(h, hash_idx + next_bit);
		neighborhood >>= next_bit;
		neighborhood ^= 1;

		if (hashes_and_keys_equal(h, key, hash, hash_idx)) {
			*p_val_idx = hash_idx;
			return 0;
		}
	}

	return -ENOENT;
}

int
hs_hash_add_key_with_hash(struct hs_hash *h, const void *key, uint32_t hash,
	uint32_t *p_user_idx)
{
	uint32_t hash_idx, val_idx, new_user_idx, empty_idx;
	int ret, ret2;

	if (unlikely(h == NULL || key == NULL || p_user_idx == NULL))
		return -EINVAL;

	hash_idx = cycle_buckets(h, hash);

	ret = find_in_neighborhood(h, key, hash, hash_idx, &val_idx);
	if (unlikely(ret == 0)) {
		/*
		 * Prioritize returning the fact that the key
		 * already exists, since this gives the client
		 * a better opportunity to act on it than -ENOSPC.
		 */
		*p_user_idx = h->buckets[val_idx].user_idx;
		return -EEXIST;
	}

	if (unlikely(is_neighborhood_full(h, &h->buckets[hash_idx])))
		return -ENOSPC;

	ret = qid_pop(&h->entry_qid, &new_user_idx);
	if (unlikely(ret < 0)) {
		/* Likely no more room in the client's entries array. */
		return ret;
	}

	ret = find_empty_bucket(h, hash_idx, &empty_idx);
	if (unlikely(ret < 0)) {
		/* No free buckets within range. */
		goto push_qid;
	}

	do {
		uint32_t bucket_diff = bucket_difference(h,
			hash_idx, empty_idx);
		if (likely(bucket_diff < h->neighborhood_size)) {
			h->buckets[empty_idx].hh_nbh &= h->neighborhood_mask;
			h->buckets[empty_idx].hh_nbh |= hash &
				h->high_hash_mask;
			h->buckets[empty_idx].user_idx = new_user_idx;
			toggle_neighbor(h, hash_idx, bucket_diff);
			*p_user_idx = new_user_idx;
			return 0;
		}

	/*
	 * Swap an empty bucket closer to try to move it into range
	 * of the neighborhood.
	 *
	 * Note that it's not possible for the function to set
	 * @empty_idx to be before @hash_idx because above we make
	 * sure that the difference between the buckets is at least
	 * a neighborhood. Therefore, since swap_empty_bucket_closer()
	 * looks at most a neighborhood before the empty index, it
	 * can't find an empty index that comes before @hash_idx.
	 */
	} while (swap_empty_bucket_closer(h, &empty_idx));

	/* Couldn't swap an empty bucket close enough. */
	ret = -ENOSPC;
push_qid:
	ret2 = qid_push(&h->entry_qid, new_user_idx);
	if (unlikely(ret2 < 0)) {
		G_LOG(ERR, "%s(): failed to push QID %u (errno=%i): %s\n",
			__func__, new_user_idx,
			-ret2, strerror(-ret2));
	}
	return ret;
}

/*
 * @nbh_idx is the index of bucket where the value was hashed to.
 * @val_idx is the index of the bucket where the value is.
 */
static void
delete_from_neighborhood(struct hs_hash *h, uint32_t nbh_idx, uint32_t val_idx)
{
	int ret = qid_push(&h->entry_qid, h->buckets[val_idx].user_idx);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(): failed to push QID %u (errno=%i): %s\n",
			__func__, h->buckets[val_idx].user_idx,
			-ret, strerror(-ret));
	}
	h->buckets[val_idx].user_idx = HS_HASH_MISS;
	h->buckets[val_idx].hh_nbh &= h->neighborhood_mask;
	toggle_neighbor(h, nbh_idx, bucket_difference(h, nbh_idx, val_idx));
}

int
hs_hash_del_key_with_hash(struct hs_hash *h, const void *key, uint32_t hash,
	uint32_t *p_user_idx)
{
	uint32_t hash_idx, val_idx, neighborhood;
	int ret;

	if (unlikely(h == NULL || key == NULL || p_user_idx == NULL))
		return -EINVAL;

	hash_idx = cycle_buckets(h, hash);
	ret = find_in_neighborhood(h, key, hash, hash_idx, &val_idx);
	if (unlikely(ret < 0))
		return ret;
	*p_user_idx = h->buckets[val_idx].user_idx;

	delete_from_neighborhood(h, hash_idx, val_idx);

	neighborhood = h->buckets[hash_idx].hh_nbh & h->neighborhood_mask;
	if (likely(neighborhood != 0)) {
		/*
		 * Swap the farthest bucket of the neighborhood
		 * to the empty spot to improve locality.
		 */
		uint32_t farthest_bit = rte_fls_u32(neighborhood) - 1;
		uint32_t val_bit = bucket_difference(h, hash_idx, val_idx);
		if (likely(farthest_bit > val_bit)) {
			swap_value_into_empty_bucket(h, hash_idx,
				val_idx, val_bit,
				cycle_buckets(h, hash_idx + farthest_bit),
				farthest_bit);
		}
	}

	return 0;
}

int
hs_hash_lookup_with_hash(const struct hs_hash *h,
	const void *key, uint32_t hash, uint32_t *p_user_idx)
{
	uint32_t hash_idx, val_idx;
	int ret;

	if (unlikely(h == NULL || key == NULL || p_user_idx == NULL))
		return -EINVAL;

	hash_idx = cycle_buckets(h, hash);
	ret = find_in_neighborhood(h, key, hash, hash_idx, &val_idx);
	if (likely(ret == 0))
		*p_user_idx = h->buckets[val_idx].user_idx;
	return ret;
}

/*
 * Bulk lookup is implemented using the G-Opt technique. The logic
 * is basically an unrolled version of the loop in find_in_neighborhood().
 *
 * For details on the G-Opt technique, see at least Section 3.2 of
 * the paper Raising the Bar for Using GPUs in Software Packet Processing
 * by Anuj Kalia, Dong Zhou, Michael Kaminsky, and David G. Andersen.
 * published in 12th USENIX Symposium on Networked Systems Design and
 * Implementation (aka NSDI 2015).
 */

#define G_SW()				\
	do {				\
		i = (i + 1) % n;	\
		goto *g_labels[i];	\
	} while (0)

/* Prefetch, Save label, and Switch lookup. */
#define G_PSS(addr, label) 		\
	do {				\
		rte_prefetch0(addr);	\
		g_labels[i] = &&label;	\
		G_SW();			\
	} while (0)

static inline void *
bucket_cache_line(const struct hs_hash *h, uint32_t idx)
{
	return (void *)((uintptr_t)&h->buckets[idx] &
		(~((uintptr_t)RTE_CACHE_LINE_MASK)));
}

int
hs_hash_lookup_with_hash_bulk(const struct hs_hash *h, const void **keys,
	const uint32_t *hashes, uint32_t n, uint32_t *user_indexes)
{
	/* Lookup state. */
	uint32_t entry_idx[n];
	void *prv_cache_line[n];
	uint32_t neighborhoods[n];
	uint32_t next_bit;
	void *cache_line;

	/* G-Opt state. */
	void *g_labels[n];
	uint32_t i, g_count;

	if (unlikely(n == 0))
		return 0;

	if (unlikely(h == NULL || keys == NULL || hashes == NULL ||
			user_indexes == NULL)) {
		return -EINVAL;
	}

	for (i = 0; i < n; i++)
		g_labels[i] = &&g_label_0;
	i = 0;
	g_count = 0;

g_label_0:
	entry_idx[i] = cycle_buckets(h, hashes[i]);
	prv_cache_line[i] = bucket_cache_line(h, entry_idx[i]);
	/* Prefetch the cache line for the initial bucket. */
	G_PSS(prv_cache_line[i], g_label_1);

g_label_1:
	/* This only needs to be initialized once for every index. */
       	neighborhoods[i] =
		h->buckets[entry_idx[i]].hh_nbh & h->neighborhood_mask;

	/* Loop over the entries of the neighborhood begins here. */
g_label_2:
	if (neighborhoods[i] == 0) {
		/*
		 * Either there were no entries in this neighborhood to begin
		 * with, or we have checked all of the entries in the
		 * neighborhood and their hashes or keys didn't match.
		 */
		user_indexes[i] = HS_HASH_MISS;
		goto g_done;
	}

	/* Find a non-empty entry in this neighborhood. */
	next_bit = rte_bsf32(neighborhoods[i]);
	entry_idx[i] = cycle_buckets(h, entry_idx[i] + next_bit);
	cache_line = bucket_cache_line(h, entry_idx[i]);
	neighborhoods[i] >>= next_bit;
	neighborhoods[i] ^= 1;

	if (unlikely(prv_cache_line[i] != cache_line)) {
		/*
		 * This bucket is not in cache. We can use unlikely
		 * here because we set up the hash for 100% occupancy,
		 * leading to entries being on the same cache line
		 * most of the time.
		 */
		prv_cache_line[i] = cache_line;
		G_PSS(cache_line, g_label_3);
	}

g_label_3:
	if (!hashes_equal(h, hashes[i], entry_idx[i])) {
		/* Go try to find another entry in the neighborhood. */
		goto g_label_2;
	}

	/* Prefetch the key of the entry to compare keys. */
	user_indexes[i] = h->buckets[entry_idx[i]].user_idx;
	G_PSS(h->key_addr_fn(user_indexes[i], h->key_addr_fn_data), g_label_4);

g_label_4:
	if (unlikely(!keys_equal(h, keys[i], entry_idx[i]))) {
		/*
		 * Go try to find another entry in the neighborhood.
		 * Unlikely because if the hashes were equal, then
		 * it's likely that the keys are also equal.
		 */
		goto g_label_2;
	}

	goto g_done;

g_skip:
	G_SW();
g_done:
	g_count++;
	g_labels[i] = &&g_skip;

	if (likely(g_count < n))
		G_SW();

	if (unlikely(g_count > n)) {
		G_LOG(CRIT, "%s(): bug: g_count=%u > n=%u\n",
			__func__, g_count, n);
		return -1;
	}

	return 0;
}

int
hs_hash_iterate(const struct hs_hash *h, uint32_t *next, uint32_t *p_user_idx)
{
	uint32_t i;
	int ret;

	if (unlikely(p_user_idx == NULL)) {
		/*
		 * Since we can't populate @p_user_idx with HS_HASH_MISS,
		 * the only thing to do is return the error.
		 */
		return -EINVAL;
	}

	if (unlikely(h == NULL || next == NULL)) {
		ret = -EINVAL;
		goto no_entry;
	}

	if (unlikely(*next >= h->num_buckets)) {
		ret = -ENOENT;
		goto no_entry;
	}

	i = *next;
	while (likely(!is_in_use(&h->buckets[i]))) {
		i++;
		if (unlikely(i >= h->num_buckets)) {
			ret = -ENOENT;
			*next = i;
			goto no_entry;
		}
	}

	*p_user_idx = h->buckets[i].user_idx;
	*next = i + 1;
	return 0;

no_entry:
	*p_user_idx = HS_HASH_MISS;
	return ret;
}

void
hs_hash_prefetch_bucket_non_temporal(const struct hs_hash *h,
	uint32_t hash)
{
	rte_prefetch_non_temporal(&h->buckets[cycle_buckets(h, hash)]);
}
