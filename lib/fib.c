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

#include <rte_malloc.h>

#include "gatekeeper_main.h"
#include "gatekeeper_fib.h"

static inline void
write_atomics(rte_atomic32_t *array, uint32_t first, uint32_t last, int val)
{
	uint32_t i;
	for (i = first; i <= last; i++)
		rte_atomic32_set(&array[i], val);
}

int
fib_create(struct fib_head *fib, const char *name, int socket_id,
	uint8_t max_length, uint32_t max_rules, uint32_t num_tbl8s)
{
	char rib_name[256], tbl8s_name[256], pool_name[256];
	int ret;
	uint32_t i;

	/*
	 * Check input.
	 */

	if (unlikely(max_length % 8 != 0)) {
		G_LOG(ERR, "%s(): max_length=%u is not a multiple of 8\n",
			__func__, max_length);
		return -EINVAL;
	}

	/*
	 * Having max_length >= 32 guarantees that there's at least one level
	 * of tbl8s. This assumption simplifies the code that implements
	 * fib_add() and fib_del().
	 */
	if (unlikely(max_length < 32 || RIB_MAX_ADDRESS_LENGTH < max_length)) {
		G_LOG(ERR, "%s(): max_length=%u must be in [32, %u]\n",
			__func__, max_length, RIB_MAX_ADDRESS_LENGTH);
		return -EINVAL;
	}

	if (unlikely(max_rules == 0)) {
		G_LOG(ERR, "%s(): max_rules=%u must be greater than zero\n",
			__func__, max_rules);
		return -EINVAL;
	}

	if (unlikely(num_tbl8s == 0 || num_tbl8s >= FIB_TBL8_FREE_INDEX)) {
		G_LOG(ERR, "%s(): num_tbl8s=%u must be in [0, %u)\n",
			__func__, num_tbl8s, FIB_TBL8_FREE_INDEX);
		return -EINVAL;
	}

	ret = snprintf(rib_name, sizeof(rib_name), "%s_RIB", name);
	if (unlikely(ret <= 0 || ret >= (int)sizeof(rib_name))) {
		G_LOG(ERR, "%s(rib_name): name=`%s' is too long\n",
			__func__, name);
		return -EINVAL;
	}

	ret = snprintf(tbl8s_name, sizeof(tbl8s_name), "%s_TBL8s", name);
	if (unlikely(ret <= 0 || ret >= (int)sizeof(tbl8s_name))) {
		G_LOG(ERR, "%s(tbl8s_name): name=`%s' is too long\n",
			__func__, name);
		return -EINVAL;
	}

	ret = snprintf(pool_name, sizeof(pool_name), "%s_TBL8s_pool", name);
	if (unlikely(ret <= 0 || ret >= (int)sizeof(pool_name))) {
		G_LOG(ERR, "%s(pool_name): name=`%s' is too long\n",
			__func__, name);
		return -EINVAL;
	}

	/*
	 * Initialize internal RIB.
	 */

	ret = rib_create(&fib->rib, rib_name, socket_id, max_length, max_rules);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(): failed to create RIB %s\n",
			__func__, rib_name);
		goto out;
	}
	fib->addr_len_bytes = max_length / 8;

	/*
	 * Initialize 8-bit tables.
	 */

	fib->tbl8s = rte_malloc_socket(tbl8s_name,
		sizeof(*fib->tbl8s) * num_tbl8s, 0, socket_id);
	if (unlikely(fib->tbl8s == NULL)) {
		ret = -ENOMEM;
		goto free_rib;
	}

	fib->num_tbl8s = num_tbl8s;
	for (i = 0; i < num_tbl8s; i++) {
		write_atomics(fib->tbl8s[i].nh,
			0, RTE_DIM(fib->tbl8s[i].nh) - 1, FIB_NO_NH);
	}

	/*
	 * Initialize pool of 8-bit tables.
	 */

	fib->tbl8_pool = rte_malloc_socket(pool_name,
		sizeof(*fib->tbl8_pool) * num_tbl8s, 0, socket_id);
	if (unlikely(fib->tbl8_pool == NULL)) {
		ret = -ENOMEM;
		goto free_tbl8s;
	}

	fib->first_free_tbl8_idx = 0;
	fib->first_free_idx = 0;
	for (i = 0; i < num_tbl8s; i++)
		fib->tbl8_pool[i] = i;

	/* Initialize 24-bit table. */
	write_atomics(fib->tbl24, 0, RTE_DIM(fib->tbl24) - 1, FIB_NO_NH);

	return 0;

free_tbl8s:
	rte_free(fib->tbl8s);
	fib->tbl8s = NULL;
free_rib:
	rib_free(&fib->rib);
out:
	return ret;
}

void
fib_free(struct fib_head *fib)
{
	fib->tbl8_pool[0] = FIB_TBL8_FREE_INDEX;
	fib->first_free_tbl8_idx = 0;
	fib->first_free_idx = 0;
	rte_free(fib->tbl8_pool);
	fib->tbl8_pool = NULL;

	fib->num_tbl8s = 0;
	rte_free(fib->tbl8s);
	fib->tbl8s = NULL;

	rib_free(&fib->rib);
}

static inline uint32_t
get_tbl24_idx(const uint8_t *address)
{
	return address[0] << 16 | address[1] << 8 | address[2];
}

#define FIB_EXTENDED_NH (0x80000000)

static inline bool
is_nh_extended(uint32_t nh)
{
	return !!(nh & FIB_EXTENDED_NH);
}

static inline uint32_t
get_tbl8_idx(uint32_t nh)
{
	RTE_BUILD_BUG_ON(!RTE_IS_POWER_OF_2(FIB_EXTENDED_NH));
	RTE_BUILD_BUG_ON(FIB_EXTENDED_NH - 1 != FIB_NO_NH);
	return nh & FIB_NO_NH;
}

#define ADDR_STR_VAR(name, addr_len) char name[2 * addr_len + 1]

static void
address_to_str(char *str, const uint8_t *address, uint8_t addr_len)
{
	static const char hex_to_char[] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f',
	};
	unsigned int i, j;

	RTE_BUILD_BUG_ON(RTE_DIM(hex_to_char) != 16);

	for (i = 0, j = 0; i < addr_len; i ++) {
		uint8_t byte = address[i];
		str[j++] = hex_to_char[(byte & 0xF0) >> 4];
		str[j++] = hex_to_char[(byte & 0x0F)];
	}
	str[j] = '\0';
}

struct prefix_range {
	bool     empty;
	uint32_t first;
	uint32_t last;
};

static inline uint32_t
n_one_bits32(uint8_t n)
{
	if (unlikely(n >= 32))
		return (uint32_t)-1;
	return (1 << n) - 1;
}

static inline void
set_range8_full(struct prefix_range *range)
{
	range->empty = false;
	range->first = 0x00;
	range->last  = 0xFF;
}

/*
 * RETURN true if the prefix was truncated.
 * NOTE the returned @range is never empty.
 */
static bool
set_range8(struct prefix_range *range, const uint8_t *address, uint8_t depth,
	uint8_t next_byte)
{
	bool truncated = false;
	int mask_depth, free_bits;

	mask_depth = next_byte * 8;
	if (mask_depth >= depth) {
		set_range8_full(range);
		return truncated;
	}

	mask_depth = depth - mask_depth;
	if (mask_depth > 8) {
		mask_depth = 8;
		truncated = true;
	}

	range->empty = false;
	free_bits = 8 - mask_depth;
	range->first = address[next_byte] &
		(n_one_bits32(mask_depth) << free_bits);
	range->last = range->first | n_one_bits32(free_bits);
	return truncated;
}

/* RETURN true if @acc_range was reduced. */
static bool
exclude_range(rte_atomic32_t *array, struct prefix_range *acc_range,
	const struct prefix_range *range, uint32_t next_hop)
{
	if (unlikely(range->empty || acc_range->empty)) {
		/* There is nothing to do. */
		return false;
	}

	/* @range is at the left of @acc_range. */
	if (range->first <= acc_range->first) {
		if (range->last < acc_range->first) {
			/* There is nothing to do. */
			return false;
		}
		if (range->last < acc_range->last)
			acc_range->first = range->last + 1;
		else
			acc_range->empty = true;
		return true;
	}

	/* @range is at the right of @acc_range. */
	if (range->last >= acc_range->last) {
		if (range->first > acc_range->last) {
			/* There is nothing to do. */
			return false;
		}
		if (range->first > acc_range->first)
			acc_range->last = range->first - 1;
		else
			acc_range->empty = true;
		return true;
	}

	/* @range is at the middle of @acc_range. */
	write_atomics(array, acc_range->first, range->first - 1, next_hop);
	acc_range->first = range->last + 1;
	return true;
}

static int
get_parent_child_nexthops(const struct fib_head *fib, const uint8_t *address,
	uint8_t depth, uint32_t *pparent_nexthop, uint32_t *pchild_nexthop)
{
	ADDR_STR_VAR(addr_str, fib->addr_len_bytes);
	struct rib_shorter_iterator_state state;
	uint32_t parent_nexthop, child_nexthop;
	int ret = rib_shorter_iterator_state_init(&state, &fib->rib, address,
		depth);
	if (unlikely(ret < 0)) {
		address_to_str(addr_str, address, fib->addr_len_bytes);
		G_LOG(ERR, "%s(%s/%u): failed to initialize RIB iterator (errno=%i): %s\n",
			__func__, addr_str, depth, -ret, strerror(-ret));
		return ret;
	}

	parent_nexthop = FIB_NO_NH;
	child_nexthop = FIB_NO_NH;
	while (true) {
		struct rib_iterator_rule rule;

		ret = rib_shorter_iterator_next(&state, &rule);
		if (unlikely(ret < 0)) {
			if (likely(ret == -ENOENT)) {
				*pparent_nexthop = parent_nexthop;
				*pchild_nexthop = child_nexthop;
				ret = 0;
				break;
			}
			address_to_str(addr_str, address, fib->addr_len_bytes);
			G_LOG(ERR, "%s(%s/%u): RIB iterator failed (errno=%i): %s\n",
				__func__, addr_str, depth,
				-ret, strerror(-ret));
			break;
		}

		if (likely(rule.depth < depth))
			parent_nexthop = rule.next_hop;
		else if (likely(rule.depth == depth))
			child_nexthop = rule.next_hop;
		else {
			address_to_str(addr_str, address, fib->addr_len_bytes);
			G_LOG(CRIT, "%s(%s/%u): bug: rule.depth=%i > depth=%i\n",
				__func__, addr_str, depth, rule.depth, depth);
			ret = -EFAULT;
			break;
		}
	}

	rib_shorter_iterator_end(&state);
	return ret;
}

/*
 * The following definitions and results drive the code.
 *
 * Definition Len(P):
 * 	Let P be a prefix in a given FIB,
 *	Len(P) is the length (AKA depth) of P.
 *
 * Definition Nh(P):
 * 	Let P be a prefix in a given FIB,
 *	Nh(P) is the next hop of P.
 *
 * Definition P1 includes P2:
 *	Let P1 and P2 be prefixes in a given FIB,
 *	P1 includes P2 if, and only if,
 *	1. Len(P1) < Len(P2) and
 *	2. the first Len(P1) bits of P2 are equal to P1.
 *	Notice that 1. forces P1 and P2 to be different.
 *	For example, P1 == 10.0.0.0/8 includes P2 == 10.10.0.0/16.
 *
 * Definition P1 is the parent of P2 (or P2 is a child of P1):
 *	Let P1 and P2 be prefixes in a given FIB F,
 *	P1 is the parent of P2 if, and only if,
 *	1. P1 includes P2 and
 *	2. there is no prefix P in F such that
 *		P1 includes P and P includes P2.
 *	Notice that a prefix can only have one parent (it it exists),
 *	whereas a prefix can have zero or more children.
 *
 * Definition Rt(T):
 * 	Let T be a tbl8 in a given FIB F,
 *	Rt(T) is the prefix of the entry where T is rooted.
 *	Notice that Rt(T) may not be in F.
 *	For example, let T be the tbl8 in which the prefix 10.0.0.1/32
 *	resides, Rt(T) == 10.0.0.0/24.
 *
 * Definition Nh(T):
 *	Let T be a tbl8 in a given FIB F.
 * 	If Rt(T) is in F, Nh(T) is Nh(Rt(T)).
 * 	If Rt(T) is NOT in F but the parent prefix P of Rt(T) is in F,
 * 		Nh(T) is Nh(P).
 * 	Otherwise, Nh(T) is FIB_NO_NH.
 *
 * Definition P justifies T:
 *	A prefix P justifies (or requires) the allocation of
 *	a tbl8 T in a given FIB if, and only if,
 *	1. Rt(T) includes P and
 *	2. Nh(P) != Nh(T).
 *	Notice that this definition is not ideal, but a compromise.
 *	For example, consider a FIB with the following prefixes:
 *	Nh(0.0.0.0/0) == A, Nh(10.0.0.0/25) == B, Nh(10.0.0.0/26) == A,
 *	and Nh(10.0.0.64/26) == A.
 *	The definition here requires the tbl8 T whose Rt(T) is 10.0.0.0/24
 *	Nh(T) == A to be allocated since Rt(T) includes 10.0.0.0/25 and
 *	Nh(T) != Nh(10.0.0.0/25). Nevertheless, NOT allocating T
 *	would produce correct lookups.
 *
 * The all-the-same theorem.
 *
 * Given a FIB F, let T be a tbl8 such that
 * there is NO prefix P in F that justifies the allocation of T.
 * For all prefixes P in F such that Rt(T) includes P, Nh(P) == Nh(T).
 *
 * NOTE
 *	While this threorem is not currently being used in the code,
 *	it is a good illustration of the use of the definitions above.
 *
 * Proof:
 *
 * If there is no prefixes P in F such that Rt(T) includes P,
 * the theorem cannot be made false.
 *
 * Let P be a prefix in F such that Rt(T) includes P.
 * Since no prefix justifies T (hypothesis), from the definition
 * "P justifies T", Nh(P) == Nh(T).
 */

static int
nh_of_tbl8(const struct fib_head *fib, const uint8_t *tbl8_address,
	uint8_t tbl8_depth, uint32_t *ptbl8_nexthop)
{
	uint32_t parent_nexthop, child_nexthop;
	int ret = get_parent_child_nexthops(fib, tbl8_address, tbl8_depth,
		&parent_nexthop, &child_nexthop);
	if (unlikely(ret < 0))
		return ret;
	*ptbl8_nexthop = child_nexthop != FIB_NO_NH
	       ? child_nexthop : parent_nexthop;
	return 0;
}

/*
 * Rt(T) == @tbl8_address/@tbl8_depth.
 * Nh(T) == @tbl8_nexthop.
 *
 * RETURN
 * 	< 0		If it fails.
 * 	false (0)	If the tbl8 T is NOT needed.
 * 	true  (1)	if the tbl8 T is needed.
 */
static int
is_tbl8_needed(struct fib_head *fib, const uint8_t *tbl8_address,
	uint8_t tbl8_depth, uint32_t tbl8_nexthop)
{
	ADDR_STR_VAR(addr_str, fib->addr_len_bytes);
	struct rib_longer_iterator_state state;
	int ret = rib_longer_iterator_state_init(&state, &fib->rib,
		tbl8_address, tbl8_depth, false);
	if (unlikely(ret < 0)) {
		address_to_str(addr_str, tbl8_address, fib->addr_len_bytes);
		G_LOG(ERR, "%s(%s/%u): failed to initialize RIB iterator (errno=%i): %s\n",
			__func__, addr_str, tbl8_depth, -ret, strerror(-ret));
		return ret;
	}

	while (true) {
		struct rib_iterator_rule rule;

		ret = rib_longer_iterator_next(&state, &rule);
		if (unlikely(ret < 0)) {
			if (likely(ret == -ENOENT)) {
				ret = false;
				break;
			}
			address_to_str(addr_str, tbl8_address,
				fib->addr_len_bytes);
			G_LOG(ERR, "%s(%s/%u): RIB iterator failed (errno=%i): %s\n",
				__func__, addr_str, tbl8_depth,
				-ret, strerror(-ret));
			break;
		}

		if (likely(rule.depth > tbl8_depth)) {
			if (rule.next_hop != tbl8_nexthop) {
				/*
				 * The longer iterator already guarantees that
				 * Rt(T) includes the prefix
				 * @rule.address_no/@rule.depth, so this prefix
				 * justifies T.
				 */
				ret = true;
				break;
			}
		} else if (likely(rule.depth == tbl8_depth)) {
			/*
			 * Ignore prefix @tbl8_address/@tbl8_depth since
			 * it cannot justify T.
			 */
		} else {
			address_to_str(addr_str, tbl8_address,
				fib->addr_len_bytes);
			G_LOG(CRIT, "%s(%s/%u): bug: rule.depth=%i < tbl8_depth=%i\n",
				__func__, addr_str, tbl8_depth,
				rule.depth, tbl8_depth);
			ret = -EFAULT;
			break;
		}
	}

	rib_longer_iterator_end(&state);
	return ret;
}

static int
tbl8_get(struct fib_head *fib, uint32_t *ptbl8_idx)
{
	uint32_t tbl8_idx_candidate = fib->tbl8_pool[fib->first_free_tbl8_idx];

	if (unlikely(tbl8_idx_candidate == FIB_TBL8_FREE_INDEX))
		return -ENOSPC;	/* No more free TBL8. */

	fib->tbl8_pool[fib->first_free_tbl8_idx] = FIB_TBL8_FREE_INDEX;
	fib->first_free_tbl8_idx =
		(fib->first_free_tbl8_idx + 1) % fib->num_tbl8s;
	*ptbl8_idx = tbl8_idx_candidate;
	return 0;
}

static void
tbl8_put(struct fib_head *fib, uint32_t tbl8_idx)
{
	if (unlikely(tbl8_idx == FIB_TBL8_FREE_INDEX)) {
		G_LOG(CRIT, "%s(): bug: called to release FIB_TBL8_FREE_INDEX\n",
			__func__);
		return;
	}

	if (unlikely(fib->tbl8_pool[fib->first_free_idx] !=
			FIB_TBL8_FREE_INDEX)) {
		G_LOG(CRIT, "%s(): bug: pool overflow\n", __func__);
		return;
	}

	fib->tbl8_pool[fib->first_free_idx] = tbl8_idx;
	fib->first_free_idx = (fib->first_free_idx + 1) % fib->num_tbl8s;
}

static void
free_tbl8(struct fib_head *fib, uint32_t tbl8_idx)
{
	/* Do not update @tbl8 to avoid disrupting concurrent readers. */
	const struct fib_tbl8 *tbl8 = &fib->tbl8s[tbl8_idx];
	int i;

	for (i = 0; i < (typeof(i))RTE_DIM(tbl8->nh); i++) {
		uint32_t nh = rte_atomic32_read(&tbl8->nh[i]);
		if (is_nh_extended(nh)) {
			/*
			 * As long as the FIB is not corrupted,
			 * free_tbl8() is never called twice on
			 * the same @tbl8_idx because each @tbl8_idx represents
			 * a unique range of the address space.
			 */
			free_tbl8(fib, get_tbl8_idx(nh));
		}
	}
	tbl8_put(fib, tbl8_idx);
}

static int build_fib_tbl8(struct fib_head *fib, rte_atomic32_t *root,
	const uint8_t *tbl8_address,  uint8_t next_byte, uint32_t tbl8_nexthop);

/*
 * RETURN
 *	< 0		Failure.
 *	false (0)	Range updating is not needed.
 *	true  (1)	Range updating may be needed.
 */
static int
check_tbl8(struct fib_head *fib, rte_atomic32_t *root,
	const uint8_t *tbl8_address, uint8_t next_byte,
	struct fib_tbl8 **ptbl8, uint32_t *ptbl8_nexthop)
{
	uint32_t tbl8_nexthop, nh;
	uint8_t tbl8_depth;
	int ret;

	tbl8_depth = next_byte * 8;
	ret = nh_of_tbl8(fib, tbl8_address, tbl8_depth, &tbl8_nexthop);
	if (unlikely(ret < 0))
		return ret;
	ret = is_tbl8_needed(fib, tbl8_address, tbl8_depth, tbl8_nexthop);
	if (unlikely(ret < 0))
		return ret;
	nh = rte_atomic32_read(root);
	if (!ret) {
		/* The tbl8 is NOT needed. */
		rte_atomic32_set(root, tbl8_nexthop);
		if (is_nh_extended(nh))
			free_tbl8(fib, get_tbl8_idx(nh));
		return false;
	}

	/*
	 * The tbl8 is needed.
	 */

	if (!is_nh_extended(nh)) {
		ret = build_fib_tbl8(fib, root, tbl8_address, next_byte,
			tbl8_nexthop);
		if (unlikely(ret < 0))
			return ret;
		return false;
	}

	/* Range updating may be needed. */
	*ptbl8 = &fib->tbl8s[get_tbl8_idx(nh)];
	*ptbl8_nexthop = tbl8_nexthop;
	return true;
}

static int
build_fib_tbl8(struct fib_head *fib, rte_atomic32_t *root,
	const uint8_t *tbl8_address,  uint8_t next_byte, uint32_t tbl8_nexthop)
{
	ADDR_STR_VAR(addr_str, fib->addr_len_bytes);
	uint32_t tbl8_idx;
	struct fib_tbl8 *tbl8;
	uint8_t tbl8_depth;
	struct rib_longer_iterator_state state;

	/*
	 * Allocate a tbl8.
	 */
	int ret = tbl8_get(fib, &tbl8_idx);
	if (unlikely(ret < 0))
		return ret;
	tbl8 = &fib->tbl8s[tbl8_idx];
	write_atomics(tbl8->nh, 0, RTE_DIM(tbl8->nh) - 1, tbl8_nexthop);

	tbl8_depth = next_byte * 8;
	ret = rib_longer_iterator_state_init(&state, &fib->rib, tbl8_address,
		tbl8_depth, false);
	if (unlikely(ret < 0)) {
		address_to_str(addr_str, tbl8_address, fib->addr_len_bytes);
		G_LOG(ERR, "%s(%s/%u): failed to initialize RIB iterator (errno=%i): %s\n",
			__func__, addr_str, tbl8_depth, -ret, strerror(-ret));
		tbl8_put(fib, tbl8_idx);
		return ret;
	}

	while (true) {
		struct rib_iterator_rule rule;

		ret = rib_longer_iterator_next(&state, &rule);
		if (unlikely(ret < 0)) {
			if (likely(ret == -ENOENT)) {
				ret = 0;
				break;
			}
			address_to_str(addr_str, tbl8_address,
				fib->addr_len_bytes);
			G_LOG(ERR, "%s(%s/%u): RIB iterator failed (errno=%i): %s\n",
				__func__, addr_str, tbl8_depth,
				-ret, strerror(-ret));
			break;
		}

		if (likely(rule.depth > tbl8_depth)) {
			const uint8_t *rule_address =
				(uint8_t *)&rule.address_no;
			struct prefix_range rule_range;
			if (set_range8(&rule_range, rule_address, rule.depth,
					next_byte)) {
				/* The rule goes deeper. */
				struct fib_tbl8 *ignore_tbl8;
				uint32_t ignore_tbl8_nexthop;
				ret = check_tbl8(fib,
					&tbl8->nh[rule_range.first],
					rule_address, next_byte + 1,
					&ignore_tbl8, &ignore_tbl8_nexthop);
				if (unlikely(ret < 0))
					break;
				if (unlikely(ret)) {
					address_to_str(addr_str, rule_address,
						fib->addr_len_bytes);
					G_LOG(CRIT, "%s(%s/%u): bug: tbl8 still requires updates\n",
						__func__, addr_str, rule.depth);
				}
				ret = rib_longer_iterator_skip_branch(&state,
					rule_address, tbl8_depth + 8);
				if (unlikely(ret < 0))
					break;
			} else {
				write_atomics(tbl8->nh, rule_range.first,
					rule_range.last, rule.next_hop);
			}
		} else if (likely(rule.depth == tbl8_depth)) {
			/* Ignore prefix @tbl8_address/@tbl8_depth. */
		} else {
			address_to_str(addr_str, tbl8_address,
				fib->addr_len_bytes);
			G_LOG(CRIT, "%s(%s/%u): bug: rule.depth=%i < tbl8_depth=%i\n",
				__func__, addr_str, tbl8_depth, rule.depth,
				tbl8_depth);
			ret = -EFAULT;
			break;
		}
	}
	rib_longer_iterator_end(&state);

	if (likely(ret == 0)) {
		/* Insert @tbl8 to FIB. */
		rte_atomic32_set(root, FIB_EXTENDED_NH | tbl8_idx);
		return 0;
	}

	free_tbl8(fib, tbl8_idx);
	return ret;
}

static int update_tbl8_nh(struct fib_head *fib, rte_atomic32_t *root,
	const uint8_t *tbl8_address, uint8_t next_byte);

/*
 * Remove all sub-prefixes of @range, and update @range of @tbl8 with
 * @range_nexthop.
 */
static int
update_tbl8_range(struct fib_head *fib, struct fib_tbl8 *tbl8,
	uint8_t next_byte, struct prefix_range range,
	const uint8_t *range_address, uint8_t range_depth,
	uint32_t range_nexthop)
{
	ADDR_STR_VAR(addr_str, fib->addr_len_bytes);
	struct rib_longer_iterator_state state;
	int ret = rib_longer_iterator_state_init(&state, &fib->rib,
		range_address, range_depth, true);
	if (unlikely(ret < 0)) {
		address_to_str(addr_str, range_address, fib->addr_len_bytes);
		G_LOG(ERR, "%s(%s/%u): failed to initialize RIB iterator (errno=%i): %s\n",
			__func__, addr_str, range_depth, -ret, strerror(-ret));
		return ret;
	}

	while (true) {
		struct rib_iterator_rule rule;

		ret = rib_longer_iterator_next(&state, &rule);
		if (unlikely(ret < 0)) {
			if (likely(ret == -ENOENT)) {
				if (!range.empty) {
					/* Write remaining range. */
					write_atomics(tbl8->nh,
						range.first, range.last,
						range_nexthop);
				}
				ret = 0;
				break;
			}
			address_to_str(addr_str, range_address,
				fib->addr_len_bytes);
			G_LOG(ERR, "%s(%s/%u): RIB iterator failed (errno=%i): %s\n",
				__func__, addr_str, range_depth,
				-ret, strerror(-ret));
			break;
		}

		if (likely(rule.depth > range_depth)) {
			const uint8_t *rule_address =
				(uint8_t *)&rule.address_no;
			struct prefix_range rule_range;
			bool dig = set_range8(&rule_range, rule_address,
				rule.depth, next_byte);
			if (unlikely(!exclude_range(tbl8->nh, &range,
					&rule_range, range_nexthop))) {
				address_to_str(addr_str, range_address,
					fib->addr_len_bytes);
				G_LOG(CRIT, "%s(%s/%u): bug: missing exclusion\n",
					__func__, addr_str, range_depth);
			}
			if (dig) {
				ret = update_tbl8_nh(fib,
					&tbl8->nh[rule_range.first],
					rule_address, next_byte + 1);
				if (unlikely(ret < 0))
					break;
				ret = rib_longer_iterator_skip_branch(&state,
					rule_address, (next_byte + 1) * 8);
				if (unlikely(ret < 0))
					break;
			}
		} else if (likely(rule.depth == range_depth)) {
			/* Ignore prefix @range_address/@range_depth. */
		} else {
			address_to_str(addr_str, range_address,
				fib->addr_len_bytes);
			G_LOG(CRIT, "%s(%s/%u): bug: rule.depth=%i < iter_depth=%i\n",
				__func__, addr_str, range_depth,
				rule.depth, range_depth);
			ret = -EFAULT;
			break;
		}
	}

	rib_longer_iterator_end(&state);
	return ret;
}

/*
 * @root is where the index of the tbl8 T will reside, or resides.
 *
 * Rt(T) = @tbl8_address/(@next_byte * 8).
 *
 * @next_byte is the index of @address to be evaluated.
 */
static int
update_tbl8_nh(struct fib_head *fib, rte_atomic32_t *root,
	const uint8_t *tbl8_address, uint8_t next_byte)
{
	struct fib_tbl8 *tbl8;
	uint32_t tbl8_nexthop;
	struct prefix_range range;

	int ret = check_tbl8(fib, root, tbl8_address, next_byte, &tbl8,
		&tbl8_nexthop);
	if (ret <= 0)
		return ret;

	set_range8_full(&range);
	return update_tbl8_range(fib, tbl8, next_byte, range,
		tbl8_address, next_byte * 8, tbl8_nexthop);
}

/*
 * @root is where the index of the tbl8 T will reside, or resides.
 *
 * Rt(T) = @address/(@next_byte * 8).
 *
 * @next_byte is the index of @address to be evaluated.
 *
 * The prefix P == @address/@depth is the prefix being updated.
 * Nh(P) == @next_hop.
 *
 * P must be in @fib->rib if it's being added or having its @next_hop updated,
 * whereas P must not be in @fib->rib if it's being removed.
 *
 * Note that @depth > (@next_byte * 8) must be true.
 */
static int
update_tbl8_rule(struct fib_head *fib, rte_atomic32_t *root, uint8_t next_byte,
	const uint8_t *address, uint8_t depth, uint32_t next_hop)
{
	struct fib_tbl8 *tbl8;
	uint32_t tbl8_nexthop;
	struct prefix_range range;
	int ret;

	if (unlikely(depth <= next_byte * 8))
		return -EINVAL;

	ret = check_tbl8(fib, root, address, next_byte, &tbl8,
		&tbl8_nexthop);
	if (ret <= 0)
		return ret;

	if (set_range8(&range, address, depth, next_byte)) {
		/* The prefix goes deeper. */
		return update_tbl8_rule(fib, &tbl8->nh[range.first],
			next_byte + 1, address, depth, next_hop);
	}

	if (depth >= (fib->addr_len_bytes * 8)) {
		if (unlikely(range.empty || range.first != range.last)) {
			G_LOG(CRIT, "%s(): bug: range.empty=%i, range.first=%u, range.last=%u\n",
				__func__, range.empty,
				range.first, range.last);
			return -EFAULT;
		}

		/*
		 * Avoid the iterator below for the common case of
		 * @depth being the maximum length.
		 */
		rte_atomic32_set(&tbl8->nh[range.first], next_hop);
		return 0;
	}

	return update_tbl8_range(fib, tbl8, next_byte, range,
		address, depth, next_hop);
}

/* RETURN true if the prefix was truncated. */
static bool
set_range24(struct prefix_range *range, const uint8_t *address, uint8_t depth)
{
	bool truncated = false;
	int free_bits;

	if (unlikely(depth > 24)) {
		depth = 24;
		truncated = true;
	}

	range->empty = false;
	free_bits = 24 - depth;
	range->first = get_tbl24_idx(address) &
		(n_one_bits32(depth) << free_bits);
	range->last = range->first | n_one_bits32(free_bits);
	return truncated;
}

/*
 * IMPORTANT:
 * 	P must have already been added/removed from the RIB before calling
 * 	this function.
 */
static int
update_fib(struct fib_head *fib, const uint8_t *address, uint8_t depth,
	uint32_t next_hop)
{
	ADDR_STR_VAR(addr_str, fib->addr_len_bytes);
	struct prefix_range range;
	struct rib_longer_iterator_state state;
	int ret;

	if (set_range24(&range, address, depth)) {
		/* The prefix goes deeper. */
		return update_tbl8_rule(fib,
			&fib->tbl24[get_tbl24_idx(address)], 3,
			address, depth, next_hop);
	}

	/*
	 * Remove all sub-prefixes of @range, and update @range of tbl24.
	 */

	ret = rib_longer_iterator_state_init(&state, &fib->rib, address,
		depth, true);
	if (unlikely(ret < 0)) {
		address_to_str(addr_str, address, fib->addr_len_bytes);
		G_LOG(ERR, "%s(%s/%u): failed to initialize RIB iterator (errno=%i): %s\n",
			__func__, addr_str, depth, -ret, strerror(-ret));
		return ret;
	}

	while (true) {
		struct rib_iterator_rule rule;

		ret = rib_longer_iterator_next(&state, &rule);
		if (unlikely(ret < 0)) {
			if (likely(ret == -ENOENT)) {
				if (!range.empty) {
					/* Write remaining range. */
					write_atomics(fib->tbl24,
						range.first, range.last,
						next_hop);
				}
				ret = 0;
				break;
			}
			address_to_str(addr_str, address, fib->addr_len_bytes);
			G_LOG(ERR, "%s(%s/%u): RIB iterator failed (errno=%i): %s\n",
				__func__, addr_str, depth,
				-ret, strerror(-ret));
			break;
		}

		if (likely(rule.depth > depth)) {
			struct prefix_range rule_range;
			bool dig = set_range24(&rule_range,
				(uint8_t *)&rule.address_no, rule.depth);
			if (unlikely(!exclude_range(fib->tbl24, &range,
					&rule_range, next_hop))) {
				address_to_str(addr_str, address,
					fib->addr_len_bytes);
				G_LOG(CRIT, "%s(%s/%u): bug: missing exclusion\n",
					__func__, addr_str, depth);
			}
			if (dig) {
				const uint8_t *dig_tbl8_address =
					(uint8_t *)&rule.address_no;
				ret = update_tbl8_nh(fib,
					&fib->tbl24[rule_range.first],
					dig_tbl8_address, 3);
				if (unlikely(ret < 0))
					break;
				ret = rib_longer_iterator_skip_branch(&state,
					dig_tbl8_address, 24);
				if (unlikely(ret < 0))
					break;
			}
		} else if (likely(rule.depth == depth)) {
			/* Ignore prefix @address/@depth. */
		} else {
			address_to_str(addr_str, address, fib->addr_len_bytes);
			G_LOG(CRIT, "%s(%s/%u): bug: rule.depth=%i < depth=%i\n",
				__func__, addr_str, depth, rule.depth, depth);
			ret = -EFAULT;
			break;
		}
	}

	rib_longer_iterator_end(&state);
	return ret;
}

int
__fib_add(struct fib_head *fib, const uint8_t *address, uint8_t depth,
	uint32_t next_hop, bool failsafe)
{
	ADDR_STR_VAR(addr_str, fib->addr_len_bytes);
	int ret, ret2;
	uint32_t parent_nexthop, child_nexthop;

	if (unlikely(depth > rib_get_max_length(&fib->rib)))
		return -EINVAL;

	if (unlikely(next_hop >= FIB_NO_NH)) {
		address_to_str(addr_str, address, fib->addr_len_bytes);
		G_LOG(ERR, "%s(%s/%u): next_hop=%u must be less than FIB_NO_NH=%u\n",
			__func__, addr_str, depth, next_hop, FIB_NO_NH);
		return -EINVAL;
	}

	ret = rib_add(&fib->rib, address, depth, next_hop);
	if (ret < 0)
		return ret;

	ret = get_parent_child_nexthops(fib, address, depth, &parent_nexthop,
		&child_nexthop);
	if (unlikely(ret < 0 || next_hop != child_nexthop)) {
		address_to_str(addr_str, address, fib->addr_len_bytes);
		G_LOG(CRIT, "%s(%s/%u): bug: RIB is corrupted: ret=%i, next_hop=%u, child_nexthop=%u\n",
			__func__, addr_str, depth, ret, next_hop,
			child_nexthop);
		/* Free rule in RIB. */
		ret = rib_delete(&fib->rib, address, depth);
		if (unlikely(ret < 0)) {
			G_LOG(CRIT, "%s(%s/%u): bug: failed to remove prefix just added to RIB (errno=%i): %s\n",
				__func__, addr_str, depth,
				-ret, strerror(-ret));
		}
		return -EFAULT;
	}

	/* Only avoid update_fib() when @failsafe is true. */
	if (unlikely(failsafe && parent_nexthop == next_hop)) {
		/* There's nothing to update in the FIB. */
		return 0;
	}
	ret = update_fib(fib, address, depth, next_hop);
	if (likely(ret == 0))
		return 0; /* It's done. */

	address_to_str(addr_str, address, fib->addr_len_bytes);
	G_LOG(ERR, "%s(%s/%u): update_fib() failed (errno=%i): %s\n",
		__func__, addr_str, depth, -ret, strerror(-ret));
	if (!failsafe)
		return ret;

	/* Try to recover @fib to a safe state. */
	ret2 = __fib_delete(fib, address, depth, false);
	if (unlikely(ret2 < 0)) {
		G_LOG(CRIT, "%s(%s/%u): bug: __fib_delete() cannot restore FIB (errno=%i): %s\n",
			__func__, addr_str, depth, -ret2, strerror(-ret2));
	}
	return ret;
}

int
__fib_delete(struct fib_head *fib, const uint8_t *address, uint8_t depth,
	bool failsafe)
{
	ADDR_STR_VAR(addr_str, fib->addr_len_bytes);
	uint32_t parent_nexthop, child_nexthop;
	int ret, ret2;

	if (unlikely(depth > rib_get_max_length(&fib->rib)))
		return -EINVAL;

	ret = get_parent_child_nexthops(fib, address, depth,
		&parent_nexthop, &child_nexthop);
	if (unlikely(ret < 0)) {
		address_to_str(addr_str, address, fib->addr_len_bytes);
		G_LOG(CRIT, "%s(%s/%u): bug: RIB is corrupted (errno=%i): %s\n",
			__func__, addr_str, depth, -ret, strerror(-ret));
		return -EFAULT;
	}
	if (child_nexthop == FIB_NO_NH) {
		/* There's nothing to do. */
		return -ENOENT;
	}

	/* Free rule in RIB. */
	ret = rib_delete(&fib->rib, address, depth);
	if (unlikely(ret < 0)) {
		address_to_str(addr_str, address, fib->addr_len_bytes);
		G_LOG(CRIT, "%s(%s/%u): bug: failed to remove prefix from RIB (errno=%i): %s\n",
			__func__, addr_str, depth, -ret, strerror(-ret));
		return ret;
	}

	/* Only avoid update_fib() when @failsafe is true. */
	if (unlikely(failsafe && parent_nexthop == child_nexthop)) {
		/* There's nothing to update in the FIB. */
		return 0;
	}
	ret = update_fib(fib, address, depth, parent_nexthop);
	if (likely(ret == 0))
		return 0; /* It's done. */

	address_to_str(addr_str, address, fib->addr_len_bytes);
	G_LOG(ERR, "%s(%s/%u): update_fib() failed (errno=%i): %s\n",
		__func__, addr_str, depth, -ret, strerror(-ret));
	if (!failsafe)
		return ret;

	/* Try to recover @fib to a safe state. */
	ret2 = __fib_add(fib, address, depth, child_nexthop, false);
	if (unlikely(ret2 < 0)) {
		G_LOG(CRIT, "%s(%s/%u): bug: __fib_add() cannot restore FIB (errno=%i): %s\n",
			__func__, addr_str, depth, -ret, strerror(-ret));
	}
	return ret;
}

int fib_lookup(const struct fib_head *fib, const uint8_t *address,
	uint32_t *pnext_hop)
{
	/* TODO */
	RTE_SET_USED(fib);
	RTE_SET_USED(address);
	RTE_SET_USED(pnext_hop);
	return -ENOTSUP;
}

void
fib_lookup_bulk(const struct fib_head *fib, const uint8_t **addresses,
	uint32_t *next_hops, unsigned int n)
{
	/* TODO */
	RTE_SET_USED(fib);
	RTE_SET_USED(addresses);
	RTE_SET_USED(next_hops);
	RTE_SET_USED(n);
}
