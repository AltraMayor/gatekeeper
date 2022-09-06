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

#include <rte_byteorder.h>
#include <rte_errno.h>

#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#include <rte_memcpy.h>
#endif

#include "gatekeeper_main.h"
#include "gatekeeper_rib.h"

static int
__read_addr(uint8_t length, rib_address_t *cpu_addr, const uint8_t *address)
{
	if (unlikely(address == NULL)) {
		*cpu_addr = 0;
		return 0;
	}

	switch (length) {
        case 32:
		*cpu_addr = rte_be_to_cpu_32(*((uint32_t *)address));
		break;

	case 128: {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t *dst = (uint64_t *)cpu_addr;
		uint64_t *src = (uint64_t *)address;
		dst[0] = rte_be_to_cpu_64(src[1]);
		dst[1] = rte_be_to_cpu_64(src[0]);
#else /* RTE_BIG_ENDIAN */
		RTE_BUILD_BUG_ON(sizeof(*cpu_addr) != sizeof(uint128_t));
		rte_mov128((uint8_t *)cpu_addr, address);
#endif
		break;
	}

	default:
		G_LOG(ERR, "%s(): length=%u is not implemented\n",
			__func__, length);
		return -EINVAL;
	}
	return 0;
}

static inline int
read_addr(const struct rib_head *rib, rib_address_t *cpu_addr,
	const uint8_t *address)
{
	return __read_addr(rib->max_length, cpu_addr, address);
}

static int
__write_addr(uint8_t length, uint8_t *address, rib_address_t cpu_addr)
{
	switch (length) {
	case 32:
		*((uint32_t *)address) = rte_cpu_to_be_32(cpu_addr);
		break;

	case 128: {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		uint64_t *dst = (uint64_t *)address;
		uint64_t *src = (uint64_t *)&cpu_addr;
		dst[0] = rte_cpu_to_be_64(src[1]);
		dst[1] = rte_cpu_to_be_64(src[0]);
#else /* RTE_BIG_ENDIAN */
		RTE_BUILD_BUG_ON(sizeof(cpu_addr) != sizeof(uint128_t));
		rte_mov128(address, (uint8_t *)&cpu_addr);
#endif
		break;
	}

	default:
		G_LOG(ERR, "%s(): length=%u is not implemented\n",
			__func__, length);
		return -EINVAL;
	}
	return 0;
}

static inline int
write_addr(const struct rib_head *rib, uint8_t *address, rib_address_t cpu_addr)
{
	return __write_addr(rib->max_length, address, cpu_addr);
}

int
rib_create(struct rib_head *rib, const char *name, int socket_id,
	uint8_t max_length, uint32_t max_rules)
{
	rib_address_t dummy;
	int ret;
	unsigned int n;

	if (unlikely(max_length > RIB_MAX_ADDRESS_LENGTH)) {
		G_LOG(ERR, "%s(): max_length=%u is greater than RIB_MAX_ADDRESS_LENGTH=%i\n",
			__func__, max_length, RIB_MAX_ADDRESS_LENGTH);
		return -EINVAL;
	}

	if (unlikely((max_length & 0x7) > 0)) {
		G_LOG(ERR, "%s(): max_length=%u is not a multiple of 8\n",
			__func__, max_length);
		return -EINVAL;
	}

	ret = __read_addr(max_length, &dummy, (const uint8_t *)&dummy);
	if (unlikely(ret < 0))
		return ret;

	ret = __write_addr(max_length, (uint8_t *)&dummy, 0);
	if (unlikely(ret < 0))
		return ret;

	memset(rib, 0, sizeof(*rib));
	rib->max_length = max_length;

	/*
	 * Number of nodes needed to store a max-length prefix.
	 * Adding (RIB_MAX_PREFIX_BITS - 1) is equivalent to rouding up
	 * the result since it's an integer division.
	 */
	n = (max_length + RIB_MAX_PREFIX_BITS - 1) / RIB_MAX_PREFIX_BITS;
	/*
	 * rib_add() needs at most a new internal node when adding
	 * a prefix to the RIB.
	 */
	n++;
	/*
	 * Loose upper bound on the number of nodes needed to have
	 * @max_rules rules.
	 */
	n *= max_rules;

	rib->mp_nodes = rte_mempool_create(name, n, sizeof(struct rib_node),
		0, 0, NULL, NULL, NULL, NULL, socket_id,
		/* Save memory; struct rib_node is small. */
		MEMPOOL_F_NO_SPREAD | MEMPOOL_F_NO_CACHE_ALIGN |
		/* No synchronization; single writer. */
		MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET |
		/* Nodes are not used for I/O. */
		MEMPOOL_F_NO_IOVA_CONTIG);
	if (unlikely(rib->mp_nodes == NULL)) {
		ret = rte_errno;
		G_LOG(ERR, "%s(): cannot create memory pool (errno=%i): %s\n",
			__func__, ret, rte_strerror(ret));
		return -ret;
	}

	return 0;
}

void
rib_free(struct rib_head *rib)
{
	rib->root_node.has_nh = false;
	rib->root_node.branch[false] = NULL;
	rib->root_node.branch[true] = NULL;
	rib->version++;

	rte_mempool_free(rib->mp_nodes);
	rib->mp_nodes = NULL;
}

static inline void
info_init(struct rib_node_info *info, const struct rib_head *rib)
{
	info->haddr_matched = 0;
	info->haddr_mask = 0;
	info->depth = 0;
	info->missing_bits = rib->max_length;
}

static rib_address_t
lshift(rib_address_t x, uint8_t count)
{
	RTE_BUILD_BUG_ON((typeof(count))-1 < RIB_MAX_ADDRESS_LENGTH);

	if (unlikely(count > RIB_MAX_ADDRESS_LENGTH)) {
		G_LOG(CRIT, "%s(): bug: count == %i is greater than %i\n",
			__func__, count, RIB_MAX_ADDRESS_LENGTH);
		count = RIB_MAX_ADDRESS_LENGTH;
	}

	/*
	 * The result of the left shift operator (i.e. <<) is undefined if
	 * the right operand is negative, or greater than or equal to
	 * the number of bits in the type of the left expression.
	 */
	if (unlikely(count == RIB_MAX_ADDRESS_LENGTH))
		return 0;

	return x << count;
}

static inline rib_address_t
n_one_bits(uint8_t n)
{
	return lshift(1, n) - 1;
}

static void
info_update(struct rib_node_info *info, const struct rib_node *cur_node)
{
	rib_address_t lsb_mask; /* Mask for the least-significant bits. */

	/* Update @info->missing_bits. */
	info->missing_bits -= cur_node->matched_bits;
	RTE_VERIFY(info->missing_bits >= 0);

	/* Update @info->depth. */
	info->depth += cur_node->matched_bits;

	/* Update @info->haddr_mask. */
	lsb_mask = n_one_bits(cur_node->matched_bits);
	info->haddr_mask |= lshift(lsb_mask, info->missing_bits);

	/* Update @info->haddr_matched. */
	RTE_VERIFY((cur_node->pfx_bits & ~lsb_mask) == 0);
	info->haddr_matched |= lshift(cur_node->pfx_bits, info->missing_bits);
}

static inline bool
info_haddr_matches(const struct rib_node_info *info, rib_address_t haddr)
{
	return (haddr & info->haddr_mask) == info->haddr_matched;
}

static inline bool
test_bit_n(rib_address_t haddr, uint8_t bit)
{
	return !!(haddr & lshift(1, bit));
}

static int
next_bit(const struct rib_node_info *info, rib_address_t haddr)
{
	if (unlikely(info->missing_bits <= 0)) {
		G_LOG(CRIT, "%s(): bug: missing_bits == %i is not positive\n",
			__func__, info->missing_bits);
		return -EINVAL;
	}

	return test_bit_n(haddr, info->missing_bits - 1);
}

static inline const struct rib_node *
next_node(const struct rib_node *cur_node, const struct rib_node_info *info,
	rib_address_t haddr)
{
	int ret = next_bit(info, haddr);
	if (unlikely(ret < 0))
		return NULL;

	return cur_node->branch[ret];
}

int
rib_lookup(const struct rib_head *rib, const uint8_t *address,
	uint32_t *pnext_hop)
{
	rib_address_t haddr;
	int ret = read_addr(rib, &haddr, address);
	bool has_nh = false;
	uint32_t next_hop;
	struct rib_node_info info;
	const struct rib_node *cur_node;

	if (unlikely(ret < 0))
		return ret;

	info_init(&info, rib);
	cur_node = &rib->root_node;
	do {
		info_update(&info, cur_node);

		if (!info_haddr_matches(&info, haddr))
			break;

		/* One more match. */

		if (cur_node->has_nh) {
			has_nh = true;
			next_hop = cur_node->next_hop;
		}

		if (info.missing_bits == 0) {
			RTE_VERIFY(cur_node->branch[false] == NULL);
			RTE_VERIFY(cur_node->branch[true] == NULL);
			break;
		}

		cur_node = next_node(cur_node, &info, haddr);
	} while (cur_node != NULL);

	if (has_nh) {
		*pnext_hop = next_hop;
		return 0;
	}
	return -ENOENT;
}

int
rib_is_rule_present(const struct rib_head *rib, const uint8_t *address,
	uint8_t depth, uint32_t *pnext_hop)
{
	rib_address_t haddr;
	int ret;
	struct rib_node_info info;
	const struct rib_node *cur_node;

	if (unlikely(depth > rib->max_length))
		return -EINVAL;

	ret = read_addr(rib, &haddr, address);
	if (unlikely(ret < 0))
		return ret;
	/*
	 * There is no need to mask @haddr because it is always accessed
	 * within its mask.
	 */

	info_init(&info, rib);
	cur_node = &rib->root_node;
	do {
		info_update(&info, cur_node);

		if (info.depth > depth || !info_haddr_matches(&info, haddr))
			break;

		/* One more match. */

		if (info.depth == depth) {
			if (cur_node->has_nh) {
				*pnext_hop = cur_node->next_hop;
				return 1;
			}
			break;
		}

		cur_node = next_node(cur_node, &info, haddr);
	} while (cur_node != NULL);
	return 0;
}

static struct rib_node *
zalloc_node(const struct rib_head *rib)
{
	struct rib_node *new_node;
	int ret = rte_mempool_get(rib->mp_nodes, (void **)&new_node);
	if (unlikely(ret < 0)) {
		G_LOG(ERR, "%s(): failed to allocate a node (errno=%i): %s\n",
			__func__, -ret, rte_strerror(-ret));
		return NULL;
	}
	return memset(new_node, 0, sizeof(*new_node));
}

static int
split_cur_node(const struct rib_head *rib, struct rib_node **anchor_cur_node,
	const struct rib_node_info *info, rib_address_t haddr, uint8_t depth)
{
	struct rib_node *new_node, *old_node;
	rib_prefix_bits_t new_prefix, first_mismatch_bit;
	int missing_bits, testing_bits, mismatch_bits;

	/* Create a new node for the split. */
	new_node = zalloc_node(rib);
	if (unlikely(new_node == NULL))
		return -ENOMEM;

	/*
	 * Find the prefix of @new_node.
	 */

	RTE_BUILD_BUG_ON(sizeof(haddr) != sizeof(uint128_t));
	RTE_BUILD_BUG_ON(sizeof(new_prefix) != sizeof(uint64_t));

	old_node = *anchor_cur_node;
	missing_bits = rib->max_length - RTE_MIN(info->depth, depth);
	testing_bits = info->depth <= depth
		? old_node->matched_bits
		: depth - (info->depth - old_node->matched_bits);
	if (unlikely(testing_bits < 1 ||
			old_node->matched_bits < testing_bits)) {
		G_LOG(CRIT,
			"%s(): bug: testing_bits == %i must be in [1, %i]\n",
			__func__, testing_bits, old_node->matched_bits);
		goto bug;
	}

	new_prefix = (haddr >> missing_bits) & n_one_bits(testing_bits);
	first_mismatch_bit = rte_align64prevpow2(new_prefix ^
	       (old_node->pfx_bits >> (old_node->matched_bits - testing_bits)));
	mismatch_bits = first_mismatch_bit == 0
		? 0 : rte_bsf64(first_mismatch_bit) + 1;
	if (unlikely(testing_bits <= mismatch_bits)) {
		G_LOG(CRIT, "%s(): bug: there should be at least one matched bit; testing_bits == %i and mismatch_bits == %i\n",
			__func__, testing_bits, mismatch_bits);
		goto bug;
	}

	new_node->pfx_bits = new_prefix >> mismatch_bits;
	new_node->matched_bits = testing_bits - mismatch_bits;

	/* Update the prefix of the old node. */
	if (unlikely(old_node->matched_bits <= new_node->matched_bits)) {
		G_LOG(CRIT, "%s(): bug: over matching; old_node->matched_bits == %i, testing_bits == %i, mismatch_bits == %i\n",
			__func__, old_node->matched_bits,
			testing_bits, mismatch_bits);
		goto bug;
	}
	old_node->matched_bits -= new_node->matched_bits;
	old_node->pfx_bits &= n_one_bits(old_node->matched_bits);

	/* Link the old and new nodes. */
	new_node->branch[
		test_bit_n(old_node->pfx_bits, old_node->matched_bits - 1)] =
		old_node;
	*anchor_cur_node = new_node;

	return 0;

bug:
	rte_mempool_put(rib->mp_nodes, new_node);
	return -EFAULT;
}

static inline struct rib_node **
next_p_node(struct rib_node **anchor_cur_node, const struct rib_node_info *info,
	rib_address_t haddr)
{
	int ret = next_bit(info, haddr);
	if (unlikely(ret < 0))
		return NULL;

	return &(*anchor_cur_node)->branch[ret];
}

static void
free_tail(const struct rib_head *rib, struct rib_node *cur_node)
{
	while (cur_node != NULL) {
		struct rib_node *n_node = cur_node->branch[false];
		if (n_node == NULL)
			n_node = cur_node->branch[true];
		rte_mempool_put(rib->mp_nodes, cur_node);
		cur_node = n_node;
	}
}

/*
 * If successful, @p_anchor_cur_node is updated to refer to
 * the last node of the tail.
 */
static int
add_haddr_tail(const struct rib_head *rib, struct rib_node ***p_anchor_cur_node,
	struct rib_node_info *info, const rib_address_t haddr,
	const uint8_t depth)
{
	struct rib_node **saved_anchor_cur_node = *p_anchor_cur_node;
	struct rib_node **anchor_cur_node = saved_anchor_cur_node;
	struct rib_node **prv_anchor_cur_node = NULL;
	int ret;

	if (unlikely(p_anchor_cur_node == NULL || *p_anchor_cur_node == NULL ||
			**p_anchor_cur_node != NULL)) {
		G_LOG(CRIT, "%s(): bug: no location to save tail\n", __func__);
		return -EINVAL;
	}

	if (unlikely(info->depth >= depth)) {
		G_LOG(CRIT, "%s(): bug: invalid call, info->depth == %i and depth == %i\n",
			__func__, info->depth, depth);
		return -EINVAL;
	}

	do {
		struct rib_node *new_node = zalloc_node(rib);
		if (unlikely(new_node == NULL)) {
			ret = -ENOMEM;
			goto error;
		}
		*anchor_cur_node = new_node;

		new_node->matched_bits =
			RTE_MIN(depth - info->depth, RIB_MAX_PREFIX_BITS);
		new_node->pfx_bits =
			(haddr >> (info->missing_bits - new_node->matched_bits))
			& n_one_bits(new_node->matched_bits);
		info_update(info, new_node);
		prv_anchor_cur_node = anchor_cur_node;

		if (info->depth == depth)
			break;

		anchor_cur_node = next_p_node(anchor_cur_node, info, haddr);
		if (unlikely(anchor_cur_node == NULL)) {
			ret = -EFAULT;
			goto error;
		}
	} while (info->depth < depth);

	if (unlikely(info->depth != depth)) {
		G_LOG(CRIT, "%s(): bug: something went wrong, info->depth == %i and depth == %i\n",
			__func__, info->depth, depth);
		ret = -EFAULT;
		goto error;
	}

	*p_anchor_cur_node = prv_anchor_cur_node;
	return 0;

error:
	free_tail(rib, *saved_anchor_cur_node);
	*saved_anchor_cur_node = NULL;
	return ret;
}

int
rib_add(struct rib_head *rib, const uint8_t *address, const uint8_t depth,
	const uint32_t next_hop)
{
	rib_address_t haddr;
	int ret;
	struct rib_node_info info;
	struct rib_node *fake_root, **anchor_cur_node;

	if (unlikely(depth > rib->max_length))
		return -EINVAL;

	ret = read_addr(rib, &haddr, address);
	if (unlikely(ret < 0))
		return ret;
	/*
	 * There is no need to mask @haddr because it is always accessed
	 * within its mask.
	 */

	info_init(&info, rib);
	/* @fake_root is only used to bootstrap the loop. */
	fake_root = &rib->root_node;
	anchor_cur_node = &fake_root;
	do {
		struct rib_node_info prv_info = info;
		info_update(&info, *anchor_cur_node);

		if (info.depth > depth || !info_haddr_matches(&info, haddr)) {
			/*
			 * If execution is here, @haddr and
			 * @(*anchor_cur_node)->pfx_bits match at least
			 * the most significant bit of
			 * @(*anchor_cur_node)->pfx_bits.
			 *
			 * Proof:
			 *
			 * If @*anchor_cur_node points to @rib->root_node,
			 * the test in this if statement is false,
			 * so the execution cannot be here. Therefore,
			 * if the execution is here, @*anchor_cur_node must
			 * point to a node that is not @rib->root_node.
			 *
			 * All nodes but @rib->root_node make
			 * @(*anchor_cur_node)->matched_bits > 0 true.
			 * Therefore, whenever next_p_node() returns,
			 * @*anchor_cur_node matches at least the most
			 * significant bit of @(*anchor_cur_node)->pfx_bits
			 * with @haddr.
			 *
			 * Since that @*anchor_cur_node does not point to
			 * @rib->root_node, the loop has reached next_p_node()
			 * at least once.
			 */
			ret = split_cur_node(rib, anchor_cur_node, &info,
				haddr, depth);
			if (unlikely(ret < 0))
				return ret;

			/*
			 * If there is an error after here, the newly split
			 * node will be left in @rib, so iterators must
			 * be aware of the change.
			 */
			rib->version++;

			/* Back track to the new node. */
			info = prv_info;
			info_update(&info, *anchor_cur_node);
		}

		/* One more match. */

		if (info.depth == depth) {
			if ((*anchor_cur_node)->has_nh)
				return -EEXIST;
			goto add_rule;
		}

		anchor_cur_node = next_p_node(anchor_cur_node, &info, haddr);
		if (unlikely(anchor_cur_node == NULL))
			return -EFAULT;
	} while (*anchor_cur_node != NULL);

	ret = add_haddr_tail(rib, &anchor_cur_node, &info, haddr, depth);
	if (unlikely(ret < 0))
		return ret;

add_rule:
	(*anchor_cur_node)->has_nh = true;
	(*anchor_cur_node)->next_hop = next_hop;
	rib->version++;
	return 0;
}

struct rib_delete_state {
	/* Parameters of rib_delete(). */
	struct rib_head *rib;
	rib_address_t   haddr;
	uint8_t         depth;
	/* Long jump to unwind the recursion. */
	jmp_buf         jmp_end;
};

static inline bool
is_node_root(struct rib_head *rib, struct rib_node *cur_node)
{
	return cur_node == &rib->root_node;
}

static unsigned int
count_children(struct rib_node *cur_node,
	struct rib_node ***p_anchor_of_single_child)
{
	if (cur_node->branch[false] != NULL) {
		if (cur_node->branch[true] != NULL) {
			*p_anchor_of_single_child = NULL;
			return 2;
		}

		*p_anchor_of_single_child = &cur_node->branch[false];
		return 1;
	}

	if (cur_node->branch[true] != NULL) {
		*p_anchor_of_single_child = &cur_node->branch[true];
		return 1;
	}

	*p_anchor_of_single_child = NULL;
	return 0;
}

static void
__rib_delete(struct rib_delete_state *state, struct rib_node **anchor_cur_node,
	struct rib_node_info info)
{
	struct rib_node **anchor_of_single_child;
	unsigned int children;

	if (*anchor_cur_node == NULL)
		longjmp(state->jmp_end, -ENOENT);

	info_update(&info, *anchor_cur_node);

	if (info.depth > state->depth ||
			!info_haddr_matches(&info, state->haddr))
		longjmp(state->jmp_end, -ENOENT);

	/* One more match. */

	if (info.depth == state->depth) {
		if (!(*anchor_cur_node)->has_nh)
			longjmp(state->jmp_end, -ENOENT);
		(*anchor_cur_node)->has_nh = false;
	} else {
		__rib_delete(state,
			next_p_node(anchor_cur_node, &info, state->haddr),
			info);
	}

	/*
	 * Try to merge @(*anchor_cur_node) downstream.
	 */

	if (is_node_root(state->rib, *anchor_cur_node) ||
			(*anchor_cur_node)->has_nh)
		goto done;
	children = count_children(*anchor_cur_node, &anchor_of_single_child);

	if (children >= 2)
		goto done;

	if (children == 0) {
		/* @(*anchor_cur_node) is a leaf node. */
		rte_mempool_put(state->rib->mp_nodes, *anchor_cur_node);
		*anchor_cur_node = NULL;
		return; /* Allow further compression of @state->rib. */
	}

	/* @children == 1 */

	if ((*anchor_cur_node)->matched_bits +
			(*anchor_of_single_child)->matched_bits >
			RIB_MAX_PREFIX_BITS) {
		/* @(*anchor_cur_node) cannot merge downstream, try upstream. */
		return;
	}

	(*anchor_of_single_child)->pfx_bits |= (*anchor_cur_node)->pfx_bits <<
		(*anchor_of_single_child)->matched_bits;
	(*anchor_of_single_child)->matched_bits +=
		(*anchor_cur_node)->matched_bits;
	rte_mempool_put(state->rib->mp_nodes, *anchor_cur_node);
	*anchor_cur_node = *anchor_of_single_child;
	return; /* Allow further compression of @state->rib. */

done:
	longjmp(state->jmp_end, true);
}

int
rib_delete(struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	struct rib_delete_state state;
	int ret;

	if (unlikely(depth > rib->max_length))
		return -EINVAL;

	ret = read_addr(rib, &state.haddr, address);
	if (unlikely(ret < 0))
		return ret;
	/*
	 * There is no need to mask @state.haddr because it is always accessed
	 * within its mask.
	 */

	state.rib = rib;
	state.depth = depth;

	ret = setjmp(state.jmp_end);
	if (ret == 0) {
		struct rib_node *fake_root = &rib->root_node;
		struct rib_node_info info;

		info_init(&info, rib);
		__rib_delete(&state, &fake_root, info);
		goto done;
	}

	if (ret < 0)
		return ret;

done:
	rib->version++;
	return 0;
}

static inline void
mask_haddr(const struct rib_head *rib, rib_address_t *haddr, uint8_t depth)
{
	*haddr &= ~n_one_bits(rib->max_length - depth);
}

static inline bool
is_haddr_in_scope(const struct rib_node_info *info, rib_address_t haddr,
	uint8_t depth)
{
	rib_address_t shorter_mask =
		lshift(info->haddr_mask, info->depth - depth);
	RTE_VERIFY(depth <= info->depth);
	return !((haddr ^ info->haddr_matched) & shorter_mask);
}

static void
scope_longer_iterator(struct rib_longer_iterator_state *state)
{
	struct rib_node_info prv_info, info;
	const struct rib_node *cur_node;

	info_init(&info, state->rib);
	cur_node = &state->rib->root_node;
	do {
		prv_info = info;

		info_update(&info, cur_node);
		if (info.depth >= state->min_depth) {
			if (!is_haddr_in_scope(&info, state->next_address,
					state->min_depth))
				break;

			/* Found the scope. */
			goto scope;
		}

		/* It is not deep enough into the prefix tree. */

		if (!info_haddr_matches(&info, state->next_address))
			break;

		cur_node = next_node(cur_node, &info, state->next_address);
	} while (cur_node != NULL);

	/*
	 * There is no prefix with @state->min_depth for
	 * @state->next_address.
	 */
	cur_node = NULL;

scope:
	state->version = state->rib->version;
	state->start_node = cur_node;
	state->start_info = prv_info;
}

int
rib_longer_iterator_state_init(struct rib_longer_iterator_state *state,
	const struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	int ret;

	if (unlikely(depth > rib->max_length))
		return -EINVAL;

	ret = read_addr(rib, &state->next_address, address);
	if (unlikely(ret < 0))
		return ret;
	/*
	 * It is necessary to mask @state->next_address because
	 * the iterator compares it with the prefixes of the branches of
	 * the RIB to avoid previously visited prefixes. And these comparisons
	 * are done without masking.
	 */
	mask_haddr(rib, &state->next_address, depth);

	state->rib = rib;
	state->min_depth = depth;
	state->next_depth = depth;
	state->has_ended = false;
	scope_longer_iterator(state);
	return 0;
}

static void
__rib_longer_iterator_next(struct rib_longer_iterator_state *state,
	const struct rib_node *cur_node, struct rib_node_info info)
{
	if (cur_node == NULL)
		return;

	info_update(&info, cur_node);

	if (!state->ignore_next_address) {
		/*
		 * Invariants:
		 *
		 * 1. Only the body of this if statement sets
		 *    @state->ignore_next_address true.
		 *
		 *    Proof: Inspect the code.
		 *
		 * 2. When @state->ignore_next_address is set true,
		 *    no recursive call already in the stack is affected,
		 *    that is, changes its execution.
		 *
		 *    Proof:
		 *
		 *    Assume that @state->ignore_next_address is false;
		 *    otherwise setting it can not affect recursive calls
		 *    already in the stack.
		 *
		 *    All recursive calls already in the stack are either
		 *    (A) within the body of this if statement or (B) after it.
		 *
		 *    (A) The recursive calls already in the stack and within
		 *    the body of this if statement do not test
		 *    @state->ignore_next_address again; inspect the code.
		 *
		 *    (B) The recursive calls already in the stack and after
		 *    the body of this if statement have no reference to
		 *    @state->ignore_next_address thanks to invariant 1.
		 *
		 *    Notice that a recursive call already in the stack may
		 *    make another recursive call that will be affected, but
		 *    this is a *new* recursive call.
		 */
		if (info.depth < state->next_depth &&
				info_haddr_matches(&info,
					state->next_address)) {
			int next_b = next_bit(&info, state->next_address);
			if (unlikely(next_b < 0))
				return;

			__rib_longer_iterator_next(state,
				cur_node->branch[next_b], info);
			/*
			 * There may or may not be a rule for the prefix
			 * @state->next_address/@state->next_depth, but
			 * one needs to find the immediately greater prefix.
			 *
			 * One does not need to check @cur_node->has_nh
			 * because (info.depth < state->next_depth) means
			 * that the rule of @cur_node is before the prefix
			 * @state->next_address/@state->next_depth.
			 */
			if (next_b == 0) {
				__rib_longer_iterator_next(state,
					cur_node->branch[true],	info);
			}
			return;
		}

		/*
		 * Notice that if @cur_node corresponds to the prefix
		 * @state->next_address/@state->next_depth, but
		 * @cur_node->has_nh is false because the prefix was removed,
		 * @state->found_return can only become true in another
		 * point of the recursion.
		 *
		 * This is why @state->ignore_next_address and
		 * @state->found_return may have different values.
		 */
		state->ignore_next_address = true;

		if (info.haddr_matched < state->next_address) {
			/*
			 * There is no rule for the prefix
			 * @state->next_address/@state->next_depth or
			 * after it on this branch.
			 */
			return;
		}
	}

	/* Any prefix from here on is a match. */

	if (cur_node->has_nh) {
		if (state->found_return) {
			state->next_address = info.haddr_matched;
			state->next_depth = info.depth;
			longjmp(state->jmp_found, true);
		}

		state->found_return = true;
		RTE_VERIFY(write_addr(state->rib,
				(uint8_t *)&state->rule->address_no,
				info.haddr_matched) == 0);
		state->rule->depth = info.depth;
		state->rule->next_hop = cur_node->next_hop;
		/* Still missing the next rule after the found rule. */
	}

	__rib_longer_iterator_next(state, cur_node->branch[false], info);
	__rib_longer_iterator_next(state, cur_node->branch[true], info);
}

int
rib_longer_iterator_next(struct rib_longer_iterator_state *state,
	struct rib_iterator_rule *rule)
{
	if (unlikely(state->has_ended))
		return -ENOENT;

	/* Set fields used during recursion. */
	state->ignore_next_address = false;
	state->found_return = false;
	state->rule = rule;

	if (setjmp(state->jmp_found) == 0) {
		if (state->version != state->rib->version)
			scope_longer_iterator(state);

		/* Start recursion. */
		__rib_longer_iterator_next(state, state->start_node,
			state->start_info);
		state->has_ended = true;

		if (state->found_return) {
			/* It found the last rule. */
			goto found;
		}
		return -ENOENT;
	}

found:
	/* A rule was found. */
	return 0;
}

int
rib_shorter_iterator_state_init(struct rib_shorter_iterator_state *state,
	const struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	int ret;

	if (unlikely(depth > rib->max_length))
		return -EINVAL;

	ret = read_addr(rib, &state->haddr, address);
	if (unlikely(ret < 0))
		return ret;
	/*
	 * There is no need to mask @haddr because it is always accessed
	 * within its mask.
	 */

	state->rib = rib;
	state->version = rib->version;
	state->cur_node = &rib->root_node;
	info_init(&state->info, rib);
	state->depth = depth;
	state->has_ended = false;
	return 0;
}

int
rib_shorter_iterator_next(struct rib_shorter_iterator_state *state,
	struct rib_iterator_rule *rule)
{
	bool found_return = false;

	if (unlikely(state->has_ended))
		return -ENOENT;

	if (unlikely(state->version != state->rib->version))
		return -EFAULT;

	do {
		info_update(&state->info, state->cur_node);

		if (state->info.depth > state->depth ||
				!info_haddr_matches(&state->info, state->haddr))
			goto end;

		/* One more match. */

		if (state->cur_node->has_nh) {
			RTE_VERIFY(write_addr(state->rib,
				(uint8_t *)&rule->address_no,
				state->info.haddr_matched) == 0);
			rule->depth = state->info.depth;
			rule->next_hop = state->cur_node->next_hop;
			found_return = true;
		}

		if (state->info.depth == state->depth)
			goto end;

		state->cur_node = next_node(state->cur_node, &state->info,
			state->haddr);
		if (state->cur_node == NULL)
			goto end;
	} while (!found_return);

	goto out;

end:
	state->has_ended = true;
out:
	return found_return ? 0 : -ENOENT;
}
