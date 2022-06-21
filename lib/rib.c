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

int
rib_add(struct rib_head *rib, const uint8_t *address, uint8_t depth,
	uint32_t next_hop)
{
	/* TODO */
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	RTE_SET_USED(next_hop);
	return -1;
}

int
rib_delete(struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	/* TODO */
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	return -1;
}

int
rib_longer_iterator_state_init(struct rib_longer_iterator_state *state,
	const struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	/* TODO */
	RTE_SET_USED(state);
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	return -1;
}

int
rib_longer_iterator_next(struct rib_longer_iterator_state *state,
	struct rib_iterator_rule *rule)
{
	/* TODO */
	RTE_SET_USED(state);
	RTE_SET_USED(rule);
	return -1;
}

int
rib_shorter_iterator_state_init(struct rib_shorter_iterator_state *state,
	const struct rib_head *rib, const uint8_t *address, uint8_t depth)
{
	/* TODO */
	RTE_SET_USED(state);
	RTE_SET_USED(rib);
	RTE_SET_USED(address);
	RTE_SET_USED(depth);
	return -1;
}

int
rib_shorter_iterator_next(struct rib_shorter_iterator_state *state,
	struct rib_iterator_rule *rule)
{
	/* TODO */
	RTE_SET_USED(state);
	RTE_SET_USED(rule);
	return -1;
}
